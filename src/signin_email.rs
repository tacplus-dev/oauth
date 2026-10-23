//! Auth.ClassifySignInEmail: how a person signs in, guessed from their work
//! email's DNS.
//!
//! An `_openid.<domain>` TXT record naming Google's, Microsoft's or Apple's
//! issuer wins. Otherwise the issuer the domain's WebFinger names for the address
//! does. Otherwise the domain's most-preferred MX hosts name its mail provider:
//! Google Workspace, Microsoft 365 or iCloud+ (Apple). Each answers with the
//! configured provider of that IDP, so the
//! SPA goes straight to Authorize; anything else is unsupported. Every other
//! enabled Google, Microsoft or Apple provider is offered as an alternative, so a person whose guess is
//! wrong (or missing) can pick. The answer is a function of public DNS, the
//! domain's own WebFinger and this service's provider config only. Nothing here reads an account, so the answer
//! cannot say whether one exists.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use oauth_model::types::services::oauth::oauth::{
    ClassifySignInEmailResponse, ProviderConfig, SignInMethod, SignInOption,
};

/// The issuer a Google provider is configured with.
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// The issuer prefix every Microsoft Entra ID provider is configured with
/// (`.../organizations/v2.0`, `.../common/v2.0` or one directory's GUID).
const MICROSOFT_ISSUER_PREFIX: &str = "https://login.microsoftonline.com/";

/// The issuer an Apple provider is configured with.
const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// The issuer hosts a TXT `iss` or a WebFinger issuer is mapped by.
const GOOGLE_ISSUER_HOST: &str = "accounts.google.com";
const MICROSOFT_ISSUER_HOST: &str = "login.microsoftonline.com";
const APPLE_ISSUER_HOST: &str = "appleid.apple.com";

/// The WebFinger link relation naming an account's OpenID Connect issuer (OIDC
/// Discovery 1.0 section 2).
const ISSUER_REL: &str = "http://openid.net/specs/connect/1.0/issuer";

/// Bounds on the WebFinger request: the whole exchange, and the body read.
const WEBFINGER_TIMEOUT: Duration = Duration::from_secs(2);
const WEBFINGER_MAX_BODY: usize = 16 * 1024;

/// DnsResolver answers a domain's MX records as (preference, exchange host),
/// and a name's TXT records, each as its character-strings concatenated.
///
/// A trait so the tests can answer from a table; the service uses the system
/// resolver (`TokioResolver`).
#[tonic::async_trait]
pub trait DnsResolver: Send + Sync {
    async fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>, String>;
    async fn txt(&self, name: &str) -> Result<Vec<String>, String>;
}

#[tonic::async_trait]
impl DnsResolver for TokioResolver {
    async fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>, String> {
        // The trailing dot makes the name absolute. Without it the pod's
        // resolv.conf (ndots:5) would first try the name under every cluster
        // search domain.
        let lookup = self.mx_lookup(format!("{domain}.")).await.map_err(|e| e.to_string())?;
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::MX(mx) => Some((mx.preference, mx.exchange.to_utf8())),
                _ => None,
            })
            .collect())
    }

    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        // Absolute for the same reason as `mx`.
        let lookup = self.txt_lookup(format!("{name}.")).await.map_err(|e| e.to_string())?;
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(txt) => Some(String::from_utf8_lossy(&txt.txt_data.concat()).into_owned()),
                _ => None,
            })
            .collect())
    }
}

/// IssuerFinder answers the OpenID Connect issuer a domain's WebFinger names
/// for an address, or None.
///
/// A trait so the tests can answer from a table; the service uses `WebFinger`.
#[tonic::async_trait]
pub trait IssuerFinder: Send + Sync {
    async fn issuer(&self, domain: &str, email: &str) -> Option<String>;
}

/// WebFinger asks `https://<domain>/.well-known/webfinger` for an address's
/// issuer. The domain is whatever a caller types, so this is a request from
/// inside the cluster to a host the caller chooses: https only, every address
/// the domain resolves to must be public and the connection goes only to those
/// (`PublicOnly`), no proxy, no redirects, and the time and body are bounded.
pub struct WebFinger {
    client: reqwest::Client,
}

impl WebFinger {
    pub fn new(resolver: TokioResolver) -> reqwest::Result<Self> {
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(PublicOnly(resolver)))
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(WEBFINGER_TIMEOUT)
            .build()?;
        Ok(Self { client })
    }

    async fn fetch(&self, domain: &str, email: &str) -> Result<Option<String>, String> {
        let url = webfinger_url(domain, email).ok_or("not a plain domain name")?;
        let mut resp = self.client.get(url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("status {}", resp.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            if body.len() + chunk.len() > WEBFINGER_MAX_BODY {
                return Err("body over the cap".to_string());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(jrd_issuer(&body))
    }
}

#[tonic::async_trait]
impl IssuerFinder for WebFinger {
    async fn issuer(&self, domain: &str, email: &str) -> Option<String> {
        // debug: most domains serve no WebFinger, and the route is public.
        self.fetch(domain, email).await.unwrap_or_else(|e| {
            debug!(domain = %domain, error = %e, "WebFinger gave no issuer");
            None
        })
    }
}

/// The WebFinger query for `email` at `domain`. None unless `domain` is a plain
/// DNS name: an IP literal would never reach `PublicOnly`, and anything the URL
/// parser rewrote is not the domain that was typed.
fn webfinger_url(domain: &str, email: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse_with_params(
        &format!("https://{domain}/.well-known/webfinger"),
        &[("resource", format!("acct:{email}").as_str()), ("rel", ISSUER_REL)],
    )
    .ok()?;
    (url.domain() == Some(domain)).then_some(url)
}

/// PublicOnly is the WebFinger client's DNS: a name's A and AAAA records, all of
/// them public or the lookup fails. The client connects only to the addresses
/// it returns, so a vetted answer cannot be swapped for another one afterwards.
struct PublicOnly(TokioResolver);

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.0.clone();
        Box::pin(async move {
            // Absolute for the same reason as `DnsResolver::mx`.
            let lookup = resolver.lookup_ip(format!("{}.", name.as_str())).await?;
            let addrs: Vec<IpAddr> = lookup.iter().collect();
            if addrs.is_empty() || !addrs.iter().all(|a| is_public(*a)) {
                return Err(format!("{} resolves to a non-public address", name.as_str()).into());
            }
            // Port 0: the client sets the URL's port.
            let addrs: Addrs = Box::new(addrs.into_iter().map(|a| SocketAddr::new(a, 0)));
            Ok(addrs)
        })
    }
}

/// Whether `addr` is a public unicast address: not unspecified, loopback,
/// private, unique-local, link-local, CGNAT, NAT64, multicast, broadcast, reserved,
/// or a documentation or benchmarking range. An IPv4-mapped IPv6 address is judged
/// as its IPv4 address.
fn is_public(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => {
                let seg = v6.segments();
                !(v6.is_unspecified()
                    || v6.is_loopback()
                    || v6.is_multicast()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    // 2001:db8::/32 documentation, 2001:2::/48 benchmarking.
                    || (seg[0] == 0x2001 && seg[1] == 0x0db8)
                    || (seg[0] == 0x2001 && seg[1] == 0x0002 && seg[2] == 0)
                    // 64:ff9b::/96 and 64:ff9b:1::/48 NAT64: they reach IPv4 space.
                    || (seg[0] == 0x0064 && seg[1] == 0xff9b))
            }
        },
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    !(a == 0
        || v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_documentation()
        // 100.64/10 CGNAT, 198.18/15 benchmarking, 240/4 reserved.
        || (a == 100 && (64..128).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

/// A WebFinger JSON Resource Descriptor, as far as the issuer link.
#[derive(Deserialize)]
struct Jrd {
    #[serde(default)]
    links: Vec<JrdLink>,
}

#[derive(Deserialize)]
struct JrdLink {
    rel: Option<String>,
    href: Option<String>,
}

/// The href of the first issuer link in a JRD body, when it is https. None for
/// anything else, including a body that is not a JRD.
fn jrd_issuer(body: &[u8]) -> Option<String> {
    let jrd: Jrd = serde_json::from_slice(body).ok()?;
    let link = jrd.links.into_iter().find(|l| l.rel.as_deref() == Some(ISSUER_REL))?;
    link.href.filter(|href| href.starts_with("https://"))
}

/// The value of the one valid `v=OID1; iss=<host[:port][/path]>` record among
/// `records` (`_openid.<domain>`, draft-sanz-openid-dns-discovery-01). Tags are
/// `;`-separated with whitespace around them ignored, tag names and the `v`
/// value are case-insensitive, and `clp` and unknown tags are ignored. A record
/// whose first tag is not `v=OID1` is not one. None when no record or more than
/// one is, or it has no single `iss`, or its `iss` carries a scheme: the guess
/// then falls through rather than to an IDP the domain may not have meant.
fn openid_iss(records: &[String]) -> Option<&str> {
    let mut ours = records.iter().filter_map(|record| {
        let mut tags = record.split(';').map(str::trim).filter(|t| !t.is_empty()).map(|t| {
            let (name, value) = t.split_once('=').unwrap_or((t, ""));
            (name.trim().to_ascii_lowercase(), value.trim())
        });
        match tags.next() {
            Some((name, value)) if name == "v" && value.eq_ignore_ascii_case("OID1") => Some(tags),
            _ => None,
        }
    });
    let tags = ours.next()?;
    if ours.next().is_some() {
        return None;
    }
    let mut isses = tags.filter(|(name, _)| name == "iss").map(|(_, value)| value);
    let iss = isses.next()?;
    if isses.next().is_some() || iss.is_empty() || iss.contains("://") {
        return None;
    }
    Some(iss)
}

/// The IDP an issuer without its scheme (`host[:port][/path]`) belongs to,
/// judged by its host alone, case-insensitively. A port is part of the host, so
/// `accounts.google.com:443` is no match. None for any other host: a custom
/// issuer has no `SignInMethod`, and DNS or WebFinger never adds a trusted one.
fn iss_method(iss: &str) -> Option<SignInMethod> {
    let host = iss.split('/').next().unwrap_or("");
    if host.eq_ignore_ascii_case(GOOGLE_ISSUER_HOST) {
        Some(SignInMethod::Google)
    } else if host.eq_ignore_ascii_case(MICROSOFT_ISSUER_HOST) {
        Some(SignInMethod::Microsoft)
    } else if host.eq_ignore_ascii_case(APPLE_ISSUER_HOST) {
        Some(SignInMethod::Apple)
    } else {
        None
    }
}

/// The mail provider a set of MX records names, judged by the most-preferred
/// records only: a domain migrating between providers keeps the old one at a
/// higher preference value, and the lowest value is where its mail goes now.
/// None when those records name no provider, or more than one.
fn mail_provider(records: &[(u16, String)]) -> Option<SignInMethod> {
    let best = records.iter().map(|(pref, _)| *pref).min()?;
    let mut found = None;
    for (_, host) in records.iter().filter(|(pref, _)| *pref == best) {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let method = if host == "smtp.google.com"
            || host == "aspmx.l.google.com"
            || host.ends_with(".aspmx.l.google.com")
            || host.ends_with(".googlemail.com")
        {
            SignInMethod::Google
        } else if host.ends_with(".mail.protection.outlook.com") || host.ends_with(".mx.microsoft") {
            SignInMethod::Microsoft
        } else if host.ends_with(".mail.icloud.com") {
            SignInMethod::Apple
        } else {
            return None;
        };
        if found.is_some_and(|f| f != method) {
            return None;
        }
        found = Some(method);
    }
    found
}

/// The IDP a configured provider's issuer belongs to, when it is one this RPC
/// answers: matched by issuer rather than the provider's free-form name.
fn issuer_method(issuer: &str) -> Option<SignInMethod> {
    if issuer == GOOGLE_ISSUER {
        Some(SignInMethod::Google)
    } else if issuer.starts_with(MICROSOFT_ISSUER_PREFIX) {
        Some(SignInMethod::Microsoft)
    } else if issuer == APPLE_ISSUER {
        Some(SignInMethod::Apple)
    } else {
        None
    }
}

/// The index of the first enabled provider for an IDP.
fn provider_index(providers: &[ProviderConfig], method: SignInMethod) -> Option<i32> {
    providers
        .iter()
        .position(|p| p.enable && issuer_method(&p.issuer) == Some(method))
        .map(|i| i as i32)
}

/// Classify `email` (already schema-validated as an address) against
/// `providers`. The domain's `_openid` TXT record decides when it names a usable
/// provider; otherwise its WebFinger issuer does; otherwise its MX does. A
/// lookup failure, an unknown provider, or a provider that is not configured
/// all leave the guess unsupported; the alternatives are every other enabled
/// Google, Microsoft or Apple provider either way.
pub async fn classify(
    resolver: &dyn DnsResolver,
    finder: &dyn IssuerFinder,
    providers: &[ProviderConfig],
    email: &str,
) -> ClassifySignInEmailResponse {
    let domain = email.rsplit_once('@').map_or("", |(_, d)| d).to_ascii_lowercase();
    let usable = |method: Option<SignInMethod>| method.and_then(|m| provider_index(providers, m).map(|i| (m, i)));
    // A failed TXT lookup is the usual case (most domains have no `_openid`
    // name), so it is not logged.
    let mut guess = match resolver.txt(&format!("_openid.{domain}")).await {
        Ok(records) => usable(openid_iss(&records).and_then(iss_method)),
        Err(_) => None,
    };
    if guess.is_none() {
        let issuer = finder.issuer(&domain, email).await;
        guess = usable(issuer.as_deref().and_then(|i| i.strip_prefix("https://")).and_then(iss_method));
    }
    if guess.is_none() {
        let method = match resolver.mx(&domain).await {
            Ok(records) => mail_provider(&records),
            Err(e) => {
                // info, not warn: a typo or a made-up domain lands here, and
                // the route is public.
                info!(domain = %domain, error = %e, "MX lookup failed, answering unsupported");
                None
            }
        };
        guess = usable(method);
    }
    let (method, provider_index) = guess.unwrap_or((SignInMethod::Unsupported, 0));
    let alternatives = providers
        .iter()
        .enumerate()
        .filter(|(i, p)| p.enable && Some(*i as i32) != guess.map(|(_, g)| g))
        .filter_map(|(i, p)| {
            Some(SignInOption {
                method: issuer_method(&p.issuer)? as i32,
                provider_index: i as i32,
                ..Default::default()
            })
        })
        .collect();
    ClassifySignInEmailResponse {
        method: method as i32,
        provider_index,
        alternatives,
        ..Default::default()
    }
}

/// Lookups one address may make in a burst, and the steady rate after it. A
/// person retyping their address is well inside this; a script asking about one
/// address over and over is not.
const BURST_PER_EMAIL: f64 = 5.0;
const RATE_PER_EMAIL_PER_SEC: f64 = 1.0 / 60.0;

/// Buckets kept before the limiter prunes idle ones. The key space is every
/// address anyone types, which a caller chooses, so it is bounded.
const MAX_TRACKED_EMAILS: usize = 20_000;

/// How long a bucket may go untouched before a prune may drop it: longer than a
/// drained bucket takes to refill (BURST / RATE = 300s), so dropping one forgives
/// no debt.
const BUCKET_IDLE_SECS: f64 = 600.0;

/// EmailRateLimiter is a token bucket per address, keyed by the SHA-256 of the
/// lowercased address so the table never holds the addresses themselves.
///
/// It bounds how often ONE address is looked up. It is not the flood defence (a
/// caller varying the address is never limited by it); that is the gateway's
/// edge limiter. So a table full of live buckets admits an untracked address
/// rather than refusing it: refusing would let anyone who fills the table lock
/// every other person out of sign-in.
pub struct EmailRateLimiter {
    buckets: Mutex<HashMap<[u8; 32], Bucket>>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    /// Refills at `rate` per second up to `burst` since the last call, then takes
    /// one token at `now`, or refuses.
    fn take(&mut self, now: Instant, burst: f64, rate: f64) -> bool {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

impl EmailRateLimiter {
    pub fn new() -> Self {
        Self { buckets: Mutex::new(HashMap::new()) }
    }

    /// Takes one lookup for `email` at `now`, or refuses.
    pub fn allow(&self, email: &str, now: Instant) -> bool {
        let key: [u8; 32] = Sha256::digest(email.to_ascii_lowercase().as_bytes()).into();
        let mut buckets = self.buckets.lock().expect("email rate limiter mutex poisoned");
        if buckets.len() >= MAX_TRACKED_EMAILS && !buckets.contains_key(&key) {
            buckets.retain(|_, b| now.duration_since(b.last).as_secs_f64() < BUCKET_IDLE_SECS);
            if buckets.len() >= MAX_TRACKED_EMAILS {
                return true;
            }
        }
        let bucket = buckets.entry(key).or_insert(Bucket { tokens: BURST_PER_EMAIL, last: now });
        bucket.take(now, BURST_PER_EMAIL, RATE_PER_EMAIL_PER_SEC)
    }
}

/// Lookups the whole process answers in a burst, and the steady rate after it.
/// Each classify costs up to four outbound DNS queries (TXT; A and AAAA for
/// WebFinger; MX) and one WebFinger request. Real sign-ins are a few per person
/// per day; even a whole company arriving on a Monday morning is a few per
/// second, and the gateway already holds each client IP to 0.5/s (burst 30).
/// 10/s sustained (36,000 an hour) is far above that, while capping what many
/// IPs together can make this service send to the resolver at 40 queries and
/// to WebFinger hosts at 10 requests a second; a burst of 100 absorbs a wave of
/// people signing in at once.
const GLOBAL_BURST: f64 = 100.0;
const GLOBAL_RATE_PER_SEC: f64 = 10.0;

/// GlobalRateLimiter is one token bucket for every classify in the process: the
/// ceiling a caller spreading lookups over many addresses and many IPs still
/// meets.
pub struct GlobalRateLimiter {
    bucket: Mutex<Bucket>,
}

impl GlobalRateLimiter {
    pub fn new() -> Self {
        Self { bucket: Mutex::new(Bucket { tokens: GLOBAL_BURST, last: Instant::now() }) }
    }

    /// Takes one lookup at `now`, or refuses.
    pub fn allow(&self, now: Instant) -> bool {
        let mut bucket = self.bucket.lock().expect("global rate limiter mutex poisoned");
        bucket.take(now, GLOBAL_BURST, GLOBAL_RATE_PER_SEC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Answers from tables; a name not in one fails like NXDOMAIN.
    struct FakeResolver {
        mx: HashMap<&'static str, Vec<(u16, &'static str)>>,
        txt: HashMap<&'static str, Vec<&'static str>>,
    }

    #[tonic::async_trait]
    impl DnsResolver for FakeResolver {
        async fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>, String> {
            self.mx
                .get(domain)
                .map(|rs| rs.iter().map(|(p, h)| (*p, h.to_string())).collect())
                .ok_or_else(|| format!("no records found for {domain}"))
        }

        async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
            self.txt
                .get(name)
                .map(|rs| rs.iter().map(|r| r.to_string()).collect())
                .ok_or_else(|| format!("no records found for {name}"))
        }
    }

    const M365_MX: (u16, &str) = (0, "contoso.mail.protection.outlook.com.");
    const GOOGLE_MX: (u16, &str) = (1, "smtp.google.com.");

    fn resolver() -> FakeResolver {
        FakeResolver { mx: HashMap::from([
            ("legacy-google.example", vec![
                (1, "aspmx.l.google.com."),
                (5, "alt1.aspmx.l.google.com."),
                (10, "aspmx2.googlemail.com."),
            ]),
            ("new-google.example", vec![(1, "smtp.google.com.")]),
            ("m365.example", vec![(0, "m365-example.mail.protection.outlook.com.")]),
            ("m365-dnssec.example", vec![(0, "m365-example.r-v1.mx.microsoft.")]),
            ("selfhosted.example", vec![(10, "mail.selfhosted.example.")]),
            // Mid-migration to Microsoft: Google kept as the fallback.
            ("migrating.example", vec![
                (0, "migrating-example.mail.protection.outlook.com."),
                (10, "aspmx.l.google.com."),
            ]),
            ("split.example", vec![
                (10, "aspmx.l.google.com."),
                (10, "split-example.mail.protection.outlook.com."),
            ]),
            ("lookalike.example", vec![
                (1, "aspmx.l.google.com.evil.example."),
                (2, "outlook.com.mail.protection.evil.example."),
            ]),
            ("empty.example", vec![]),
            // iCloud+ mail on a custom domain.
            ("icloud.example", vec![(10, "mx01.mail.icloud.com."), (10, "mx02.mail.icloud.com.")]),
            ("icloud-google-split.example", vec![(10, "mx01.mail.icloud.com."), (10, "aspmx.l.google.com.")]),
            // Jody's case: a Google login whose mail is on iCloud.
            ("thescottsweb.com", vec![(10, "mx01.mail.icloud.com."), (10, "mx02.mail.icloud.com.")]),
            ("txt-google.example", vec![M365_MX]),
            ("txt-microsoft.example", vec![GOOGLE_MX]),
            ("txt-microsoft-tenant.example", vec![GOOGLE_MX]),
            ("txt-apple.example", vec![M365_MX]),
            ("txt-custom-issuer.example", vec![M365_MX]),
            ("txt-two-records.example", vec![M365_MX]),
            ("txt-v-not-first.example", vec![M365_MX]),
            ("txt-no-version.example", vec![M365_MX]),
            ("txt-no-iss.example", vec![M365_MX]),
            ("txt-empty-iss.example", vec![M365_MX]),
            ("txt-two-iss.example", vec![M365_MX]),
            ("txt-scheme-iss.example", vec![M365_MX]),
            ("txt-port-iss.example", vec![M365_MX]),
            ("txt-lookalike-iss.example", vec![M365_MX]),
            ("txt-sloppy.example", vec![M365_MX]),
            ("txt-one-of-many.example", vec![M365_MX]),
            ("wf-google.example", vec![M365_MX]),
            ("wf-microsoft.example", vec![GOOGLE_MX]),
            ("wf-apple.example", vec![M365_MX]),
            ("wf-custom.example", vec![M365_MX]),
            ("wf-http.example", vec![M365_MX]),
        ]), txt: HashMap::from([
            ("_openid.thescottsweb.com", vec!["v=OID1;iss=accounts.google.com"]),
            ("_openid.txt-google.example", vec!["v=OID1; iss=accounts.google.com"]),
            ("_openid.txt-microsoft.example", vec!["v=OID1;iss=login.microsoftonline.com"]),
            ("_openid.txt-microsoft-tenant.example", vec!["v=OID1;iss=login.microsoftonline.com/0f0e0d0c-0000-4000-8000-000000000001/v2.0"]),
            ("_openid.txt-apple.example", vec!["v=OID1;iss=appleid.apple.com"]),
            ("_openid.txt-custom-issuer.example", vec!["v=OID1;iss=idp.example"]),
            ("_openid.txt-two-records.example", vec!["v=OID1;iss=accounts.google.com", "v=OID1;iss=accounts.google.com"]),
            ("_openid.txt-v-not-first.example", vec!["iss=accounts.google.com;v=OID1"]),
            ("_openid.txt-no-version.example", vec!["iss=accounts.google.com"]),
            ("_openid.txt-no-iss.example", vec!["v=OID1;clp=https://idp.example/clp"]),
            ("_openid.txt-empty-iss.example", vec!["v=OID1;iss="]),
            ("_openid.txt-two-iss.example", vec!["v=OID1;iss=accounts.google.com;iss=accounts.google.com"]),
            ("_openid.txt-scheme-iss.example", vec!["v=OID1;iss=https://accounts.google.com"]),
            ("_openid.txt-port-iss.example", vec!["v=OID1;iss=accounts.google.com:443"]),
            ("_openid.txt-lookalike-iss.example", vec!["v=OID1;iss=accounts.google.com.evil.example"]),
            ("_openid.txt-sloppy.example", vec![" V = oid1 ;CLP=https://idp.example/clp;  ISS = Accounts.Google.COM ; future-tag ;"]),
            // Other services' records under the same name are not ours.
            ("_openid.txt-one-of-many.example", vec!["google-site-verification=abc", "v=OID1;iss=accounts.google.com", "v=spf1 -all"]),
        ]) }
    }

    /// Answers WebFinger from a table by domain, counting the calls.
    struct FakeFinder {
        issuers: HashMap<&'static str, &'static str>,
        calls: AtomicUsize,
    }

    #[tonic::async_trait]
    impl IssuerFinder for FakeFinder {
        async fn issuer(&self, domain: &str, _email: &str) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.issuers.get(domain).map(|i| i.to_string())
        }
    }

    fn finder() -> FakeFinder {
        FakeFinder {
            issuers: HashMap::from([
                ("wf-google.example", "https://accounts.google.com"),
                ("wf-microsoft.example", "https://login.microsoftonline.com/0f0e0d0c-0000-4000-8000-000000000001/v2.0"),
                ("wf-apple.example", "https://appleid.apple.com"),
                ("wf-custom.example", "https://idp.example/realms/drpepper"),
                ("wf-http.example", "http://accounts.google.com"),
                // Never asked: its TXT record answers first.
                ("txt-google.example", "https://login.microsoftonline.com/organizations/v2.0"),
            ]),
            calls: AtomicUsize::new(0),
        }
    }

    fn provider(name: &str, issuer: &str, enable: bool) -> ProviderConfig {
        ProviderConfig {
            enable,
            name: name.to_string(),
            issuer: issuer.to_string(),
            ..Default::default()
        }
    }

    /// The dev provider list's shape: Keycloak first, then the platform IDPs.
    fn providers() -> Vec<ProviderConfig> {
        vec![
            provider("keycloak", "https://idp.example/realms/drpepper", true),
            provider("google", "https://accounts.google.com", true),
            provider("apple", "https://appleid.apple.com", true),
            provider("microsoft", "https://login.microsoftonline.com/organizations/v2.0", true),
        ]
    }

    async fn answer(email: &str, providers: &[ProviderConfig]) -> (SignInMethod, i32) {
        let resp = classify(&resolver(), &finder(), providers, email).await;
        (SignInMethod::try_from(resp.method).unwrap(), resp.provider_index)
    }

    #[tokio::test]
    async fn google_workspace_mx_answers_the_google_provider() {
        assert_eq!(answer("pat@legacy-google.example", &providers()).await, (SignInMethod::Google, 1));
        assert_eq!(answer("pat@new-google.example", &providers()).await, (SignInMethod::Google, 1));
    }

    #[tokio::test]
    async fn microsoft_365_mx_answers_the_microsoft_provider() {
        assert_eq!(answer("pat@m365.example", &providers()).await, (SignInMethod::Microsoft, 3));
        assert_eq!(answer("pat@m365-dnssec.example", &providers()).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn icloud_mx_answers_the_apple_provider() {
        assert_eq!(answer("pat@icloud.example", &providers()).await, (SignInMethod::Apple, 2));
    }

    #[tokio::test]
    async fn icloud_mx_with_no_apple_provider_answers_unsupported() {
        let mut apple_off = providers();
        apple_off[2].enable = false;
        assert_eq!(answer("pat@icloud.example", &apple_off).await, (SignInMethod::Unsupported, 0));
    }

    #[tokio::test]
    async fn the_domain_is_matched_case_insensitively() {
        assert_eq!(answer("Pat@M365.Example", &providers()).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn anything_else_answers_unsupported() {
        for email in [
            "pat@selfhosted.example",
            "pat@lookalike.example",
            "pat@empty.example",
            "pat@nxdomain.example",
            "pat@split.example",
            "pat@icloud-google-split.example",
        ] {
            assert_eq!(
                answer(email, &providers()).await,
                (SignInMethod::Unsupported, 0),
                "{email} must answer unsupported"
            );
        }
    }

    #[tokio::test]
    async fn only_the_most_preferred_records_count() {
        assert_eq!(answer("pat@migrating.example", &providers()).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn an_unconfigured_or_disabled_provider_answers_unsupported() {
        let no_microsoft = providers()[..3].to_vec();
        assert_eq!(answer("pat@m365.example", &no_microsoft).await, (SignInMethod::Unsupported, 0));

        let mut google_off = providers();
        google_off[1].enable = false;
        assert_eq!(answer("pat@new-google.example", &google_off).await, (SignInMethod::Unsupported, 0));

        assert_eq!(answer("pat@new-google.example", &[]).await, (SignInMethod::Unsupported, 0));
    }

    #[tokio::test]
    async fn the_provider_is_found_by_issuer_not_by_name() {
        let renamed = vec![
            provider("Continue with Microsoft", "https://login.microsoftonline.com/organizations/v2.0", true),
            provider("Google", "https://accounts.google.com", true),
            provider("google", "https://idp.example/realms/google", true),
        ];
        assert_eq!(answer("pat@m365.example", &renamed).await, (SignInMethod::Microsoft, 0));
        assert_eq!(answer("pat@new-google.example", &renamed).await, (SignInMethod::Google, 1));
    }

    /// The dev provider list plus a second, single-directory Microsoft provider.
    fn providers_with_tenant() -> Vec<ProviderConfig> {
        let mut providers = providers();
        providers.push(provider(
            "contoso",
            "https://login.microsoftonline.com/0f0e0d0c-0000-4000-8000-000000000001/v2.0",
            true,
        ));
        providers
    }

    async fn alternatives(email: &str, providers: &[ProviderConfig]) -> Vec<(SignInMethod, i32)> {
        let resp = classify(&resolver(), &finder(), providers, email).await;
        resp.alternatives.iter().map(|o| (SignInMethod::try_from(o.method).unwrap(), o.provider_index)).collect()
    }

    #[tokio::test]
    async fn a_txt_google_issuer_beats_a_microsoft_mx() {
        assert_eq!(answer("pat@txt-google.example", &providers()).await, (SignInMethod::Google, 1));
    }

    #[tokio::test]
    async fn a_txt_microsoft_issuer_beats_a_google_mx() {
        assert_eq!(answer("pat@txt-microsoft.example", &providers()).await, (SignInMethod::Microsoft, 3));
        // Any path on the Microsoft host, a directory's issuer included.
        assert_eq!(answer("pat@txt-microsoft-tenant.example", &providers()).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn a_txt_apple_issuer_beats_a_microsoft_mx() {
        assert_eq!(answer("pat@txt-apple.example", &providers()).await, (SignInMethod::Apple, 2));
    }

    #[tokio::test]
    async fn a_txt_record_signs_in_an_icloud_mail_domain_with_google() {
        assert_eq!(answer("jody@thescottsweb.com", &providers()).await, (SignInMethod::Google, 1));
    }

    #[tokio::test]
    async fn a_custom_txt_issuer_falls_through() {
        // No `SignInMethod` for it: DNS never adds a trusted issuer.
        assert_eq!(answer("pat@txt-custom-issuer.example", &providers()).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn a_txt_issuer_with_no_enabled_provider_falls_through() {
        let mut google_off = providers();
        google_off[1].enable = false;
        assert_eq!(answer("pat@txt-google.example", &google_off).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn an_ambiguous_or_malformed_txt_record_is_ignored() {
        for email in [
            "pat@txt-two-records.example",
            "pat@txt-v-not-first.example",
            "pat@txt-no-version.example",
            "pat@txt-no-iss.example",
            "pat@txt-empty-iss.example",
            "pat@txt-two-iss.example",
            "pat@txt-scheme-iss.example",
            "pat@txt-port-iss.example",
            "pat@txt-lookalike-iss.example",
        ] {
            assert_eq!(answer(email, &providers()).await, (SignInMethod::Microsoft, 3), "{email} must answer from MX");
        }
    }

    #[tokio::test]
    async fn txt_tags_tolerate_case_whitespace_and_unknown_tags() {
        assert_eq!(answer("pat@txt-sloppy.example", &providers()).await, (SignInMethod::Google, 1));
        assert_eq!(answer("pat@txt-one-of-many.example", &providers()).await, (SignInMethod::Google, 1));
    }

    #[tokio::test]
    async fn a_failed_txt_lookup_asks_webfinger() {
        // wf-google.example has no `_openid` name: the fake fails it like NXDOMAIN.
        assert!(resolver().txt("_openid.wf-google.example").await.is_err());
        assert_eq!(answer("pat@wf-google.example", &providers()).await, (SignInMethod::Google, 1));
    }

    #[tokio::test]
    async fn a_webfinger_issuer_beats_the_mx() {
        assert_eq!(answer("pat@wf-google.example", &providers()).await, (SignInMethod::Google, 1));
        assert_eq!(answer("pat@wf-microsoft.example", &providers()).await, (SignInMethod::Microsoft, 3));
        assert_eq!(answer("pat@wf-apple.example", &providers()).await, (SignInMethod::Apple, 2));
    }

    #[tokio::test]
    async fn an_unusable_webfinger_issuer_falls_back_to_mx() {
        assert_eq!(answer("pat@wf-custom.example", &providers()).await, (SignInMethod::Microsoft, 3));
        assert_eq!(answer("pat@wf-http.example", &providers()).await, (SignInMethod::Microsoft, 3));
        assert_eq!(answer("pat@m365.example", &providers()).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn webfinger_is_asked_only_when_txt_gave_nothing() {
        let finder = finder();
        let resp = classify(&resolver(), &finder, &providers(), "pat@txt-google.example").await;
        assert_eq!(resp.method, SignInMethod::Google as i32);
        assert_eq!(finder.calls.load(Ordering::SeqCst), 0, "a usable TXT issuer answers before WebFinger");

        classify(&resolver(), &finder, &providers(), "pat@txt-custom-issuer.example").await;
        classify(&resolver(), &finder, &providers(), "pat@m365.example").await;
        assert_eq!(finder.calls.load(Ordering::SeqCst), 2, "an unusable or missing TXT record asks WebFinger once");
    }

    #[tokio::test]
    async fn the_alternatives_are_every_other_google_microsoft_or_apple_provider() {
        assert_eq!(
            alternatives("pat@m365.example", &providers()).await,
            vec![(SignInMethod::Google, 1), (SignInMethod::Apple, 2)],
        );
        assert_eq!(
            alternatives("pat@txt-google.example", &providers()).await,
            vec![(SignInMethod::Apple, 2), (SignInMethod::Microsoft, 3)],
        );
        assert_eq!(
            alternatives("pat@txt-microsoft-tenant.example", &providers_with_tenant()).await,
            vec![(SignInMethod::Google, 1), (SignInMethod::Apple, 2), (SignInMethod::Microsoft, 4)],
        );
    }

    #[tokio::test]
    async fn an_icloud_guess_offers_google_as_an_alternative() {
        // Jody's case without the TXT record: iCloud mail, but a Google login.
        assert_eq!(answer("pat@icloud.example", &providers()).await, (SignInMethod::Apple, 2));
        assert_eq!(
            alternatives("pat@icloud.example", &providers()).await,
            vec![(SignInMethod::Google, 1), (SignInMethod::Microsoft, 3)],
        );
    }

    #[tokio::test]
    async fn an_unsupported_guess_offers_every_google_microsoft_or_apple_provider() {
        let all = vec![
            (SignInMethod::Google, 1),
            (SignInMethod::Apple, 2),
            (SignInMethod::Microsoft, 3),
            (SignInMethod::Microsoft, 4),
        ];
        for email in ["pat@selfhosted.example", "pat@nxdomain.example"] {
            assert_eq!(answer(email, &providers_with_tenant()).await, (SignInMethod::Unsupported, 0));
            assert_eq!(alternatives(email, &providers_with_tenant()).await, all, "{email}");
        }
    }

    #[tokio::test]
    async fn a_disabled_provider_is_never_an_alternative() {
        let mut microsoft_off = providers_with_tenant();
        microsoft_off[3].enable = false;
        assert_eq!(
            alternatives("pat@new-google.example", &microsoft_off).await,
            vec![(SignInMethod::Apple, 2), (SignInMethod::Microsoft, 4)],
        );
        assert_eq!(
            alternatives("pat@selfhosted.example", &microsoft_off).await,
            vec![(SignInMethod::Google, 1), (SignInMethod::Apple, 2), (SignInMethod::Microsoft, 4)],
        );
    }

    #[test]
    fn is_public_refuses_every_internal_and_special_range() {
        for addr in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "2001:db8::1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "240.0.0.1",
        ] {
            assert!(!is_public(addr.parse().unwrap()), "{addr} must be refused");
        }
    }

    #[test]
    fn is_public_accepts_public_unicast() {
        for addr in ["8.8.8.8", "2001:4860:4860::8888", "::ffff:8.8.8.8", "100.128.0.1", "172.32.0.1"] {
            assert!(is_public(addr.parse().unwrap()), "{addr} must be accepted");
        }
    }

    #[test]
    fn the_webfinger_url_is_encoded_and_only_for_a_plain_domain() {
        assert_eq!(
            webfinger_url("example.com", "pat+x@example.com").unwrap().as_str(),
            "https://example.com/.well-known/webfinger?resource=acct%3Apat%2Bx%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer",
        );
        for domain in ["127.0.0.1", "[::1]", "example.com:8443", "example.com/x", "evil.example#.example.com", ""] {
            assert!(webfinger_url(domain, "pat@example.com").is_none(), "{domain} must be refused");
        }
    }

    #[test]
    fn jrd_issuer_is_the_first_https_issuer_link() {
        let body = br#"{"subject":"acct:pat@example.com","links":[
            {"rel":"http://webfinger.net/rel/profile-page","href":"https://example.com/pat"},
            {"rel":"http://openid.net/specs/connect/1.0/issuer","href":"https://accounts.google.com"},
            {"rel":"http://openid.net/specs/connect/1.0/issuer","href":"https://login.microsoftonline.com/common/v2.0"}
        ]}"#;
        assert_eq!(jrd_issuer(body).as_deref(), Some("https://accounts.google.com"));

        let http_first = br#"{"links":[
            {"rel":"http://openid.net/specs/connect/1.0/issuer","href":"http://accounts.google.com"},
            {"rel":"http://openid.net/specs/connect/1.0/issuer","href":"https://accounts.google.com"}
        ]}"#;
        assert_eq!(jrd_issuer(http_first), None, "the first issuer link decides, and it must be https");

        assert_eq!(jrd_issuer(br#"{"links":[{"rel":"other","href":"https://accounts.google.com"}]}"#), None);
        assert_eq!(jrd_issuer(br#"{"subject":"acct:pat@example.com"}"#), None);
        assert_eq!(jrd_issuer(b"not json"), None);
        assert_eq!(jrd_issuer(b""), None);
    }

    #[test]
    fn the_global_ceiling_refuses_after_its_burst_across_addresses() {
        let per_email = EmailRateLimiter::new();
        let global = GlobalRateLimiter::new();
        let t0 = Instant::now();
        for i in 0..GLOBAL_BURST as usize {
            let email = format!("pat{i}@m365.example");
            assert!(per_email.allow(&email, t0) && global.allow(t0), "lookup {i} is inside the burst");
        }
        assert!(per_email.allow("fresh@m365.example", t0), "a new address is inside its own limit");
        assert!(!global.allow(t0), "but the process is over its ceiling");

        assert!(global.allow(t0 + Duration::from_millis(100)), "one lookup refills per 1/rate seconds");
        assert!(!global.allow(t0 + Duration::from_millis(100)));
    }

    #[test]
    fn one_address_is_limited_to_its_burst_then_its_rate() {
        let limiter = EmailRateLimiter::new();
        let t0 = Instant::now();
        for i in 0..5 {
            assert!(limiter.allow("pat@m365.example", t0), "lookup {i} is inside the burst");
        }
        assert!(!limiter.allow("pat@m365.example", t0), "the sixth lookup is over the burst");
        assert!(!limiter.allow("PAT@M365.EXAMPLE", t0), "the address is limited whatever its case");
        assert!(limiter.allow("someone-else@m365.example", t0), "another address has its own bucket");

        assert!(!limiter.allow("pat@m365.example", t0 + Duration::from_secs(59)));
        assert!(limiter.allow("pat@m365.example", t0 + Duration::from_secs(61)), "one lookup refills per minute");
        assert!(!limiter.allow("pat@m365.example", t0 + Duration::from_secs(61)));
    }

    #[test]
    fn a_full_table_admits_new_addresses_and_still_limits_tracked_ones() {
        let limiter = EmailRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(limiter.allow("pat@m365.example", t0));
        }
        for i in 1..MAX_TRACKED_EMAILS {
            assert!(limiter.allow(&format!("filler{i}@example.com"), t0));
        }
        assert_eq!(limiter.buckets.lock().unwrap().len(), MAX_TRACKED_EMAILS);

        assert!(limiter.allow("newcomer@example.com", t0), "a full table must not lock a new address out");
        assert!(!limiter.allow("pat@m365.example", t0), "a tracked address keeps its limit");
        assert_eq!(limiter.buckets.lock().unwrap().len(), MAX_TRACKED_EMAILS, "the table never grows past its bound");

        // Once the fillers have idled out, a prune makes room and new addresses are tracked again.
        let later = t0 + Duration::from_secs(BUCKET_IDLE_SECS as u64 + 1);
        assert!(limiter.allow("newcomer@example.com", later));
        assert_eq!(limiter.buckets.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_table_holds_no_address() {
        let limiter = EmailRateLimiter::new();
        limiter.allow("pat@m365.example", Instant::now());
        let expected: [u8; 32] = Sha256::digest(b"pat@m365.example").into();
        assert!(limiter.buckets.lock().unwrap().contains_key(&expected));
    }
}
