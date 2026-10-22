//! Auth.ClassifySignInEmail: how a person signs in, guessed from their work
//! email's DNS.
//!
//! A `_seabeam.<domain>` TXT record naming the IDP wins. Otherwise the domain's
//! most-preferred MX hosts name its mail provider: Google Workspace or Microsoft
//! 365 answer with the configured provider of that IDP, so the SPA goes straight
//! to Authorize; anything else is unsupported. Every other enabled Google or
//! Microsoft provider is offered as an alternative, so a person whose guess is
//! wrong (or missing) can pick. The answer is a function of public DNS and this
//! service's provider config only. Nothing here reads an account, so the answer
//! cannot say whether one exists.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use sha2::{Digest, Sha256};
use tracing::info;

use oauth_model::types::services::oauth::oauth::{
    ClassifySignInEmailResponse, ProviderConfig, SignInMethod, SignInOption,
};

/// The issuer a Google provider is configured with.
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// The issuer prefix every Microsoft Entra ID provider is configured with
/// (`.../organizations/v2.0`, `.../common/v2.0` or one directory's GUID).
const MICROSOFT_ISSUER_PREFIX: &str = "https://login.microsoftonline.com/";

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

/// What a domain's `_seabeam` TXT record names as its IDP.
#[derive(Debug, PartialEq)]
enum TxtIdp {
    Method(SignInMethod),
    Issuer(String),
}

/// The IDP named by the one valid `v=seabeam1; idp=<google|microsoft|https://issuer>`
/// record among `records`. Tags are `;`-separated with whitespace around them
/// ignored, tag names and the `v`/keyword values are case-insensitive, and
/// unknown tags are ignored. A record whose first tag is not `v=seabeam1` is not
/// ours. None when no record or more than one is ours, or ours has no single
/// well-formed `idp`: the guess then falls to MX rather than to an IDP the
/// domain may not have meant.
fn seabeam_idp(records: &[String]) -> Option<TxtIdp> {
    let mut ours = records.iter().filter_map(|record| {
        let mut tags = record.split(';').map(str::trim).filter(|t| !t.is_empty()).map(|t| {
            let (name, value) = t.split_once('=').unwrap_or((t, ""));
            (name.trim().to_ascii_lowercase(), value.trim())
        });
        match tags.next() {
            Some((name, value)) if name == "v" && value.eq_ignore_ascii_case("seabeam1") => Some(tags),
            _ => None,
        }
    });
    let tags = ours.next()?;
    if ours.next().is_some() {
        return None;
    }
    let mut idps = tags.filter(|(name, _)| name == "idp").map(|(_, value)| value);
    let idp = idps.next()?;
    if idps.next().is_some() {
        return None;
    }
    if idp.eq_ignore_ascii_case("google") {
        Some(TxtIdp::Method(SignInMethod::Google))
    } else if idp.eq_ignore_ascii_case("microsoft") {
        Some(TxtIdp::Method(SignInMethod::Microsoft))
    } else if idp.starts_with("https://") {
        Some(TxtIdp::Issuer(idp.to_string()))
    } else {
        None
    }
}

/// The mail provider a set of MX records names, judged by the most-preferred
/// records only: a domain migrating between providers keeps the old one at a
/// higher preference value, and the lowest value is where its mail goes now.
/// None when those records name neither provider, or name both.
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

/// The enabled provider a TXT record's IDP names. An issuer is answered only
/// when it is a configured Google or Microsoft provider's issuer: DNS never adds
/// a trusted issuer.
fn txt_provider(providers: &[ProviderConfig], idp: TxtIdp) -> Option<(SignInMethod, i32)> {
    match idp {
        TxtIdp::Method(method) => provider_index(providers, method).map(|i| (method, i)),
        TxtIdp::Issuer(issuer) => providers.iter().enumerate().find_map(|(i, p)| {
            let method = issuer_method(&p.issuer)?;
            (p.enable && p.issuer == issuer).then_some((method, i as i32))
        }),
    }
}

/// Classify `email` (already schema-validated as an address) against
/// `providers`. The domain's `_seabeam` TXT record decides when it names a
/// usable provider; otherwise its MX does. A lookup failure, an unknown
/// provider, or a provider that is not configured all leave the guess
/// unsupported; the alternatives are every other enabled Google or Microsoft
/// provider either way.
pub async fn classify(
    resolver: &dyn DnsResolver,
    providers: &[ProviderConfig],
    email: &str,
) -> ClassifySignInEmailResponse {
    let domain = email.rsplit_once('@').map_or("", |(_, d)| d).to_ascii_lowercase();
    // A failed TXT lookup is the usual case (most domains have no `_seabeam`
    // name), so it is not logged.
    let from_txt = match resolver.txt(&format!("_seabeam.{domain}")).await {
        Ok(records) => seabeam_idp(&records).and_then(|idp| txt_provider(providers, idp)),
        Err(_) => None,
    };
    let guess = match from_txt {
        Some(guess) => Some(guess),
        None => {
            let method = match resolver.mx(&domain).await {
                Ok(records) => mail_provider(&records),
                Err(e) => {
                    // info, not warn: a typo or a made-up domain lands here, and
                    // the route is public.
                    info!(domain = %domain, error = %e, "MX lookup failed, answering unsupported");
                    None
                }
            };
            method.and_then(|m| provider_index(providers, m).map(|i| (m, i)))
        }
    };
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
/// Each classify costs up to two outbound DNS queries (TXT, then MX). Real
/// sign-ins are a few per person per day; even a whole company arriving on a
/// Monday morning is a few per second, and the gateway already holds each
/// client IP to 0.5/s (burst 30). 10/s sustained (36,000 an hour) is far above
/// that, while capping what many IPs together can make this service send to
/// the resolver at 20 queries a second; a burst of 100 absorbs a wave of
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
    use std::time::Duration;

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
            ("txt-google.example", vec![M365_MX]),
            ("txt-microsoft.example", vec![GOOGLE_MX]),
            // Jody's case: a Google login whose mail is on iCloud.
            ("thescottsweb.com", vec![(10, "mx01.mail.icloud.com."), (10, "mx02.mail.icloud.com.")]),
            ("txt-tenant-issuer.example", vec![GOOGLE_MX]),
            ("txt-unknown-issuer.example", vec![GOOGLE_MX]),
            ("txt-keycloak-issuer.example", vec![GOOGLE_MX]),
            ("txt-two-records.example", vec![M365_MX]),
            ("txt-v-not-first.example", vec![M365_MX]),
            ("txt-no-version.example", vec![M365_MX]),
            ("txt-sloppy.example", vec![M365_MX]),
            ("txt-bad-idp.example", vec![M365_MX]),
            ("txt-http-issuer.example", vec![M365_MX]),
            ("txt-two-idps.example", vec![M365_MX]),
            ("txt-no-idp.example", vec![M365_MX]),
            ("txt-one-of-many.example", vec![M365_MX]),
        ]), txt: HashMap::from([
            ("_seabeam.txt-google.example", vec!["v=seabeam1; idp=google"]),
            ("_seabeam.txt-microsoft.example", vec!["v=seabeam1; idp=microsoft"]),
            ("_seabeam.thescottsweb.com", vec!["v=seabeam1; idp=google"]),
            ("_seabeam.txt-tenant-issuer.example", vec!["v=seabeam1; idp=https://login.microsoftonline.com/0f0e0d0c-0000-4000-8000-000000000001/v2.0"]),
            ("_seabeam.txt-unknown-issuer.example", vec!["v=seabeam1; idp=https://idp.attacker.example"]),
            ("_seabeam.txt-keycloak-issuer.example", vec!["v=seabeam1; idp=https://idp.example/realms/drpepper"]),
            ("_seabeam.txt-two-records.example", vec!["v=seabeam1; idp=google", "v=seabeam1; idp=google"]),
            ("_seabeam.txt-v-not-first.example", vec!["idp=google; v=seabeam1"]),
            ("_seabeam.txt-no-version.example", vec!["idp=google"]),
            ("_seabeam.txt-sloppy.example", vec![" V = SeaBeam1 ;color=blue;  IDP =Google ; future-tag ;"]),
            ("_seabeam.txt-bad-idp.example", vec!["v=seabeam1; idp=okta"]),
            ("_seabeam.txt-http-issuer.example", vec!["v=seabeam1; idp=http://accounts.google.com"]),
            ("_seabeam.txt-two-idps.example", vec!["v=seabeam1; idp=google; idp=microsoft"]),
            ("_seabeam.txt-no-idp.example", vec!["v=seabeam1"]),
            // Other services' records under the same name are not ours.
            ("_seabeam.txt-one-of-many.example", vec!["google-site-verification=abc", "v=seabeam1; idp=google", "v=spf1 -all"]),
        ]) }
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
        let resp = classify(&resolver(), providers, email).await;
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
        let resp = classify(&resolver(), providers, email).await;
        resp.alternatives.iter().map(|o| (SignInMethod::try_from(o.method).unwrap(), o.provider_index)).collect()
    }

    #[tokio::test]
    async fn a_txt_google_record_beats_a_microsoft_mx() {
        assert_eq!(answer("pat@txt-google.example", &providers()).await, (SignInMethod::Google, 1));
    }

    #[tokio::test]
    async fn a_txt_microsoft_record_beats_a_google_mx() {
        assert_eq!(answer("pat@txt-microsoft.example", &providers()).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn a_txt_record_signs_in_an_icloud_mail_domain_with_google() {
        assert_eq!(answer("jody@thescottsweb.com", &providers()).await, (SignInMethod::Google, 1));
    }

    #[tokio::test]
    async fn a_txt_issuer_of_a_configured_provider_answers_that_provider() {
        assert_eq!(answer("pat@txt-tenant-issuer.example", &providers_with_tenant()).await, (SignInMethod::Microsoft, 4));
    }

    #[tokio::test]
    async fn an_unusable_txt_issuer_falls_back_to_mx() {
        // Not configured at all: DNS never adds a trusted issuer.
        assert_eq!(answer("pat@txt-unknown-issuer.example", &providers()).await, (SignInMethod::Google, 1));
        assert_eq!(answer("pat@txt-tenant-issuer.example", &providers()).await, (SignInMethod::Google, 1));
        // Configured, but not a provider this RPC can answer.
        assert_eq!(answer("pat@txt-keycloak-issuer.example", &providers()).await, (SignInMethod::Google, 1));
        // Configured but disabled.
        let mut tenant_off = providers_with_tenant();
        tenant_off[4].enable = false;
        assert_eq!(answer("pat@txt-tenant-issuer.example", &tenant_off).await, (SignInMethod::Google, 1));
    }

    #[tokio::test]
    async fn a_txt_method_with_no_enabled_provider_falls_back_to_mx() {
        let mut google_off = providers();
        google_off[1].enable = false;
        assert_eq!(answer("pat@txt-google.example", &google_off).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn an_ambiguous_or_malformed_txt_record_is_ignored_for_mx() {
        for email in [
            "pat@txt-two-records.example",
            "pat@txt-v-not-first.example",
            "pat@txt-no-version.example",
            "pat@txt-bad-idp.example",
            "pat@txt-http-issuer.example",
            "pat@txt-two-idps.example",
            "pat@txt-no-idp.example",
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
    async fn a_failed_txt_lookup_answers_from_mx() {
        // m365.example has MX but no `_seabeam` name: the fake fails it like NXDOMAIN.
        assert!(resolver().txt("_seabeam.m365.example").await.is_err());
        assert_eq!(answer("pat@m365.example", &providers()).await, (SignInMethod::Microsoft, 3));
    }

    #[tokio::test]
    async fn the_alternatives_are_every_other_google_or_microsoft_provider() {
        assert_eq!(alternatives("pat@m365.example", &providers()).await, vec![(SignInMethod::Google, 1)]);
        assert_eq!(alternatives("pat@txt-google.example", &providers()).await, vec![(SignInMethod::Microsoft, 3)]);
        assert_eq!(
            alternatives("pat@txt-tenant-issuer.example", &providers_with_tenant()).await,
            vec![(SignInMethod::Google, 1), (SignInMethod::Microsoft, 3)],
        );
    }

    #[tokio::test]
    async fn an_unsupported_guess_offers_every_google_or_microsoft_provider() {
        let all = vec![(SignInMethod::Google, 1), (SignInMethod::Microsoft, 3), (SignInMethod::Microsoft, 4)];
        for email in ["pat@selfhosted.example", "pat@nxdomain.example"] {
            assert_eq!(answer(email, &providers_with_tenant()).await, (SignInMethod::Unsupported, 0));
            assert_eq!(alternatives(email, &providers_with_tenant()).await, all, "{email}");
        }
    }

    #[tokio::test]
    async fn a_disabled_provider_is_never_an_alternative() {
        let mut microsoft_off = providers_with_tenant();
        microsoft_off[3].enable = false;
        assert_eq!(alternatives("pat@new-google.example", &microsoft_off).await, vec![(SignInMethod::Microsoft, 4)]);
        assert_eq!(
            alternatives("pat@selfhosted.example", &microsoft_off).await,
            vec![(SignInMethod::Google, 1), (SignInMethod::Microsoft, 4)],
        );
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
