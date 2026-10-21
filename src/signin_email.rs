//! Auth.ClassifySignInEmail: how a person signs in, from their work email's MX.
//!
//! The domain's most-preferred MX hosts name its mail provider: Google Workspace
//! or Microsoft 365 answer with the configured provider of that IDP, so the SPA
//! goes straight to Authorize; anything else is unsupported. The answer is a
//! function of public DNS and this service's provider config only. Nothing here
//! reads an account, so the answer cannot say whether one exists.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use sha2::{Digest, Sha256};
use tracing::info;

use oauth_model::types::services::oauth::oauth::{
    ClassifySignInEmailResponse, ProviderConfig, SignInMethod,
};

/// The issuer a Google provider is configured with.
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// The issuer prefix every Microsoft Entra ID provider is configured with
/// (`.../organizations/v2.0`, `.../common/v2.0` or one directory's GUID).
const MICROSOFT_ISSUER_PREFIX: &str = "https://login.microsoftonline.com/";

/// MxResolver answers a domain's MX records as (preference, exchange host).
///
/// A trait so the tests can answer from a table; the service uses the system
/// resolver (`TokioResolver`).
#[tonic::async_trait]
pub trait MxResolver: Send + Sync {
    async fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>, String>;
}

#[tonic::async_trait]
impl MxResolver for TokioResolver {
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

/// The index of the first enabled provider for an IDP, by its issuer rather than
/// its free-form name.
fn provider_index(providers: &[ProviderConfig], method: SignInMethod) -> Option<i32> {
    providers
        .iter()
        .position(|p| {
            p.enable
                && match method {
                    SignInMethod::Google => p.issuer == GOOGLE_ISSUER,
                    SignInMethod::Microsoft => p.issuer.starts_with(MICROSOFT_ISSUER_PREFIX),
                    _ => false,
                }
        })
        .map(|i| i as i32)
}

/// Classify `email` (already schema-validated as an address) against
/// `providers`. A lookup failure, an unknown provider, or a provider that is not
/// configured all answer unsupported.
pub async fn classify(
    resolver: &dyn MxResolver,
    providers: &[ProviderConfig],
    email: &str,
) -> ClassifySignInEmailResponse {
    let domain = email.rsplit_once('@').map_or("", |(_, d)| d).to_ascii_lowercase();
    let method = match resolver.mx(&domain).await {
        Ok(records) => mail_provider(&records),
        Err(e) => {
            // info, not warn: a typo or a made-up domain lands here, and the
            // route is public.
            info!(domain = %domain, error = %e, "MX lookup failed, answering unsupported");
            None
        }
    };
    match method.and_then(|m| provider_index(providers, m).map(|i| (m, i))) {
        Some((method, index)) => ClassifySignInEmailResponse {
            method: method as i32,
            provider_index: index,
            ..Default::default()
        },
        None => ClassifySignInEmailResponse {
            method: SignInMethod::Unsupported as i32,
            ..Default::default()
        },
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
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * RATE_PER_EMAIL_PER_SEC).min(BURST_PER_EMAIL);
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Answers from a table; a domain not in it fails like NXDOMAIN.
    struct FakeResolver(HashMap<&'static str, Vec<(u16, &'static str)>>);

    #[tonic::async_trait]
    impl MxResolver for FakeResolver {
        async fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>, String> {
            self.0
                .get(domain)
                .map(|rs| rs.iter().map(|(p, h)| (*p, h.to_string())).collect())
                .ok_or_else(|| format!("no records found for {domain}"))
        }
    }

    fn resolver() -> FakeResolver {
        FakeResolver(HashMap::from([
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
        ]))
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
