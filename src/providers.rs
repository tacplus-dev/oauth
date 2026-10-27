//! The provider list oauth offers and brokers: the fleet-wide `Config.providers`
//! followed by the providers of every tenant's `OAuthTenantConfig` slice.
//!
//! The fleet runs one oauth instance, rooted at /system, that brokers every
//! login (decided 2026-10-25), so a tenant's IdP is one record in its own slice
//! kernel stores, not an entry an operator copies into the fleet's list. The
//! merged list is what the rest of the service indexes: ListProviders, the
//! OIDC client, the state codec and the callback checks all see one list, and a
//! tenant provider's login takes exactly the path a fleet-wide one does.

use std::collections::HashMap;

use tracing::{error, info, warn};

use oauth_model::types::services::kernel::kernel::TenantConfigEntry;
use oauth_model::types::services::oauth::oauth::{
    Config, OAuthProvider, OAuthTenantConfig, ProviderConfig,
};

/// `ListProvidersResponse.providers`' `assert_max_size`. The generated server
/// validates responses, so a list past it would fail ListProviders for
/// everyone; a tenant slice that would take the list past it is refused whole.
pub const MAX_LISTED_PROVIDERS: usize = 256;

/// `ProviderInfo.name`'s `assert_max_size`.
const MAX_NAME_BYTES: usize = 128;

/// The reserved `people` tenant. Kernel seeds its slice with Apple, Google and
/// Microsoft (kernel.proto PeopleIdpCredential), which an `OAuthProvider`
/// cannot express (no `apple`, no `issuer_template`), so its providers stay
/// fleet-wide in `Config.providers` and its slice is not read (Hub, 2026-10-27).
const PEOPLE_TENANT: &str = "people";

/// One tenant's oauth config slice.
#[derive(Clone, Debug, PartialEq)]
pub struct TenantSlice {
    pub tenant: String,
    pub config: OAuthTenantConfig,
}

/// The oauth slices of kernel's `ConfigState.tenant_configs`, in tenant order so
/// the merged list (and the provider indexes it gives) does not depend on the
/// map's iteration order.
pub fn tenant_slices(entries: &HashMap<String, TenantConfigEntry>) -> Vec<TenantSlice> {
    let mut slices: Vec<TenantSlice> = entries
        .iter()
        .filter_map(|(key, entry)| {
            let config = entry.config.as_ref()?.oauth.clone()?;
            let tenant = if entry.tenant_name.is_empty() { key } else { &entry.tenant_name };
            Some(TenantSlice { tenant: tenant.clone(), config })
        })
        .collect();
    slices.sort_by(|a, b| a.tenant.cmp(&b.tenant));
    slices
}

/// The tenant's own name, without the namespace form ("/tenants/acme", "/acme").
fn tenant_label(tenant: &str) -> &str {
    let bare = tenant.trim_start_matches('/');
    bare.strip_prefix("tenants/").unwrap_or(bare)
}

/// Why `p` cannot authenticate to its token endpoint, if it cannot: a Sign in
/// with Apple provider needs the .p8 key from the pod env, any other a static
/// `client_secret`. `client_secret` is not schema-required (an Apple provider
/// has none), so this is what keeps a provider missing both from being offered.
pub fn credential_error(p: &ProviderConfig, apple_key_p8: &str) -> Option<String> {
    match &p.apple {
        Some(_) if apple_key_p8.is_empty() => Some(
            "it sets apple, but PROTO_SERVICES_OAUTH_SECRETS_APPLE_SIGNIN_KEY_P8 is empty".to_string(),
        ),
        None if p.client_secret.is_empty() => Some("it has no client_secret".to_string()),
        _ => None,
    }
}

/// The (issuer, client_id) pair that identifies a provider's client. A
/// trailing slash on the issuer does not make it another provider.
fn client_key<'a>(issuer: &'a str, client_id: &'a str) -> (&'a str, &'a str) {
    (issuer.trim_end_matches('/'), client_id)
}

/// Whose a provider is: the operator's fleet-wide list, or a tenant's slice.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderOwner {
    Fleet,
    Tenant(String),
}

/// The stable name of a provider: its owner and client. A sign-in state names
/// its provider by this, not by its index in the list, which shifts whenever a
/// tenant's slice is added, edited or deleted; a state whose key is no longer
/// offered resolves to nothing instead of to whatever provider took its index.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProviderKey {
    #[serde(rename = "o")]
    pub owner: ProviderOwner,
    #[serde(rename = "i")]
    pub issuer: String,
    #[serde(rename = "c")]
    pub client_id: String,
}

impl ProviderKey {
    pub fn new(owner: ProviderOwner, p: &ProviderConfig) -> Self {
        let (issuer, client_id) = client_key(&p.issuer, &p.client_id);
        Self { owner, issuer: issuer.to_string(), client_id: client_id.to_string() }
    }
}

/// A tenant slice's provider as the service's provider type.
///
/// Its redirect allowlist is the operator's `tenant_redirect_uri_prefixes`:
/// the redirect target is the fleet's webapp, which a tenant may never name.
/// `jwks_uri` has no counterpart: like a fleet-wide provider's, the JWKS comes
/// from the issuer's discovery document.
fn tenant_provider(tenant: &str, p: &OAuthProvider, redirect_prefixes: &[String]) -> ProviderConfig {
    let name = if p.name.is_empty() {
        let host = reqwest::Url::parse(&p.issuer_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| p.issuer_url.clone());
        let mut name = format!("{}: {host}", tenant_label(tenant));
        if name.len() > MAX_NAME_BYTES {
            let mut end = MAX_NAME_BYTES;
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            name.truncate(end);
        }
        name
    } else {
        p.name.clone()
    };
    ProviderConfig {
        enable: p.enable,
        name,
        issuer: p.issuer_url.clone(),
        client_id: p.client_id.clone(),
        client_secret: p.client_secret.clone(),
        scopes: p.allowed_scopes.clone(),
        ca_pem: p.ca_pem.clone(),
        allowed_redirect_uri_prefixes: redirect_prefixes.to_vec(),
        ..Default::default()
    }
}

/// The providers the service offers, each with its key: `cfg.providers`, at
/// their own indexes, then each tenant slice's.
///
/// The list is built from `cfg` and `slices` alone: nothing of an earlier list
/// is carried over, so a provider its tenant removed (or a tenant deleted with
/// its slice) is in no list built after.
///
/// One bad provider never takes the others down: an enabled provider missing
/// its credential is disabled (a fleet-wide one keeps its index, so the list
/// an operator wrote still lines up), and a tenant provider is left out when it
/// lacks its secret, has an unusable `ca_pem`, or names the (issuer, client_id)
/// of a fleet-wide provider or of another tenant's. A tenant slice that would
/// take the offered list past MAX_LISTED_PROVIDERS is left out whole. Each
/// refusal is logged with the tenant it came from.
pub fn effective_providers(
    cfg: &Config,
    slices: &[TenantSlice],
    apple_key_p8: &str,
) -> Vec<(ProviderKey, ProviderConfig)> {
    let mut providers: Vec<(ProviderKey, ProviderConfig)> = cfg
        .providers
        .iter()
        .cloned()
        .map(|mut p| {
            if p.enable {
                if let Some(why) = credential_error(&p, apple_key_p8) {
                    error!(provider = %p.name, "provider disabled: {why}");
                    p.enable = false;
                }
            }
            (ProviderKey::new(ProviderOwner::Fleet, &p), p)
        })
        .collect();

    let slices: Vec<&TenantSlice> = slices
        .iter()
        .filter(|s| s.config.providers.iter().any(|p| p.enable))
        .filter(|s| {
            let people = tenant_label(&s.tenant) == PEOPLE_TENANT;
            if people {
                info!(tenant = %s.tenant, "the people tenant's providers are fleet-wide, its slice is not read");
            }
            !people
        })
        .collect();
    if slices.is_empty() {
        return providers;
    }
    if cfg.tenant_redirect_uri_prefixes.is_empty() {
        warn!(
            tenants = slices.len(),
            "tenant providers are not offered: Config.tenant_redirect_uri_prefixes is empty"
        );
        return providers;
    }

    // Who holds each (issuer, client_id): None for the fleet-wide list.
    let mut owners: HashMap<(String, String), Option<String>> = HashMap::new();
    for (_, p) in &providers {
        let (iss, id) = client_key(&p.issuer, &p.client_id);
        owners.insert((iss.to_string(), id.to_string()), None);
    }
    let mut listed = providers.iter().filter(|(_, p)| p.enable).count();

    for slice in slices {
        let tenant = slice.tenant.as_str();
        let mut accepted: Vec<ProviderConfig> = Vec::new();
        for p in slice.config.providers.iter().filter(|p| p.enable) {
            let candidate = tenant_provider(tenant, p, &cfg.tenant_redirect_uri_prefixes);
            let (iss, id) = client_key(&candidate.issuer, &candidate.client_id);
            let key = (iss.to_string(), id.to_string());
            let taken = owners.get(&key).cloned().or_else(|| {
                accepted
                    .iter()
                    .any(|a| client_key(&a.issuer, &a.client_id) == (iss, id))
                    .then(|| Some(tenant.to_string()))
            });
            match taken {
                Some(None) => {
                    warn!(tenant = %tenant, issuer = %candidate.issuer, client_id = %candidate.client_id,
                        "tenant provider refused: it shadows a fleet-wide provider");
                    continue;
                }
                Some(Some(owner)) => {
                    warn!(tenant = %tenant, owner = %owner, issuer = %candidate.issuer, client_id = %candidate.client_id,
                        "tenant provider refused: another tenant provider has the same issuer and client_id");
                    continue;
                }
                None => {}
            }
            if let Some(why) = credential_error(&candidate, apple_key_p8) {
                error!(tenant = %tenant, provider = %candidate.name, "tenant provider disabled: {why}");
                continue;
            }
            if let Err(e) = crate::oidc::http_client(&candidate) {
                error!(tenant = %tenant, provider = %candidate.name, error = %e, "tenant provider disabled");
                continue;
            }
            accepted.push(candidate);
        }

        if listed + accepted.len() > MAX_LISTED_PROVIDERS {
            warn!(
                tenant = %tenant,
                providers = accepted.len(),
                listed,
                max = MAX_LISTED_PROVIDERS,
                "tenant slice refused: its providers would take the provider list past its bound"
            );
            continue;
        }
        listed += accepted.len();
        for a in &accepted {
            let (iss, id) = client_key(&a.issuer, &a.client_id);
            owners.insert((iss.to_string(), id.to_string()), Some(tenant.to_string()));
        }
        let owner = ProviderOwner::Tenant(tenant.to_string());
        providers.extend(accepted.into_iter().map(|a| (ProviderKey::new(owner.clone(), &a), a)));
    }
    providers
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use oauth_model::types::generated::tenant_config::tenant_config::TenantConfig;
    use oauth_model::types::services::oauth::oauth::AppleSignIn;

    const WEBAPP: &str = "https://console.example/";
    const P8: &str = "-----BEGIN PRIVATE KEY-----";

    fn fleet(name: &str, issuer: &str) -> ProviderConfig {
        ProviderConfig {
            enable: true,
            name: name.to_string(),
            issuer: issuer.to_string(),
            client_id: "fleet-client".to_string(),
            client_secret: "fleet-secret".to_string(),
            allowed_redirect_uri_prefixes: vec![WEBAPP.to_string()],
            ..Default::default()
        }
    }

    fn config(providers: Vec<ProviderConfig>) -> Config {
        Config {
            enable: true,
            providers,
            tenant_redirect_uri_prefixes: vec![WEBAPP.to_string()],
            ..Default::default()
        }
    }

    fn tenant_idp(issuer: &str, client_id: &str) -> OAuthProvider {
        OAuthProvider {
            enable: true,
            issuer_url: issuer.to_string(),
            client_id: client_id.to_string(),
            client_secret: format!("{client_id}-secret"),
            ..Default::default()
        }
    }

    fn slice(tenant: &str, providers: Vec<OAuthProvider>) -> TenantSlice {
        TenantSlice {
            tenant: tenant.to_string(),
            config: OAuthTenantConfig { providers, ..Default::default() },
        }
    }

    /// The offered providers without their keys.
    fn offered(cfg: &Config, slices: &[TenantSlice], apple_key_p8: &str) -> Vec<ProviderConfig> {
        effective_providers(cfg, slices, apple_key_p8).into_iter().map(|(_, p)| p).collect()
    }

    fn names(providers: &[ProviderConfig]) -> Vec<(&str, bool)> {
        providers.iter().map(|p| (p.name.as_str(), p.enable)).collect()
    }

    /// What `f` logs, as the fmt layer writes it.
    fn logs<T>(f: impl FnOnce() -> T) -> (T, String) {
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        (out, text)
    }

    #[test]
    fn without_tenant_slices_the_fleet_list_is_unchanged() {
        let cfg = config(vec![fleet("Google", "https://accounts.google.com"), fleet("Okta", "https://okta.example")]);
        assert_eq!(offered(&cfg, &[], ""), cfg.providers);
    }

    #[test]
    fn tenant_providers_follow_the_fleet_list_with_the_operator_allowlist() {
        let cfg = config(vec![fleet("Google", "https://accounts.google.com")]);
        let mut named = tenant_idp("https://login.beta.example/realm", "beta-client");
        named.name = "Beta SSO".to_string();
        named.allowed_scopes = vec!["openid".to_string(), "groups".to_string()];
        let mut off = tenant_idp("https://off.acme.example", "off");
        off.enable = false;
        let slices = vec![
            slice("/tenants/acme", vec![tenant_idp("https://idp.acme.example/oidc", "acme-client"), off]),
            slice("/tenants/beta", vec![named]),
        ];

        let got = offered(&cfg, &slices, "");
        assert_eq!(names(&got), [("Google", true), ("acme: idp.acme.example", true), ("Beta SSO", true)]);
        let acme = &got[1];
        assert_eq!(acme.issuer, "https://idp.acme.example/oidc");
        assert_eq!(acme.client_id, "acme-client");
        assert_eq!(acme.client_secret, "acme-client-secret");
        assert_eq!(acme.allowed_redirect_uri_prefixes, [WEBAPP]);
        assert_eq!(got[2].scopes, ["openid", "groups"]);
    }

    #[test]
    fn a_long_fallback_name_is_cut_to_the_provider_info_bound() {
        let tenant = "é".repeat(100);
        let got = offered(&config(vec![]), &[slice(&tenant, vec![tenant_idp("https://idp.example", "c")])], "");
        assert!(got[0].name.len() <= MAX_NAME_BYTES && got[0].name.len() > MAX_NAME_BYTES - 2, "{}", got[0].name);
    }

    #[test]
    fn no_tenant_allowlist_offers_no_tenant_provider() {
        let mut cfg = config(vec![fleet("Google", "https://accounts.google.com")]);
        cfg.tenant_redirect_uri_prefixes.clear();
        let slices = [slice("/tenants/acme", vec![tenant_idp("https://idp.acme.example", "acme")])];
        let (got, log) = logs(|| offered(&cfg, &slices, ""));
        assert_eq!(got, cfg.providers);
        assert!(log.contains("tenant_redirect_uri_prefixes is empty"), "{log}");
    }

    #[test]
    fn the_people_tenant_slice_is_not_read() {
        let cfg = config(vec![fleet("Google", "https://accounts.google.com")]);
        for people in ["people", "/people", "/tenants/people"] {
            let slices = [slice(people, vec![tenant_idp("https://appleid.apple.com", "com.example.people")])];
            assert_eq!(offered(&cfg, &slices, ""), cfg.providers, "{people}");
        }
        // A tenant merely named like it is read.
        let slices = [slice("/tenants/peoples", vec![tenant_idp("https://idp.example", "c")])];
        assert_eq!(offered(&cfg, &slices, "").len(), 2);
    }

    #[test]
    fn a_tenant_cannot_shadow_a_fleet_wide_provider() {
        let mut disabled = fleet("Okta", "https://okta.example");
        disabled.enable = false;
        let cfg = config(vec![fleet("Google", "https://accounts.google.com"), disabled]);
        let slices = [slice(
            "/tenants/acme",
            vec![
                // Same issuer (bar a trailing slash) and client id as Google.
                tenant_idp("https://accounts.google.com/", "fleet-client"),
                // A disabled fleet-wide provider is still the fleet's.
                tenant_idp("https://okta.example", "fleet-client"),
                // The same issuer with the tenant's own client is the tenant's.
                tenant_idp("https://accounts.google.com", "acme-client"),
            ],
        )];

        let (got, log) = logs(|| offered(&cfg, &slices, ""));
        assert_eq!(names(&got), [("Google", true), ("Okta", false), ("acme: accounts.google.com", true)]);
        assert_eq!(got[2].client_id, "acme-client");
        assert_eq!(log.matches("shadows a fleet-wide provider").count(), 2, "{log}");
        assert!(log.contains("tenant=/tenants/acme"), "{log}");
    }

    #[test]
    fn a_tenant_cannot_take_another_tenants_client() {
        let slices = [
            slice("/tenants/acme", vec![tenant_idp("https://idp.example", "shared")]),
            slice("/tenants/beta", vec![tenant_idp("https://idp.example", "shared"), tenant_idp("https://idp.example", "beta")]),
        ];
        let (got, log) = logs(|| offered(&config(vec![]), &slices, ""));
        assert_eq!(got.iter().map(|p| p.client_id.as_str()).collect::<Vec<_>>(), ["shared", "beta"]);
        assert!(log.contains("tenant=/tenants/beta owner=/tenants/acme"), "{log}");
    }

    #[test]
    fn a_provider_missing_its_credential_disables_only_itself() {
        let mut no_secret = fleet("NoSecret", "https://nosecret.example");
        no_secret.client_secret.clear();
        let mut apple = fleet("Apple", "https://appleid.apple.com");
        apple.client_secret.clear();
        apple.apple = Some(AppleSignIn::default());
        let cfg = config(vec![no_secret, fleet("Google", "https://accounts.google.com"), apple]);
        let mut tenant_no_secret = tenant_idp("https://idp.acme.example", "acme");
        tenant_no_secret.client_secret.clear();
        let slices = [slice("/tenants/acme", vec![tenant_no_secret, tenant_idp("https://other.acme.example", "acme")])];

        // Without the .p8 the Apple provider is off too; every other stays.
        let (got, log) = logs(|| offered(&cfg, &slices, ""));
        assert_eq!(
            names(&got),
            [("NoSecret", false), ("Google", true), ("Apple", false), ("acme: other.acme.example", true)]
        );
        assert!(log.contains("provider disabled: it has no client_secret"), "{log}");
        assert!(log.contains("tenant=/tenants/acme"), "{log}");

        // With it, Apple is offered.
        let got = offered(&cfg, &slices, P8);
        assert_eq!(names(&got)[2], ("Apple", true));
    }

    #[test]
    fn a_tenant_provider_with_an_unusable_ca_is_left_out() {
        let mut bad_ca = tenant_idp("https://idp.acme.example", "acme");
        bad_ca.ca_pem = "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n".to_string();
        let slices = [slice("/tenants/acme", vec![bad_ca, tenant_idp("https://other.acme.example", "acme")])];
        let got = offered(&config(vec![]), &slices, "");
        assert_eq!(names(&got), [("acme: other.acme.example", true)]);
    }

    #[test]
    fn a_slice_past_the_list_bound_is_refused_whole() {
        let fleet_list: Vec<ProviderConfig> =
            (0..16).map(|i| fleet(&format!("f{i}"), &format!("https://f{i}.example"))).collect();
        let tenant = |t: usize, n: usize| {
            slice(
                &format!("/tenants/t{t:02}"),
                (0..n).map(|i| tenant_idp(&format!("https://t{t}.example"), &format!("c{i}"))).collect(),
            )
        };
        // 16 fleet-wide + 15 × 16 is exactly the bound; t15's one more is past
        // it, and t16's empty slice still fits.
        let mut slices: Vec<TenantSlice> = (0..15).map(|t| tenant(t, 16)).collect();
        slices.push(tenant(15, 1));
        slices.push(tenant(16, 0));

        let (got, log) = logs(|| offered(&config(fleet_list), &slices, ""));
        assert_eq!(got.len(), MAX_LISTED_PROVIDERS);
        assert!(got.iter().all(|p| p.issuer != "https://t15.example"));
        assert!(log.contains("tenant=/tenants/t15"), "{log}");
        assert!(log.contains("past its bound"), "{log}");
    }

    #[test]
    fn tenant_slices_are_the_oauth_slices_in_tenant_order() {
        let entry = |name: &str, oauth: Option<OAuthTenantConfig>| TenantConfigEntry {
            tenant_name: name.to_string(),
            config: Some(TenantConfig { oauth, ..Default::default() }),
            ..Default::default()
        };
        let one = OAuthTenantConfig { providers: vec![tenant_idp("https://idp.example", "c")], ..Default::default() };
        let entries: HashMap<String, TenantConfigEntry> = [
            ("/tenants/zeta".to_string(), entry("/tenants/zeta", Some(one.clone()))),
            ("/tenants/acme".to_string(), entry("/tenants/acme", Some(OAuthTenantConfig::default()))),
            ("/tenants/kilo".to_string(), entry("/tenants/kilo", None)),
            ("/tenants/keyed".to_string(), entry("", Some(one.clone()))),
        ]
        .into_iter()
        .collect();
        let got: Vec<String> = tenant_slices(&entries).into_iter().map(|s| s.tenant).collect();
        assert_eq!(got, ["/tenants/acme", "/tenants/keyed", "/tenants/zeta"]);
    }
}
