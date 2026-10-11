use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{info, warn};

use oauth_model::types::services::oauth::oauth::ProviderConfig;

use crate::apple::AppleClientSecret;

/// Subset of .well-known/openid-configuration that we need.
#[derive(Debug, Clone, Default, serde::Deserialize)]
struct OidcConfig {
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: Option<String>,
    end_session_endpoint: Option<String>,
}

/// Per-provider discovered endpoints and cached JWKS.
struct OidcProvider {
    config: RwLock<OidcConfig>,
    jwks: RwLock<CachedJwks>,
    provider_cfg: ProviderConfig,
    http_client: Client,
    /// Set for a provider with `apple`: its client secret is minted per token
    /// exchange instead of read from `client_secret`.
    apple_secret: Option<AppleClientSecret>,
}

impl OidcProvider {
    /// The redirect_uri the IDP is sent, on both the authorize and the token
    /// request. A form_post provider (Apple) answers at the server-side
    /// callback it was registered with; `callback_url` then only travels in the
    /// state, as the place that callback finally sends the browser.
    fn redirect_uri<'a>(&'a self, callback_url: &'a str) -> &'a str {
        match &self.provider_cfg.apple {
            Some(apple) => &apple.form_post_redirect_uri,
            None => callback_url,
        }
    }
}

#[derive(Default)]
struct CachedJwks {
    keys: Vec<JwkEntry>,
    last_fetch: Option<Instant>,
}

/// A single JWK entry from the IDP's JWKS endpoint.
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct JwkEntry {
    pub kid: Option<String>,
    pub kty: Option<String>,
    pub alg: Option<String>,
    /// We keep the raw JSON for signature verification.
    #[serde(flatten)]
    pub raw: HashMap<String, serde_json::Value>,
}

impl JwkEntry {
    /// Reassembles the original JWK JSON object.
    ///
    /// kid/kty/alg are lifted into typed fields and the rest is captured by the
    /// flattened `raw` map, so the object has to be put back together before it
    /// can be deserialized into the chassis Jwk for signature verification.
    pub fn to_json_value(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        for (k, v) in &self.raw {
            obj.insert(k.clone(), v.clone());
        }
        if let Some(ref kid) = self.kid {
            obj.insert("kid".to_string(), serde_json::Value::String(kid.clone()));
        }
        if let Some(ref kty) = self.kty {
            obj.insert("kty".to_string(), serde_json::Value::String(kty.clone()));
        }
        if let Some(ref alg) = self.alg {
            obj.insert("alg".to_string(), serde_json::Value::String(alg.clone()));
        }
        serde_json::Value::Object(obj)
    }
}

/// Token response from the IDP's token endpoint.
#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub id_token: Option<String>,
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
}

/// OIDC client handles discovery, authorization URL construction, and token exchange.
pub struct OidcClient {
    providers: HashMap<i32, Arc<OidcProvider>>,
    refetch_interval: Duration,
    default_scopes: Vec<String>,
}

impl OidcClient {
    /// Create a new OidcClient and discover endpoints for all enabled providers.
    ///
    /// `apple_key_p8` is the PEM of the Sign in with Apple key
    /// (`Secrets.apple_signin_key_p8`), used by any provider that sets `apple`.
    pub async fn new(
        providers_cfg: &[ProviderConfig],
        default_scopes: &[String],
        refetch_interval_secs: i64,
        apple_key_p8: &str,
    ) -> Result<Self, String> {
        let scopes = if default_scopes.is_empty() {
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]
        } else {
            default_scopes.to_vec()
        };

        let mut oc = OidcClient {
            providers: HashMap::new(),
            refetch_interval: Duration::from_secs(refetch_interval_secs as u64),
            default_scopes: scopes,
        };

        for (i, p) in providers_cfg.iter().enumerate() {
            if !p.enable {
                continue;
            }

            // TLS certificate verification is ON for every IDP connection. It used
            // to be disabled here (danger_accept_invalid_certs) in BOTH branches,
            // on the claim that "rustls-webpki does not verify Ed25519 CA chains
            // correctly" -- which also made a configured ca_pem pointless. Anyone
            // able to intercept the IDP connection could then serve their own JWKS
            // and mint tokens this platform would trust: a full auth bypass.
            //
            // The Ed25519 claim does not hold. rustls-webpki verifies an Ed25519
            // CA chain -- see the tests at the bottom of this file, which stand up
            // a real TLS server behind an Ed25519 root and check both that the
            // chain is accepted and that an untrusted cert is refused.
            //
            // http1_only is a SEPARATE, non-security workaround and stays: mock
            // OIDC servers (Netty-based) don't advertise ALPN, and hyper/h2 fails
            // when ALPN negotiation returns None.
            let mut builder = Client::builder()
                .timeout(Duration::from_secs(10))
                // Stated rather than left to the feature defaults: the runtime
                // image has no /etc/ssl/certs, so the compiled-in Mozilla root
                // store is the only trust anchor set an IDP connection has.
                .tls_built_in_webpki_certs(true)
                .http1_only();
            if !p.ca_pem.is_empty() {
                info!(provider = %p.name, "using custom CA for OIDC HTTP client");
                let cert = reqwest::Certificate::from_pem(p.ca_pem.as_bytes())
                    .map_err(|e| format!("parsing CA PEM for provider {}: {e}", p.name))?;
                builder = builder.add_root_certificate(cert);
            }
            let http_client = builder
                .build()
                .map_err(|e| format!("creating HTTP client for provider {}: {e}", p.name))?;

            let apple_secret = match &p.apple {
                Some(apple) => Some(
                    AppleClientSecret::new(apple, &p.client_id, apple_key_p8)
                        .map_err(|e| format!("provider {}: {e}", p.name))?,
                ),
                None => None,
            };

            let prov = Arc::new(OidcProvider {
                config: RwLock::new(OidcConfig::default()),
                jwks: RwLock::new(CachedJwks::default()),
                provider_cfg: p.clone(),
                http_client,
                apple_secret,
            });
            if let Err(e) = oc.discover(&prov).await {
                warn!(provider = %p.name, error = %e, "OIDC discovery failed");
                // Apply explicit endpoint overrides from config as fallback when
                // discovery fails (e.g. self-signed CA, network unreachable).
                let mut cfg = prov.config.write().await;
                if !p.authorization_endpoint.is_empty() {
                    cfg.authorization_endpoint = Some(p.authorization_endpoint.clone());
                }
                if !p.token_endpoint.is_empty() {
                    cfg.token_endpoint = Some(p.token_endpoint.clone());
                }
                if !p.end_session_endpoint.is_empty() {
                    cfg.end_session_endpoint = Some(p.end_session_endpoint.clone());
                }
            }
            oc.providers.insert(i as i32, prov);
        }

        Ok(oc)
    }

    /// Fetch .well-known/openid-configuration for a provider.
    async fn discover(&self, prov: &OidcProvider) -> Result<(), String> {
        let issuer = prov.provider_cfg.issuer.trim_end_matches('/');
        let well_known = format!("{issuer}/.well-known/openid-configuration");

        let resp = prov
            .http_client
            .get(&well_known)
            .send()
            .await
            .map_err(|e| format!("fetch: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("unexpected status {}", resp.status()));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("read body: {e}"))?;

        let mut cfg: OidcConfig =
            serde_json::from_slice(&body).map_err(|e| format!("parse config: {e}"))?;

        // Allow provider config overrides
        if !prov.provider_cfg.authorization_endpoint.is_empty() {
            cfg.authorization_endpoint = Some(prov.provider_cfg.authorization_endpoint.clone());
        }
        if !prov.provider_cfg.token_endpoint.is_empty() {
            cfg.token_endpoint = Some(prov.provider_cfg.token_endpoint.clone());
        }
        if !prov.provider_cfg.end_session_endpoint.is_empty() {
            cfg.end_session_endpoint = Some(prov.provider_cfg.end_session_endpoint.clone());
        }

        let auth_ep = cfg
            .authorization_endpoint
            .as_deref()
            .unwrap_or("(none)")
            .to_string();
        *prov.config.write().await = cfg;

        info!(
            provider = %prov.provider_cfg.name,
            auth_endpoint = %auth_ep,
            "OIDC discovery complete"
        );

        Ok(())
    }

    /// Read one discovered endpoint, rediscovering lazily if it is not there.
    ///
    /// Discovery runs once, in `new()`, and a failure there used to be permanent:
    /// the endpoint stayed `None` and every Authorize answered 500 until somebody
    /// restarted oauth by hand. That is a startup race against the IDP — oauth
    /// comes up first, Keycloak is not serving `.well-known` yet — and it recurs
    /// on every later IDP restart too, so on a cluster where things get restarted
    /// routinely it is a trap rather than a one-off.
    ///
    /// `fetch_jwks` already retried discovery for exactly this reason; the JWKS
    /// URI was simply the only endpoint that did. Every endpoint accessor now
    /// goes through here instead, so a provider that was undiscoverable at init
    /// recovers on the next request that needs it.
    async fn endpoint(
        &self,
        prov: &OidcProvider,
        name: &str,
        pick: fn(&OidcConfig) -> Option<String>,
    ) -> Result<String, String> {
        if let Some(v) = pick(&*prov.config.read().await) {
            return Ok(v);
        }
        self.discover(prov).await.map_err(|e| {
            format!(
                "no {name} for provider {} (discovery retry: {e})",
                prov.provider_cfg.name
            )
        })?;
        pick(&*prov.config.read().await).ok_or_else(|| {
            format!(
                "no {name} for provider {} after discovery retry",
                prov.provider_cfg.name
            )
        })
    }

    /// Build the IDP authorization redirect URL with PKCE (S256).
    ///
    /// `nonce` is the caller-supplied OIDC nonce. An empty `nonce` sends no
    /// `nonce` param at all rather than an empty one — IDPs differ on what an
    /// empty value means, and only a device-possession login needs one.
    pub async fn build_authorize_url(
        &self,
        provider_index: i32,
        state: &str,
        code_verifier: &str,
        redirect_uri: &str,
        nonce: &str,
    ) -> Result<String, String> {
        let prov = self
            .providers
            .get(&provider_index)
            .ok_or_else(|| format!("unknown provider index {provider_index}"))?;

        let auth_endpoint = self
            .endpoint(prov, "authorization endpoint", |c| {
                c.authorization_endpoint.clone()
            })
            .await?;

        let scopes = if prov.provider_cfg.scopes.is_empty() {
            &self.default_scopes
        } else {
            &prov.provider_cfg.scopes
        };

        // PKCE code_challenge = BASE64URL(SHA256(code_verifier))
        let hash = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        let scope = scopes.join(" ");
        let mut params = vec![
            ("response_type", "code"),
            ("client_id", &prov.provider_cfg.client_id),
            ("redirect_uri", prov.redirect_uri(redirect_uri)),
            ("scope", &scope),
            ("state", state),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ];
        if !nonce.is_empty() {
            params.push(("nonce", nonce));
        }
        // Apple requires form_post whenever name or email is requested, and
        // answers it at the server-side callback named by redirect_uri.
        if prov.provider_cfg.apple.is_some() {
            params.push(("response_mode", "form_post"));
        }

        let query = serde_urlencoded::to_string(params)
            .map_err(|e| format!("encoding params: {e}"))?;

        Ok(format!("{auth_endpoint}?{query}"))
    }

    /// Exchange an authorization code for IDP tokens.
    pub async fn exchange_code(
        &self,
        provider_index: i32,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, String> {
        let prov = self
            .providers
            .get(&provider_index)
            .ok_or_else(|| format!("unknown provider index {provider_index}"))?;

        let token_endpoint = self
            .endpoint(prov, "token endpoint", |c| c.token_endpoint.clone())
            .await?;

        let client_secret = match &prov.apple_secret {
            Some(apple) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                apple.mint(now)?
            }
            None => prov.provider_cfg.client_secret.clone(),
        };

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", prov.redirect_uri(redirect_uri)),
            ("client_id", &prov.provider_cfg.client_id),
            ("client_secret", &client_secret),
            ("code_verifier", code_verifier),
        ];

        let resp = prov
            .http_client
            .post(&token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("token exchange: {e}"))?;

        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| format!("read body: {e}"))?;

        if !status.is_success() {
            return Err(format!(
                "token endpoint returned {}: {}",
                status,
                String::from_utf8_lossy(&body)
            ));
        }

        serde_json::from_slice(&body).map_err(|e| format!("parse token response: {e}"))
    }

    /// The (issuer, client_id) an id_token from this provider must carry.
    ///
    /// Verification lives in auth.rs but the provider config is private here,
    /// so the two values the token must be BOUND to are exposed deliberately
    /// and narrowly. Without binding, a validly-signed token from one
    /// configured provider is accepted for another — the signature check alone
    /// does not catch that.
    ///
    /// For a provider with `issuer_template` the issuer is that template, still
    /// holding "{tid}"; `verify_id_token` fills it from the verified token.
    pub fn expected_claims(&self, provider_index: i32) -> Result<(String, String), String> {
        let prov = self
            .providers
            .get(&provider_index)
            .ok_or_else(|| format!("unknown provider index {provider_index}"))?;
        let issuer = if prov.provider_cfg.issuer_template.is_empty() {
            &prov.provider_cfg.issuer
        } else {
            &prov.provider_cfg.issuer_template
        };
        Ok((
            issuer.trim_end_matches('/').to_string(),
            prov.provider_cfg.client_id.clone(),
        ))
    }

    /// Fetch the IDP's JWKS. Results are cached for refetch_interval.
    pub async fn fetch_jwks(&self, provider_index: i32) -> Result<Vec<JwkEntry>, String> {
        let prov = self
            .providers
            .get(&provider_index)
            .ok_or_else(|| format!("unknown provider index {provider_index}"))?;

        // Check cache
        {
            let cache = prov.jwks.read().await;
            if let Some(last) = cache.last_fetch {
                if last.elapsed() < self.refetch_interval && !cache.keys.is_empty() {
                    return Ok(cache.keys.clone());
                }
            }
        }

        let jwks_uri = self
            .endpoint(prov, "JWKS URI", |c| c.jwks_uri.clone())
            .await?;

        let resp = prov
            .http_client
            .get(&jwks_uri)
            .send()
            .await
            .map_err(|e| format!("fetch JWKS: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("JWKS endpoint returned {}", resp.status()));
        }

        let body = resp.bytes().await.map_err(|e| format!("read body: {e}"))?;

        #[derive(serde::Deserialize)]
        struct JwksResponse {
            keys: Vec<JwkEntry>,
        }

        let jwks: JwksResponse =
            serde_json::from_slice(&body).map_err(|e| format!("parse JWKS: {e}"))?;

        // Update cache
        let keys = jwks.keys;
        {
            let mut cache = prov.jwks.write().await;
            cache.keys = keys.clone();
            cache.last_fetch = Some(Instant::now());
        }

        Ok(keys)
    }

    /// Return the IDP's end-session URL for a provider, or empty string.
    pub async fn end_session_endpoint(&self, provider_index: i32) -> String {
        if let Some(prov) = self.providers.get(&provider_index) {
            let cfg = prov.config.read().await;
            cfg.end_session_endpoint
                .as_deref()
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    const ED25519_CA: &str = include_str!("../tests/fixtures/ed25519-ca.crt");
    const ED25519_LEAF_CRT: &str = include_str!("../tests/fixtures/ed25519-leaf.crt");
    const ED25519_LEAF_KEY: &str = include_str!("../tests/fixtures/ed25519-leaf.key");
    const ROGUE_CRT: &str = include_str!("../tests/fixtures/rogue.crt");
    const ROGUE_KEY: &str = include_str!("../tests/fixtures/rogue.key");

    /// Stand up a throwaway HTTPS listener serving an OIDC discovery document.
    ///
    /// `chain_pem` is what the server presents; the tests vary it to play either
    /// the legitimate IDP (leaf under the Ed25519 test CA) or an interceptor
    /// (self-signed cert the client has no reason to trust).
    async fn spawn_idp(chain_pem: &str, key_pem: &str) -> u16 {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let certs = rustls_pemfile::certs(&mut BufReader::new(chain_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .expect("parse server chain");
        let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))
            .expect("parse server key")
            .expect("server key present");

        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(cfg));

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local addr").port();

        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // A failed handshake is the expected outcome in the negative
                    // tests, so it is dropped rather than treated as an error.
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    let mut buf = [0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let body = r#"{"authorization_endpoint":"https://idp.test/auth","token_endpoint":"https://idp.test/token","jwks_uri":"https://idp.test/jwks"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        port
    }

    fn provider(port: u16, ca_pem: &str) -> ProviderConfig {
        ProviderConfig {
            enable: true,
            name: "test".to_string(),
            issuer: format!("https://localhost:{port}"),
            client_id: "test-client".to_string(),
            ca_pem: ca_pem.to_string(),
            ..Default::default()
        }
    }

    /// Drive the client all the way to a discovered endpoint.
    ///
    /// `OidcClient::new` deliberately swallows a discovery failure and falls back
    /// to configured endpoint overrides, so it is not the observable. No overrides
    /// are set here, so `build_authorize_url` re-runs discovery and surfaces the
    /// real result.
    async fn discover_via_client(p: ProviderConfig) -> Result<String, String> {
        let oc = OidcClient::new(&[p], &[], 3600, "").await?;
        oc.build_authorize_url(0, "state", "verifier", "https://rp.test/cb", "")
            .await
    }

    /// reqwest's Display only prints the outermost error, so the TLS cause has to
    /// be pulled out of the source chain to be asserted on.
    fn error_chain(e: &dyn std::error::Error) -> String {
        let mut out = e.to_string();
        let mut src = e.source();
        while let Some(s) = src {
            out.push_str(&format!(" <- {s}"));
            src = s.source();
        }
        out
    }

    /// A caller-supplied nonce reaches the IDP's authorization endpoint. Without
    /// it the IDP has no reason to put a `nonce` claim in the id_token, so
    /// kernel's `origin_nonce` device-link check has nothing to compare.
    #[tokio::test]
    async fn a_supplied_nonce_is_sent_to_the_idp() {
        let port = spawn_idp(ED25519_LEAF_CRT, ED25519_LEAF_KEY).await;
        let oc = OidcClient::new(&[provider(port, ED25519_CA)], &[], 3600, "")
            .await
            .expect("client");
        let url = oc
            .build_authorize_url(0, "state", "verifier", "https://rp.test/cb", "device-key-thumbprint")
            .await
            .expect("authorize URL");
        assert!(
            url.contains("nonce=device-key-thumbprint"),
            "the supplied nonce must be in the query: {url}"
        );
    }

    /// Every login that is not proving device possession supplies no nonce, and
    /// must send no `nonce` param at all — not an empty one.
    #[tokio::test]
    async fn no_nonce_param_is_sent_when_none_is_supplied() {
        let port = spawn_idp(ED25519_LEAF_CRT, ED25519_LEAF_KEY).await;
        let oc = OidcClient::new(&[provider(port, ED25519_CA)], &[], 3600, "")
            .await
            .expect("client");
        let url = oc
            .build_authorize_url(0, "state", "verifier", "https://rp.test/cb", "")
            .await
            .expect("authorize URL");
        assert!(!url.contains("nonce="), "no nonce param may appear: {url}");
    }

    /// The workaround this file used to carry claimed rustls-webpki cannot verify
    /// an Ed25519 CA chain. It can: this is a real TLS handshake against a real
    /// leaf issued by a real Ed25519 root, with verification fully enabled.
    #[tokio::test]
    async fn ed25519_ca_chain_verifies() {
        let port = spawn_idp(ED25519_LEAF_CRT, ED25519_LEAF_KEY).await;
        let url = discover_via_client(provider(port, ED25519_CA))
            .await
            .expect("Ed25519 CA chain must verify");
        assert!(url.starts_with("https://idp.test/auth?"), "got {url}");
    }

    /// The MITM case: an interceptor answers on the IDP's address with a cert the
    /// configured CA did not issue. The handshake must fail.
    #[tokio::test]
    async fn untrusted_cert_rejected_when_ca_configured() {
        let port = spawn_idp(ROGUE_CRT, ROGUE_KEY).await;
        let err = discover_via_client(provider(port, ED25519_CA))
            .await
            .expect_err("untrusted cert must not be accepted");
        assert!(err.contains("discovery retry"), "got {err}");
    }

    /// Same, with no ca_pem configured: the system trust store must not accept a
    /// self-signed IDP cert either.
    #[tokio::test]
    async fn untrusted_cert_rejected_with_system_roots() {
        let port = spawn_idp(ROGUE_CRT, ROGUE_KEY).await;
        let err = discover_via_client(provider(port, ""))
            .await
            .expect_err("untrusted cert must not be accepted");
        assert!(err.contains("discovery retry"), "got {err}");
    }

    /// Names the actual rejection reason, which the OidcClient error string cannot
    /// carry (reqwest's Display drops the cause chain). Guards against the request
    /// failing for some unrelated reason and the tests above passing vacuously.
    #[tokio::test]
    async fn rejection_reason_is_certificate_verification() {
        let port = spawn_idp(ROGUE_CRT, ROGUE_KEY).await;
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .http1_only()
            .build()
            .unwrap();
        let err = client
            .get(format!("https://localhost:{port}/.well-known/openid-configuration"))
            .send()
            .await
            .expect_err("must fail");
        let chain = error_chain(&err);
        assert!(
            chain.contains("UnknownIssuer") || chain.contains("certificate"),
            "expected a certificate failure, got: {chain}"
        );
    }

    /// Paired live control against the real IDP, opt-in because it needs the
    /// cluster. Run with OAUTH_TEST_LIVE_ISSUER=https://<keycloak>/realms/<realm>.
    #[tokio::test]
    async fn live_idp_verifies() {
        let Ok(issuer) = std::env::var("OAUTH_TEST_LIVE_ISSUER") else {
            eprintln!("skipped: OAUTH_TEST_LIVE_ISSUER not set");
            return;
        };
        let p = ProviderConfig {
            enable: true,
            name: "live".to_string(),
            issuer,
            client_id: "schematic".to_string(),
            ..Default::default()
        };
        let issuer = p.issuer.clone();
        let url = discover_via_client(p)
            .await
            .expect("live IDP chain must verify");
        assert!(url.contains("code_challenge_method=S256"), "got {url}");

        // Same fetch with the OS trust store switched off, which is what the
        // runtime image actually is: it ships no /etc/ssl/certs. If this fails,
        // verification works on a developer box and breaks in the cluster.
        let container_like = Client::builder()
            .timeout(Duration::from_secs(10))
            .tls_built_in_webpki_certs(true)
            .tls_built_in_native_certs(false)
            .http1_only()
            .build()
            .unwrap();
        let resp = container_like
            .get(format!("{issuer}/.well-known/openid-configuration"))
            .send()
            .await
            .expect("live IDP must verify against the compiled-in root store alone");
        assert!(resp.status().is_success(), "got {}", resp.status());
    }
}
