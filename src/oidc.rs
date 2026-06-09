use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{info, warn};

use oauth_model::types::services::oauth::oauth::ProviderConfig;

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
    pub async fn new(
        providers_cfg: &[ProviderConfig],
        default_scopes: &[String],
        refetch_interval_secs: i64,
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

            // danger_accept_invalid_certs is needed because rustls-webpki does not verify
            // Ed25519 CA chains correctly. http1_only is needed because mock OIDC servers
            // (Netty-based) don't advertise ALPN, and hyper/h2 fails when ALPN returns None.
            // TODO: remove both workarounds once rustls-webpki Ed25519 CA chain bug is fixed.
            let http_client = if !p.ca_pem.is_empty() {
                info!(provider = %p.name, "using custom CA for OIDC HTTP client");
                let cert = reqwest::Certificate::from_pem(p.ca_pem.as_bytes())
                    .map_err(|e| format!("parsing CA PEM for provider {}: {e}", p.name))?;
                Client::builder()
                    .timeout(Duration::from_secs(10))
                    .add_root_certificate(cert)
                    .danger_accept_invalid_certs(true)
                    .http1_only()
                    .build()
                    .map_err(|e| format!("creating HTTP client for provider {}: {e}", p.name))?
            } else {
                warn!(provider = %p.name, "no ca_pem configured; using danger_accept_invalid_certs as workaround");
                Client::builder()
                    .timeout(Duration::from_secs(10))
                    .danger_accept_invalid_certs(true)
                    .http1_only()
                    .build()
                    .map_err(|e| format!("creating HTTP client: {e}"))?
            };

            let prov = Arc::new(OidcProvider {
                config: RwLock::new(OidcConfig::default()),
                jwks: RwLock::new(CachedJwks::default()),
                provider_cfg: p.clone(),
                http_client,
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

    /// Build the IDP authorization redirect URL with PKCE (S256).
    pub async fn build_authorize_url(
        &self,
        provider_index: i32,
        state: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<String, String> {
        let prov = self
            .providers
            .get(&provider_index)
            .ok_or_else(|| format!("unknown provider index {provider_index}"))?;

        let cfg = prov.config.read().await;
        let auth_endpoint = cfg
            .authorization_endpoint
            .as_deref()
            .ok_or_else(|| format!("no authorization endpoint for provider {}", prov.provider_cfg.name))?;

        let scopes = if prov.provider_cfg.scopes.is_empty() {
            &self.default_scopes
        } else {
            &prov.provider_cfg.scopes
        };

        // PKCE code_challenge = BASE64URL(SHA256(code_verifier))
        let hash = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        let params = [
            ("response_type", "code"),
            ("client_id", &prov.provider_cfg.client_id),
            ("redirect_uri", redirect_uri),
            ("scope", &scopes.join(" ")),
            ("state", state),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ];

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

        let cfg = prov.config.read().await;
        let token_endpoint = cfg
            .token_endpoint
            .as_deref()
            .ok_or_else(|| format!("no token endpoint for provider {}", prov.provider_cfg.name))?
            .to_string();
        drop(cfg);

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", &prov.provider_cfg.client_id),
            ("client_secret", &prov.provider_cfg.client_secret),
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

        let jwks_uri = {
            let cfg = prov.config.read().await;
            cfg.jwks_uri.as_deref().map(|s| s.to_string())
        };
        // If discovery failed at startup (IDP not yet ready), retry now — the IDP
        // is likely available by the time the first login attempt arrives.
        let jwks_uri = match jwks_uri {
            Some(uri) => uri,
            None => {
                if let Err(e) = self.discover(&prov).await {
                    return Err(format!(
                        "no JWKS URI for provider {} (discovery retry: {e})",
                        prov.provider_cfg.name
                    ));
                }
                let cfg = prov.config.read().await;
                cfg.jwks_uri
                    .as_deref()
                    .ok_or_else(|| {
                        format!(
                            "no JWKS URI for provider {} after discovery retry",
                            prov.provider_cfg.name
                        )
                    })?
                    .to_string()
            }
        };

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
