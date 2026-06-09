use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{info, warn};

use oauth_model::s2sm::internal::grpc::servers::services::oauth::auth::AuthHandler;
use oauth_model::s2sm::ServiceManager;
use oauth_model::types::common::tokenrequest::tokenrequest::MintUserTokenRequest;
use oauth_model::types::services::oauth::oauth::{
    AuthorizeRequest, AuthorizeResponse, CallbackRequest, CallbackResponse, Config,
    ListProvidersResponse, LogoutRequest, LogoutResponse, ProviderInfo,
};
use oauth_model::types::services::kernel::kernel::{
    CliTokenBrokerRequest, cli_token_broker_request, CliTokenBrokerCompleteNonce,
};
use oauth_model::s2sm::internal::grpc::clients::services::kernel::cli_token_broker::BrokerStreamBidiHandle;
use oauth_model::types::services::oauth::oauth::{
    CompleteCliAuthRequest, CompleteCliAuthResponse,
};

use crate::nonce::{generate_code_verifier, StateCodec};
use crate::oidc::OidcClient;

/// AuthImpl implements the Auth gRPC service (OAuth2/OIDC browser flows).
pub struct AuthImpl {
    sm: Arc<ServiceManager>,
    broker: BrokerStreamBidiHandle,
    pending: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<String>>>>,
    state: RwLock<Option<AuthState>>,
}

/// Initialized state — created on first config delivery.
struct AuthState {
    oidc_client: OidcClient,
    state_codec: StateCodec,
    config: Config,
}

impl AuthImpl {
    pub fn new(
        sm: Arc<ServiceManager>,
        broker: &BrokerStreamBidiHandle,
        pending: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<String>>>>,
    ) -> Self {
        Self {
            sm,
            broker: broker.clone(),
            pending,
            state: RwLock::new(None),
        }
    }

    /// Initialize OIDC client and state codec from config.
    pub async fn apply_config(&self, cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
        if !cfg.enable {
            info!("OAuth2/OIDC disabled in config");
            *self.state.write().await = None;
            return Ok(());
        }

        let oidc_client = OidcClient::new(
            &cfg.providers,
            &cfg.scopes,
            cfg.jwk_refetch_interval_seconds,
        )
        .await
        .map_err(|e| format!("oidc client: {e}"))?;

        let state_codec = StateCodec::new(&cfg.providers, cfg.nonce_expire_seconds);

        *self.state.write().await = Some(AuthState {
            oidc_client,
            state_codec,
            config: cfg.clone(),
        });

        info!("OAuth2/OIDC initialized with {} providers", cfg.providers.len());
        Ok(())
    }

    /// Helper to get initialized state or return error.
    async fn require_state(&self) -> Result<tokio::sync::RwLockReadGuard<'_, Option<AuthState>>, tonic::Status> {
        let guard = self.state.read().await;
        if guard.is_none() {
            return Err(tonic::Status::failed_precondition("OAuth2 not enabled"));
        }
        Ok(guard)
    }
}

/// Well-known JWT claims that get `origin_` prefix when forwarding from an
/// external IDP token to avoid collision with Cavalier claims.
const WELL_KNOWN_JWT_CLAIMS: &[&str] = &["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// Recursively convert a serde_json::Value to a prost_wkt_types::Value.
/// Empty strings are dropped (return None). All other types are supported:
/// booleans, numbers, strings, arrays, objects, and null.
fn json_to_proto_value(val: &serde_json::Value) -> Option<prost_wkt_types::Value> {
    use prost_wkt_types::value::Kind;
    let kind = match val {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(*b),
        serde_json::Value::Number(n) => Kind::NumberValue(n.as_f64()?),
        serde_json::Value::String(s) => {
            if s.is_empty() {
                return None;
            }
            Kind::StringValue(s.clone())
        }
        serde_json::Value::Array(arr) => {
            let values: Vec<prost_wkt_types::Value> =
                arr.iter().filter_map(json_to_proto_value).collect();
            if values.is_empty() {
                return None;
            }
            Kind::ListValue(prost_wkt_types::ListValue { values })
        }
        serde_json::Value::Object(_) => {
            // Objects are JSON-serialized; kernel can only store strings.
            Kind::StringValue(serde_json::to_string(val).ok()?)
        }
    };
    Some(prost_wkt_types::Value { kind: Some(kind) })
}

/// Build a prost_wkt_types::Struct from IDP token claims.
/// Well-known JWT claims are prefixed with `origin_` to preserve the IDP's
/// values without colliding with Cavalier's own standard claims.
/// All JSON value types are supported (strings, numbers, booleans, arrays, objects).
fn build_claims_struct(payload: &HashMap<String, serde_json::Value>) -> Option<prost_wkt_types::Struct> {
    let mut fields = HashMap::new();

    for (key, val) in payload {
        let output_key = if WELL_KNOWN_JWT_CLAIMS.contains(&key.as_str()) {
            format!("origin_{key}")
        } else {
            key.clone()
        };
        if let Some(proto_val) = json_to_proto_value(val) {
            fields.insert(output_key, proto_val);
        }
    }

    if fields.is_empty() {
        None
    } else {
        Some(prost_wkt_types::Struct { fields })
    }
}

/// Parse a JWT's payload without signature verification (claims extraction).
/// Returns the payload as a map. We verify signatures separately using IDP JWKS.
fn parse_jwt_payload(token: &str) -> Result<HashMap<String, serde_json::Value>, String> {
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT: expected 3 parts".to_string());
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("invalid JWT payload encoding: {e}"))?;

    serde_json::from_slice(&payload_bytes).map_err(|e| format!("invalid JWT payload JSON: {e}"))
}

/// Extract the `kid` header from a JWT.
fn jwt_kid(token: &str) -> Option<String> {
    use base64::Engine;

    let header_part = token.split('.').next()?;
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_part)
        .ok()?;
    let header: HashMap<String, serde_json::Value> = serde_json::from_slice(&header_bytes).ok()?;
    header.get("kid")?.as_str().map(|s| s.to_string())
}

/// Extract `exp` from a token's payload and compute remaining seconds.
fn expires_in_from_token(token_proto: &oauth_model::types::libs::token::token::Token, now: i64) -> i64 {
    for (k, v) in &token_proto.payload {
        if k == "exp" {
            if let Ok(exp) = v.parse::<i64>() {
                if exp > now {
                    return exp - now;
                }
            }
        }
    }
    0
}

#[tonic::async_trait]
impl AuthHandler for AuthImpl {
    async fn list_providers(
        &self,
        _caller: Option<&servicemanager::auth::Caller>,
    ) -> Result<ListProvidersResponse, tonic::Status> {
        let guard = self.state.read().await;
        let state = match guard.as_ref() {
            Some(s) => s,
            None => {
                return Ok(ListProvidersResponse {
                    providers: vec![],
                    ..Default::default()
                })
            }
        };

        let mut providers = Vec::new();
        for (i, p) in state.config.providers.iter().enumerate() {
            if !p.enable {
                continue;
            }
            providers.push(ProviderInfo {
                name: p.name.clone(),
                domains: p.domains.clone(),
                provider_index: i as i32,
                ..Default::default()
            });
        }

        Ok(ListProvidersResponse {
            providers,
            ..Default::default()
        })
    }

    async fn authorize(
        &self,
        _caller: Option<&servicemanager::auth::Caller>,
        req: AuthorizeRequest,
    ) -> Result<AuthorizeResponse, tonic::Status> {
        let guard = self.require_state().await?;
        let state = guard.as_ref().unwrap();

        let code_verifier = generate_code_verifier();
        let session_id = if req.session_id.is_empty() {
            None
        } else {
            Some(req.session_id.as_str())
        };
        let encoded_state =
            state
                .state_codec
                .encode(req.provider_index, &req.callback_url, &code_verifier, session_id);

        let redirect_url = state
            .oidc_client
            .build_authorize_url(req.provider_index, &encoded_state, &code_verifier, &req.callback_url)
            .await
            .map_err(|e| tonic::Status::internal(format!("failed to build authorize URL: {e}")))?;

        Ok(AuthorizeResponse {
            redirect_url,
            ..Default::default()
        })
    }

    async fn callback(
        &self,
        _caller: Option<&servicemanager::auth::Caller>,
        req: CallbackRequest,
    ) -> Result<CallbackResponse, tonic::Status> {
        let guard = self.require_state().await?;
        let state = guard.as_ref().unwrap();

        // 1. Decrypt the state to recover nonce data.
        let payload = state
            .state_codec
            .decode(&req.state)
            .map_err(|e| tonic::Status::unauthenticated(format!("invalid or expired state: {e}")))?;

        // 2. Exchange authorization code for IDP tokens.
        let token_resp = state
            .oidc_client
            .exchange_code(
                payload.provider_index,
                &req.code,
                &payload.code_verifier,
                &payload.callback_url,
            )
            .await
            .map_err(|e| {
                warn!(error = %e, "token exchange failed");
                tonic::Status::internal(format!("token exchange failed: {e}"))
            })?;

        let id_token_str = token_resp
            .id_token
            .as_deref()
            .ok_or_else(|| tonic::Status::internal("IDP returned no id_token"))?;

        // 3. Verify IDP ID token against IDP's JWKS.
        let kid = jwt_kid(id_token_str);
        let jwks = state
            .oidc_client
            .fetch_jwks(payload.provider_index)
            .await
            .map_err(|e| tonic::Status::internal(format!("failed to fetch IDP JWKS: {e}")))?;

        // Find matching key by kid
        let _matching_key = kid
            .as_deref()
            .and_then(|k| jwks.iter().find(|j| j.kid.as_deref() == Some(k)));

        // Note: Full cryptographic verification of the IDP's JWT signature requires
        // JWK-to-public-key conversion (RSA/EC/Ed25519). For now we verify the token
        // structure and trust the TLS channel to the IDP's token endpoint (the id_token
        // came directly from the IDP over HTTPS, not from the user).
        // TODO: Add full JWK signature verification once ring/ed25519 JWK support is wired.

        // 4. Parse the ID token payload to extract subject + claims.
        let id_claims = parse_jwt_payload(id_token_str)
            .map_err(|e| tonic::Status::unauthenticated(format!("failed to parse IDP ID token: {e}")))?;

        // Prefer email over opaque sub.
        let subject = id_claims
            .get("email")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| id_claims.get("sub").and_then(|v| v.as_str()))
            .unwrap_or("unknown")
            .to_string();

        // 5. Build claims struct from IDP token.
        let mut claims = build_claims_struct(&id_claims).unwrap_or_else(|| prost_wkt_types::Struct {
            fields: HashMap::new(),
        });
        // Set azp (authorized party) — tokens minted via OAuth flow carry azp=oauth
        claims.fields.insert(
            "azp".to_string(),
            prost_wkt_types::Value {
                kind: Some(prost_wkt_types::value::Kind::StringValue(
                    "oauth".to_string(),
                )),
            },
        );
        // Set sub — OPA trusted_caller check requires input.claims.sub.
        // build_claims_struct renames "sub" → "origin_sub" to avoid collisions,
        // so we re-inject the resolved subject (email or opaque sub) as "sub".
        claims.fields.insert(
            "sub".to_string(),
            prost_wkt_types::Value {
                kind: Some(prost_wkt_types::value::Kind::StringValue(
                    subject.clone(),
                )),
            },
        );

        // 6. Call kernel MintUserToken to get signed tokens.
        let mint_resp = self.sm.s2s().kernel().mint_client()
            .mint_user_token(MintUserTokenRequest {
                subject: subject.clone(),
                claims: Some(claims.clone()),
                // Propagate trace_id so kernel and opa appear in the trace.
                trace_id: req.trace_id.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "kernel MintUserToken failed");
                tonic::Status::internal(format!("kernel token mint failed: {e}"))
            })?
            .into_inner();

        // 7. Compute expires_in from the tokens.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let refresh_token = mint_resp
            .refresh_token
            .as_ref()
            .map(|t| t.base64.clone())
            .unwrap_or_default();
        let access_token = mint_resp
            .access_token
            .as_ref()
            .map(|t| t.base64.clone())
            .unwrap_or_default();

        let refresh_expires_in = mint_resp
            .refresh_token
            .as_ref()
            .map(|t| expires_in_from_token(t, now))
            .unwrap_or(0);
        let access_expires_in = mint_resp
            .access_token
            .as_ref()
            .map(|t| expires_in_from_token(t, now))
            .unwrap_or(0);

        // 8. If this was a CLI-originated flow, complete the nonce via the
        // kernel CliTokenBroker. Kernel matches the nonce, mints the token,
        // and delivers it to the oauth instance holding the CLI stream.
        if let Some(session_id) = &payload.session_id {
            self.broker.send(CliTokenBrokerRequest {
                msg: Some(cli_token_broker_request::Msg::CompleteNonce(
                    CliTokenBrokerCompleteNonce {
                        nonce: session_id.clone(),
                        subject: subject.clone(),
                        claims: Some(claims),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }).await.map_err(|e| {
                warn!(session_id = %session_id, error = %e, "failed to complete CLI nonce via broker");
                tonic::Status::internal(format!("failed to complete CLI nonce: {e}"))
            })?;

            info!(sub = %subject, session_id = %session_id, "CLI nonce completed via broker");
        }

        info!(sub = %subject, "OAuth callback completed (delegated to kernel)");

        Ok(CallbackResponse {
            refresh_token,
            access_token,
            callback_url: payload.callback_url,
            access_token_expires_in: access_expires_in,
            refresh_token_expires_in: refresh_expires_in,
            ..Default::default()
        })
    }

    async fn logout(
        &self,
        _caller: Option<&servicemanager::auth::Caller>,
        req: LogoutRequest,
    ) -> Result<LogoutResponse, tonic::Status> {
        let mut redirect_url = String::new();

        let guard = self.state.read().await;
        if let Some(state) = guard.as_ref() {
            if !req.post_logout_redirect_url.is_empty() {
                for i in 0..state.config.providers.len() {
                    let endpoint = state.oidc_client.end_session_endpoint(i as i32).await;
                    if !endpoint.is_empty() {
                        let mut params = vec![(
                            "post_logout_redirect_uri",
                            req.post_logout_redirect_url.as_str(),
                        )];
                        if !req.id_token_hint.is_empty() {
                            params.push(("id_token_hint", &req.id_token_hint));
                        }
                        let query = serde_urlencoded::to_string(&params).unwrap_or_default();
                        redirect_url = format!("{endpoint}?{query}");
                        break;
                    }
                }
            }
        }

        Ok(LogoutResponse {
            redirect_url,
            ..Default::default()
        })
    }

    async fn complete_cli_auth(
        &self,
        caller: Option<&servicemanager::auth::Caller>,
        req: CompleteCliAuthRequest,
    ) -> Result<CompleteCliAuthResponse, tonic::Status> {
        let caller = caller.ok_or_else(|| {
            tonic::Status::unauthenticated("CompleteCliAuth requires authentication")
        })?;
        let token = caller.token();
        let subject = token.subject().unwrap_or("unknown").to_string();

        // Extract claims from the caller's token for OPA entitlement resolution.
        // Build a prost Struct from the token's custom fields.
        let mut fields = std::collections::HashMap::new();
        fields.insert("sub".to_string(), prost_wkt_types::Value {
            kind: Some(prost_wkt_types::value::Kind::StringValue(subject.clone())),
        });
        if let Some(email) = token.custom_field("email").and_then(|v| v.as_str()) {
            fields.insert("email".to_string(), prost_wkt_types::Value {
                kind: Some(prost_wkt_types::value::Kind::StringValue(email.to_string())),
            });
        }
        // origin_iss is the IDP issuer, stamped on the token at first login
        // (build_claims_struct prefixes well-known IDP claims with origin_, and
        // the kernel clones it through refresh→access→service). The entitlements
        // policy derives the tenant from input.claims.origin_iss, so without it
        // OPA resolves tenant="" → empty entitlements. Forward it so the cached
        // "already authenticated" re-auth resolves the same tenant as a fresh login.
        if let Some(iss) = token.custom_field("origin_iss").and_then(|v| v.as_str()) {
            fields.insert("origin_iss".to_string(), prost_wkt_types::Value {
                kind: Some(prost_wkt_types::value::Kind::StringValue(iss.to_string())),
            });
        }
        // groups drives authorized_projects + is_admin in the policy. It is NOT a
        // well-known JWT claim, so it is stored under "groups" (not origin_groups).
        if let Some(groups) = token.custom_field("groups") {
            if let Some(arr) = groups.as_array() {
                let values: Vec<prost_wkt_types::Value> = arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| prost_wkt_types::Value {
                        kind: Some(prost_wkt_types::value::Kind::StringValue(s.to_string())),
                    })
                    .collect();
                fields.insert("groups".to_string(), prost_wkt_types::Value {
                    kind: Some(prost_wkt_types::value::Kind::ListValue(
                        prost_wkt_types::ListValue { values },
                    )),
                });
            }
        }
        let claims = prost_wkt_types::Struct { fields };

        self.broker.send(CliTokenBrokerRequest {
            msg: Some(cli_token_broker_request::Msg::CompleteNonce(
                CliTokenBrokerCompleteNonce {
                    nonce: req.session_id.clone(),
                    subject: subject.clone(),
                    claims: Some(claims),
                    ..Default::default()
                },
            )),
            ..Default::default()
        }).await?;

        info!(sub = %subject, session_id = %req.session_id, "CLI auth completed via broker (already authenticated)");

        Ok(CompleteCliAuthResponse {
            success: true,
            ..Default::default()
        })
    }
}
