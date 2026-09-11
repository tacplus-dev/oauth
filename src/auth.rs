use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{info, warn};

use oauth_model::s2sm::internal::grpc::servers::services::oauth::auth::AuthHandler;
use oauth_model::s2sm::ServiceManager;
use oauth_model::types::sys::tokenrequest::tokenrequest::{AuthBrokerKind, MintUserTokenRequest};
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
    state: RwLock<Option<AuthState>>,
}

/// Initialized state — created on first config delivery.
struct AuthState {
    oidc_client: OidcClient,
    state_codec: StateCodec,
    config: Config,
}

impl AuthImpl {
    pub fn new(sm: Arc<ServiceManager>, broker: &BrokerStreamBidiHandle) -> Self {
        Self {
            sm,
            broker: broker.clone(),
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
/// external IDP token to avoid collision with Schematic claims.
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
/// values without colliding with Schematic's own standard claims.
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

/// True when the token's audience contains the expected client_id.
///
/// `aud` is either a string or an array of strings in the JWT spec. The typed
/// payload models it as a single string, so the array shape is read from the
/// custom claims — an IdP that sends an array must not silently fail open.
fn audience_matches(claims: &HashMap<String, serde_json::Value>, expected: &str) -> bool {
    match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == expected,
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .any(|v| v.as_str().map(|s| s == expected).unwrap_or(false)),
        _ => false,
    }
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

/// Verify an IdP id_token and return its claims.
///
/// The chassis token library checks the signature against the JWKS key named by
/// the token's `kid`, plus alg, `exp` and `nbf`. On top of that the token is
/// bound to the provider whose code was just exchanged: a signature check alone
/// would accept a validly-signed token from one configured IdP for another
/// provider_index, since nothing else in this flow ties the two together.
///
/// Every failure path rejects. Claims are read only once all checks have passed.
fn verify_id_token(
    id_token_str: &str,
    jwks: &[crate::oidc::JwkEntry],
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<HashMap<String, serde_json::Value>, tonic::Status> {
    // Find the signing key by kid. FAIL CLOSED when there is no match: an
    // unmatched kid means we cannot verify, and "cannot verify" is not "accept".
    let kid = jwt_kid(id_token_str).ok_or_else(|| {
        tonic::Status::unauthenticated("IDP id_token has no kid; cannot select a verification key")
    })?;
    let matching_key = jwks
        .iter()
        .find(|j| j.kid.as_deref() == Some(kid.as_str()))
        .ok_or_else(|| {
            warn!(kid = %kid, "no IDP JWKS key matches the id_token kid");
            tonic::Status::unauthenticated("no IDP signing key matches the id_token kid")
        })?;

    let parsed_jwk: jwk::jwk::Jwk =
        serde_json::from_value(matching_key.to_json_value()).map_err(|e| {
            tonic::Status::unauthenticated(format!("IDP JWKS entry is not a usable JWK: {e}"))
        })?;
    let verifying_key = jwk::ImmutableJwk::new(parsed_jwk).map_err(|e| {
        tonic::Status::unauthenticated(format!("IDP JWKS key could not be parsed: {e}"))
    })?;
    let id_token = token::Token::parse(id_token_str).map_err(|e| {
        tonic::Status::unauthenticated(format!("IDP id_token is not a well-formed JWT: {e}"))
    })?;
    id_token.verify(&verifying_key).map_err(|e| {
        warn!(error = %e, "IDP id_token verification failed");
        tonic::Status::unauthenticated("IDP id_token failed verification")
    })?;

    let token_issuer = id_token.issuer().unwrap_or_default();
    if token_issuer.trim_end_matches('/') != expected_issuer {
        warn!(expected = %expected_issuer, got = %token_issuer, "IDP id_token issuer mismatch");
        return Err(tonic::Status::unauthenticated("IDP id_token issuer mismatch"));
    }

    let id_claims = parse_jwt_payload(id_token_str)
        .map_err(|e| tonic::Status::unauthenticated(format!("failed to parse IDP ID token: {e}")))?;

    if !audience_matches(&id_claims, expected_audience) {
        warn!(expected = %expected_audience, "IDP id_token audience mismatch");
        return Err(tonic::Status::unauthenticated("IDP id_token audience mismatch"));
    }

    Ok(id_claims)
}

/// Extract `exp` from a token's payload and compute remaining seconds.
fn expires_in_from_token(token_proto: &oauth_model::types::sys::token::token::Token, now: i64) -> i64 {
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

/// Build the kernel MintUserToken request for an IdP-brokered login.
///
/// `broker_kind` is set explicitly: kernel refuses the mint unless the request's
/// kind appears in the resolved Delegate's `auth_broker_kinds`, and the
/// `Default` zero value is `AUTH_BROKER_KIND_UNSPECIFIED`, which never matches.
fn idp_mint_request(
    subject: &str,
    claims: prost_wkt_types::Struct,
    trace_id: &str,
) -> MintUserTokenRequest {
    MintUserTokenRequest {
        subject: subject.to_string(),
        claims: Some(claims),
        broker_kind: AuthBrokerKind::Idp as i32,
        // Propagate trace_id so kernel and opa appear in the trace.
        trace_id: trace_id.to_string(),
        ..Default::default()
    }
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

    async fn mint_callback_tokens(
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

        // 3. Verify the IDP id_token: signature against the IDP's JWKS, plus
        // exp/nbf, and bind it to the provider whose code we just exchanged.
        let jwks = state
            .oidc_client
            .fetch_jwks(payload.provider_index)
            .await
            .map_err(|e| tonic::Status::internal(format!("failed to fetch IDP JWKS: {e}")))?;
        let (expected_issuer, expected_audience) = state
            .oidc_client
            .expected_claims(payload.provider_index)
            .map_err(|e| tonic::Status::internal(format!("provider lookup failed: {e}")))?;

        // 4. Claims come from the verified token only — a rejection here never
        // reaches MintUserToken.
        let id_claims =
            verify_id_token(id_token_str, &jwks, &expected_issuer, &expected_audience)?;

        // The principal is the raw IDP `sub`, as-is — never the email, which is
        // reassignable and would make an email change into cross-user row
        // inheritance under the store model. No issuer prefix: one human must be
        // one principal. With no usable `sub` there is no identity to mint for.
        let subject = id_claims
            .get("sub")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                tonic::Status::unauthenticated("IDP id_token carries no usable sub claim")
            })?
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
        // so we re-inject the resolved subject (the IDP sub) as "sub".
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
            .mint_user_token(idp_mint_request(&subject, claims.clone(), &req.trace_id))
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

    async fn revoke_session(
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

    async fn broker_cli_auth(
        &self,
        caller: Option<&servicemanager::auth::Caller>,
        req: CompleteCliAuthRequest,
    ) -> Result<CompleteCliAuthResponse, tonic::Status> {
        let caller = caller.ok_or_else(|| {
            tonic::Status::unauthenticated("BrokerCliAuth requires authentication")
        })?;
        let token = caller.token();
        // Same rule as the callback path: no usable subject means no identity to
        // broker, not a shared "unknown" principal.
        let subject = token
            .subject()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                tonic::Status::unauthenticated("caller token carries no usable subject")
            })?
            .to_string();

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

#[cfg(test)]
mod idp_token_verification_tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    const TEST_KID: &str = "oauth-test-key";
    const TEST_ISSUER: &str = "https://idp.example.com/realms/schematic";
    const TEST_AUDIENCE: &str = "schematic";

    /// Fixture P-256 keypair. Test-only, never used outside these tests — it
    /// stands in for the IdP's signing key so the crypto path runs for real
    /// instead of being mocked out.
    const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7k1HsdAkjUtBG428\n\
QH39rQVnir+rMuH2d6biVXBV2ZShRANCAAQOxMIoQW+QyI3WkD4Er9S43V/BK+F+\n\
vtvE2Lrd3RM3DB/PzXNv36i967AX9G2Z+iS938JmBiFHZGwVnizguCe9\n\
-----END PRIVATE KEY-----\n";

    const TEST_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDsTCKEFvkMiN1pA+BK/UuN1fwSvh\n\
fr7bxNi63d0TNwwfz81zb9+oveuwF/Rtmfokvd/CZgYhR2RsFZ4s4LgnvQ==\n\
-----END PUBLIC KEY-----\n";

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn b64_pem(pem: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pem.as_bytes())
    }

    fn signing_key() -> key::keys::ImmutableKey {
        key::keys::ImmutableKey::from_pem(TEST_KID.to_string(), &b64_pem(TEST_PRIVATE_PEM)).unwrap()
    }

    /// The JWKS the "IdP" publishes — the fixture key's public half, converted
    /// through the same chassis path a real IdP's key travels.
    fn test_jwks() -> Vec<crate::oidc::JwkEntry> {
        let public =
            key::keys::ImmutablePublicKey::from_pem(TEST_KID.to_string(), &b64_pem(TEST_PUBLIC_PEM))
                .unwrap();
        let key_jwk = jwk::jwk::key_to_jwk(&public).unwrap();
        vec![serde_json::from_value(serde_json::to_value(&key_jwk).unwrap()).unwrap()]
    }

    /// Mint an id_token signed by the fixture key, as the IdP would.
    fn signed_id_token(iss: &str, aud: &str, exp: i64, nbf: Option<i64>) -> String {
        let mut t = token::Token::new();
        t.set_issuer(iss).unwrap();
        t.set_audience(aud).unwrap();
        t.set_subject("subject-opaque-id").unwrap();
        t.set_expiration(exp).unwrap();
        t.set_custom_field("email", json!("user@example.com")).unwrap();
        if let Some(nbf) = nbf {
            t.set_custom_field("nbf", json!(nbf)).unwrap();
        }
        t.sign(&signing_key()).unwrap();
        t.base64().unwrap().to_string()
    }

    fn verify(token: &str) -> Result<HashMap<String, serde_json::Value>, tonic::Status> {
        verify_id_token(token, &test_jwks(), TEST_ISSUER, TEST_AUDIENCE)
    }

    /// The real login path must still work: a correctly-signed token from the
    /// configured issuer, for the configured client_id, verifies and yields its
    /// claims.
    #[test]
    fn correctly_signed_matching_token_is_accepted() {
        let tok = signed_id_token(TEST_ISSUER, TEST_AUDIENCE, now() + 3600, None);
        let claims = verify(&tok).expect("a genuine id_token must be accepted");
        assert_eq!(claims["email"], json!("user@example.com"));
        assert_eq!(claims["sub"], json!("subject-opaque-id"));

        // A trailing slash on the configured issuer is normalized, not a reject.
        let with_slash = signed_id_token(
            &format!("{TEST_ISSUER}/"),
            TEST_AUDIENCE,
            now() + 3600,
            None,
        );
        assert!(verify(&with_slash).is_ok());
    }

    /// A token whose payload was altered after signing must fail. This is the
    /// case the old code could not detect at all: the JWKS key was located by
    /// kid and dropped, and claims came from a bare base64 decode.
    #[test]
    fn tampered_payload_is_rejected() {
        let tok = signed_id_token(TEST_ISSUER, TEST_AUDIENCE, now() + 3600, None);
        let parts: Vec<&str> = tok.split('.').collect();

        let mut claims = parse_jwt_payload(&tok).unwrap();
        claims.insert("email".to_string(), json!("attacker@evil.example"));
        let forged_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);

        let err = verify(&forged).expect_err("altered claims must not verify");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    /// An unsigned token (alg=none style: valid structure, empty signature) must
    /// be rejected, not read for its claims.
    #[test]
    fn unsigned_and_malformed_tokens_are_rejected() {
        let tok = signed_id_token(TEST_ISSUER, TEST_AUDIENCE, now() + 3600, None);
        let parts: Vec<&str> = tok.split('.').collect();

        let unsigned = format!("{}.{}.", parts[0], parts[1]);
        assert_eq!(
            verify(&unsigned).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );

        // Not a JWT at all.
        assert_eq!(
            verify("not-a-jwt").unwrap_err().code(),
            tonic::Code::Unauthenticated
        );

        // Signed by a key the JWKS does not contain — no kid match means we
        // cannot verify, and "cannot verify" is not "accept".
        let other_key = key::keys::generate_ec_p256_key().unwrap();
        let mut t = token::Token::new();
        t.set_issuer(TEST_ISSUER).unwrap();
        t.set_audience(TEST_AUDIENCE).unwrap();
        t.set_expiration(now() + 3600).unwrap();
        t.sign(&other_key).unwrap();
        let foreign = t.base64().unwrap().to_string();
        assert_eq!(
            verify(&foreign).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }

    /// A perfectly-signed token from a DIFFERENT issuer must not be accepted for
    /// this provider. Nothing else in the callback flow binds the token to the
    /// provider whose code was exchanged.
    #[test]
    fn wrong_issuer_is_rejected() {
        let tok = signed_id_token(
            "https://other-idp.example.com/realms/schematic",
            TEST_AUDIENCE,
            now() + 3600,
            None,
        );
        let err = verify(&tok).expect_err("issuer mismatch must reject");
        assert!(
            err.message().contains("issuer mismatch"),
            "unexpected error: {}",
            err.message()
        );
    }

    /// Likewise for a token minted for a different client_id.
    #[test]
    fn wrong_audience_is_rejected() {
        let tok = signed_id_token(TEST_ISSUER, "some-other-client", now() + 3600, None);
        let err = verify(&tok).expect_err("audience mismatch must reject");
        assert!(
            err.message().contains("audience mismatch"),
            "unexpected error: {}",
            err.message()
        );
    }

    /// Expiry and not-before are enforced (the chassis allows 60s of clock skew,
    /// so these are well outside it).
    #[test]
    fn expired_and_not_yet_valid_tokens_are_rejected() {
        let expired = signed_id_token(TEST_ISSUER, TEST_AUDIENCE, now() - 3600, None);
        assert_eq!(
            verify(&expired).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );

        let not_yet = signed_id_token(
            TEST_ISSUER,
            TEST_AUDIENCE,
            now() + 7200,
            Some(now() + 3600),
        );
        assert_eq!(
            verify(&not_yet).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }

    /// The audience check must accept BOTH JWT shapes and reject everything
    /// else, including a missing claim.
    ///
    /// This binding is what stops a validly-signed token from one configured
    /// IdP being accepted for another provider_index. Before this work the
    /// callback verified nothing at all: the JWKS key was located by kid and
    /// then dropped on the floor (`let _matching_key`), and the subject handed
    /// to kernel's MintUserToken came from a bare base64 decode.
    #[test]
    fn audience_must_match_and_handles_both_jwt_shapes() {
        let string_aud: HashMap<String, serde_json::Value> =
            serde_json::from_value(json!({"aud": "schematic"})).unwrap();
        assert!(audience_matches(&string_aud, "schematic"));
        assert!(!audience_matches(&string_aud, "other-client"));

        // The spec allows an array; the typed payload models aud as a single
        // string, so an array must not silently fail open.
        let array_aud: HashMap<String, serde_json::Value> =
            serde_json::from_value(json!({"aud": ["other", "schematic"]})).unwrap();
        assert!(audience_matches(&array_aud, "schematic"));
        assert!(!audience_matches(&array_aud, "not-present"));

        // Absent or wrongly-typed audience is a rejection, never a pass.
        let no_aud: HashMap<String, serde_json::Value> =
            serde_json::from_value(json!({"sub": "someone"})).unwrap();
        assert!(!audience_matches(&no_aud, "schematic"));
        let numeric_aud: HashMap<String, serde_json::Value> =
            serde_json::from_value(json!({"aud": 42})).unwrap();
        assert!(!audience_matches(&numeric_aud, "schematic"));
    }

    /// A JWKS entry must round-trip back into a JWK the chassis can parse.
    ///
    /// JwkEntry lifts kid/kty/alg into typed fields and flattens the rest, so
    /// the object has to be reassembled before verification. If this drops a
    /// field the key fails to parse and the callback fails CLOSED — but it
    /// would fail closed for every login, so it is worth pinning.
    #[test]
    fn jwks_entry_round_trips_into_a_parsable_jwk() {
        let entry: crate::oidc::JwkEntry = serde_json::from_value(json!({
            "kid": "test-key-1",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM",
            "e": "AQAB"
        }))
        .unwrap();

        let value = entry.to_json_value();
        assert_eq!(value["kid"], "test-key-1");
        assert_eq!(value["kty"], "RSA");
        assert_eq!(value["alg"], "RS256");
        // The flattened remainder must survive too — without n/e there is no key.
        assert_eq!(value["e"], "AQAB");
        assert!(value["n"].as_str().is_some());
    }
}

#[cfg(test)]
mod live_idp_verification {
    use super::*;

    /// Runs a REAL id_token and the REAL JWKS from a live IdP through
    /// `verify_id_token` — the same function the callback calls — and proves a
    /// tampered copy is rejected.
    ///
    /// The fixture-key tests above prove the logic; this proves it against an
    /// actual IdP's RSA keys and claim shapes. Ignored by default because it
    /// needs a live IdP. Run with:
    ///   OIDC_TEST_TOKEN=$(cat idtok.txt) OIDC_TEST_JWKS=$(cat jwks.json) \
    ///   OIDC_TEST_ISS=<issuer> OIDC_TEST_AUD=<client_id> \
    ///   cargo test live_idp -- --ignored --nocapture
    #[test]
    #[ignore]
    fn real_idp_token_verifies_and_tampering_is_rejected() {
        let token_str = std::env::var("OIDC_TEST_TOKEN").expect("OIDC_TEST_TOKEN");
        let jwks_raw = std::env::var("OIDC_TEST_JWKS").expect("OIDC_TEST_JWKS");
        let issuer = std::env::var("OIDC_TEST_ISS").expect("OIDC_TEST_ISS");
        let audience = std::env::var("OIDC_TEST_AUD").expect("OIDC_TEST_AUD");
        let token_str = token_str.trim();

        let jwks: serde_json::Value = serde_json::from_str(&jwks_raw).unwrap();
        let keys: Vec<crate::oidc::JwkEntry> =
            serde_json::from_value(jwks["keys"].clone()).unwrap();

        let claims = verify_id_token(token_str, &keys, &issuer, &audience)
            .expect("a genuine IdP id_token must be accepted");
        println!(
            "live IdP token accepted; sub={:?}",
            claims.get("sub").and_then(|v| v.as_str())
        );

        // Same signature, altered claims — the case the old code could not
        // detect at all, since it read claims from a bare base64 decode.
        use base64::Engine;
        let parts: Vec<&str> = token_str.split('.').collect();
        let mut evil_claims = claims.clone();
        evil_claims.insert(
            "sub".to_string(),
            serde_json::Value::String("attacker".to_string()),
        );
        let evil_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&evil_claims).unwrap());
        let forged = format!("{}.{}.{}", parts[0], evil_payload, parts[2]);
        verify_id_token(&forged, &keys, &issuer, &audience)
            .expect_err("a token with altered claims MUST be rejected");

        // A live token is still bound to its provider: the real issuer's token
        // must not be accepted for a different configured provider.
        verify_id_token(token_str, &keys, "https://other-idp.example.com", &audience)
            .expect_err("issuer binding must reject a token from another provider");
        verify_id_token(token_str, &keys, &issuer, "some-other-client")
            .expect_err("audience binding must reject a token for another client_id");

        println!("live IdP: tampering, wrong issuer and wrong audience all rejected");
    }
}

#[cfg(test)]
mod broker_kind_tests {
    use super::*;

    /// The request the OAuth callback hands to kernel must name the IdP broker
    /// kind. Kernel matches `broker_kind` against the resolved Delegate's
    /// `auth_broker_kinds` and refuses the mint on a mismatch, so leaving the
    /// field at its `Default` zero value refuses every real IdP login.
    #[test]
    fn the_mint_request_names_the_idp_broker_kind() {
        let req = idp_mint_request(
            "subject-opaque-id",
            prost_wkt_types::Struct {
                fields: HashMap::new(),
            },
            "trace-1",
        );

        assert_eq!(
            AuthBrokerKind::try_from(req.broker_kind),
            Ok(AuthBrokerKind::Idp)
        );
        assert_eq!(
            AuthBrokerKind::Idp.as_str_name(),
            "AUTH_BROKER_KIND_IDP"
        );
        assert_ne!(req.broker_kind, AuthBrokerKind::Unspecified as i32);
    }
}
