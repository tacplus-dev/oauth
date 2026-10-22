use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{oneshot, RwLock};
use tracing::{info, warn};

use oauth_model::s2sm::internal::grpc::servers::services::oauth::auth::AuthHandler;
use oauth_model::s2sm::ServiceManager;
use oauth_model::types::sys::token::JwtPayloadType;
use oauth_model::types::sys::tokenrequest::tokenrequest::{AuthBrokerKind, MintUserTokenRequest};
use oauth_model::types::services::oauth::helpers::secrets_from_env_var;
use oauth_model::types::services::oauth::oauth::{
    AuthorizeRequest, AuthorizeResponse, CallbackRequest, CallbackResponse,
    ClassifySignInEmailRequest, ClassifySignInEmailResponse, Config,
    FormPostCallbackRequest, FormPostCallbackResponse, ListProvidersResponse, LogoutRequest,
    LogoutResponse, ProviderConfig, ProviderInfo,
};
use oauth_model::types::services::kernel::kernel::{
    CliTokenBrokerRequest, cli_token_broker_request, CliTokenBrokerCompleteNonce,
};
use oauth_model::s2sm::internal::grpc::clients::services::kernel::cli_token_broker::BrokerStreamBidiHandle;
use oauth_model::types::services::oauth::oauth::{
    CompleteCliAuthRequest, CompleteCliAuthResponse,
};

use crate::nonce::{generate_code_verifier, StateCodec, StatePayload};
use crate::oidc::OidcClient;
use crate::signin_email::{DnsResolver, EmailRateLimiter, GlobalRateLimiter};

/// A `session_id` is completable only where its CLI session is pending.
///
/// `broker_cli_auth` takes the `session_id` verbatim from the request, so
/// without this check any authenticated caller who learns a nonce can complete
/// someone else's CLI login and have that login's token delivered to the CLI
/// that is waiting on it. `pending` is per-process: this closes the
/// same-instance angle, and the kernel's `REGISTER_NONCE` `putIfAbsent` covers
/// a registration that landed on a different oauth instance.
async fn check_pending_session(
    pending: &RwLock<HashMap<String, oneshot::Sender<String>>>,
    session_id: &str,
) -> Result<(), tonic::Status> {
    if pending.read().await.contains_key(session_id) {
        return Ok(());
    }
    warn!(session_id = %session_id, "BrokerCliAuth for a session_id with no pending CLI session, refusing");
    Err(tonic::Status::not_found(
        "no pending CLI login session for the supplied session_id",
    ))
}

/// AuthImpl implements the Auth gRPC service (OAuth2/OIDC browser flows).
pub struct AuthImpl {
    sm: Arc<ServiceManager>,
    broker: BrokerStreamBidiHandle,
    /// The same map `OauthImpl` registers CLI sessions in — shared, not a copy,
    /// so `broker_cli_auth` can tell a session this instance is actually
    /// holding open from a `session_id` the caller merely knows.
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
    state: RwLock<Option<AuthState>>,
    dns_resolver: Arc<dyn DnsResolver>,
    sign_in_email_limiter: EmailRateLimiter,
    sign_in_global_limiter: GlobalRateLimiter,
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
        pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
        dns_resolver: Arc<dyn DnsResolver>,
    ) -> Self {
        Self {
            sm,
            broker: broker.clone(),
            pending,
            state: RwLock::new(None),
            dns_resolver,
            sign_in_email_limiter: EmailRateLimiter::new(),
            sign_in_global_limiter: GlobalRateLimiter::new(),
        }
    }

    /// Initialize OIDC client and state codec from config.
    pub async fn apply_config(&self, cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
        let state = auth_state(cfg).await?;
        match state {
            None => info!("OAuth2/OIDC disabled in config"),
            Some(_) => info!("OAuth2/OIDC initialized with {} providers", cfg.providers.len()),
        }
        *self.state.write().await = state;
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

/// The flow state a config yields. None while `enable` is off, and every
/// sign-in RPC refuses on None (`require_state`): that is the sign-in, and so
/// sign-up, kill switch (ops/datagate/README.md).
async fn auth_state(cfg: &Config) -> Result<Option<AuthState>, Box<dyn std::error::Error>> {
    if !cfg.enable {
        return Ok(None);
    }

    // Secret inputs come from the pod env (operator SecretEnvVars), never
    // from Config, which every config-holder in the fleet can read.
    let secrets = secrets_from_env_var(&std::env::vars().collect());
    check_provider_credentials(&cfg.providers, &secrets.apple_signin_key_p8)?;

    let oidc_client = OidcClient::new(
        &cfg.providers,
        &cfg.scopes,
        cfg.jwk_refetch_interval_seconds,
        &secrets.apple_signin_key_p8,
    )
    .await
    .map_err(|e| format!("oidc client: {e}"))?;

    let state_codec = StateCodec::new(
        &cfg.providers,
        &secrets.apple_signin_key_p8,
        cfg.nonce_expire_seconds,
    );

    Ok(Some(AuthState {
        oidc_client,
        state_codec,
        config: cfg.clone(),
    }))
}

/// Every enabled provider must be able to authenticate to its token endpoint:
/// a Sign in with Apple provider with the .p8 key from the pod env, any other
/// with a static `client_secret`. `client_secret` is not schema-required (an
/// Apple provider has none), so this is what keeps a provider missing both
/// from loading.
fn check_provider_credentials(
    providers: &[ProviderConfig],
    apple_key_p8: &str,
) -> Result<(), String> {
    for p in providers.iter().filter(|p| p.enable) {
        match &p.apple {
            Some(_) if apple_key_p8.is_empty() => {
                return Err(format!(
                    "provider {} sets apple, but PROTO_SERVICES_OAUTH_SECRETS_APPLE_SIGNIN_KEY_P8 is empty",
                    p.name
                ))
            }
            None if p.client_secret.is_empty() => {
                return Err(format!("provider {} has no client_secret", p.name))
            }
            _ => {}
        }
    }
    Ok(())
}

/// Where the browser goes after a form_post IDP (Apple) POSTs its response.
///
/// The webapp already completes a query-mode login from `?code=&state=` on its
/// own page with MintCallbackTokens, so the POST is turned into exactly that
/// redirect rather than given a second handoff. The state is checked here as it
/// is again in MintCallbackTokens, and re-sealed carrying the first-
/// authorization name, which Apple sends only in this POST. An unusable state
/// sends the browser to "/", never to a URL the request named.
fn form_post_redirect(
    codec: &StateCodec,
    config: &Config,
    req: &FormPostCallbackRequest,
) -> String {
    let mut payload = match codec.decode(&req.state) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "form_post callback without a usable state, redirecting to /");
            return "/".to_string();
        }
    };
    if check_callback_url(config, payload.provider_index, &payload.callback_url).is_err() {
        return "/".to_string();
    }
    // check_callback_url resolved the index, so the provider exists.
    if config.providers[payload.provider_index as usize].apple.is_none() {
        warn!(
            provider_index = payload.provider_index,
            "form_post callback for a provider that does not use form_post, redirecting to /"
        );
        return "/".to_string();
    }

    if req.code.is_empty() {
        info!(error = %req.error, "form_post callback carried no code, returning to the webapp");
        return payload.callback_url;
    }

    if !req.user.is_empty() {
        match crate::apple::parse_user_name(&req.user) {
            Ok((given, family)) => {
                payload.given_name = given;
                payload.family_name = family;
            }
            Err(e) => warn!(error = %e, "ignoring the form_post user field"),
        }
    }

    let query = serde_urlencoded::to_string([
        ("code", req.code.as_str()),
        ("state", codec.seal(&payload).as_str()),
    ])
    .unwrap_or_default();
    let separator = if payload.callback_url.contains('?') { '&' } else { '?' };
    format!("{}{separator}{query}", payload.callback_url)
}

/// Add the first-authorization name a form_post IDP relayed through the state.
///
/// Apple sends the name once and never in the id_token, so this login's mint is
/// the only one that can carry it. A claim the id_token already has is kept.
fn add_first_authorization_name(claims: &mut prost_wkt_types::Struct, payload: &StatePayload) {
    let string_value = |s: &str| prost_wkt_types::Value {
        kind: Some(prost_wkt_types::value::Kind::StringValue(s.to_string())),
    };
    let full_name = [payload.given_name.as_deref(), payload.family_name.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    for (claim, value) in [
        ("given_name", payload.given_name.as_deref().unwrap_or("")),
        ("family_name", payload.family_name.as_deref().unwrap_or("")),
        ("name", full_name.as_str()),
    ] {
        if !value.is_empty() {
            claims
                .fields
                .entry(claim.to_string())
                .or_insert_with(|| string_value(value));
        }
    }
}

/// Stamp the configured issuer of the provider this login came through as
/// `provider_iss`.
///
/// `origin_iss` is the token's own `iss`, which for an Entra multi-tenant
/// provider is per directory (`.../<tid>/v2.0`), so it never equals the
/// configured `.../organizations/v2.0`. A tenant claim matcher names the
/// configured provider issuer, and matches on this claim. Inserted after the
/// IdP claims, so an id_token carrying its own `provider_iss` cannot set it.
fn add_provider_issuer(claims: &mut prost_wkt_types::Struct, provider: &ProviderConfig) {
    claims.fields.insert(
        "provider_iss".to_string(),
        prost_wkt_types::Value {
            kind: Some(prost_wkt_types::value::Kind::StringValue(provider.issuer.clone())),
        },
    );
}

/// Well-known JWT claims that get `origin_` prefix when forwarding from an
/// external IDP token to avoid collision with Schematic claims.
const WELL_KNOWN_JWT_CLAIMS: &[&str] = &["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "nonce"];

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

#[cfg(test)]
mod build_claims_struct_tests {
    use super::*;
    use serde_json::json;

    /// A device/person link (identity §2/§3) proves two IdP logins share a
    /// nonce by comparing the `origin_nonce` claim kernel reads off each
    /// minted token. If `nonce` is not well-known, it passes through
    /// unprefixed and kernel never sees `origin_nonce` — every link request
    /// then fails `UNAUTHENTICATED` for a claim that was never missing on
    /// the IDP side, only mislabeled on the way through oauth.
    #[test]
    fn nonce_claim_is_forwarded_as_origin_nonce() {
        let mut payload = HashMap::new();
        payload.insert("nonce".to_string(), json!("device-key-thumbprint"));
        payload.insert("email".to_string(), json!("user@example.com"));

        let claims = build_claims_struct(&payload).expect("non-empty payload yields a Struct");

        assert!(
            !claims.fields.contains_key("nonce"),
            "nonce must not survive unprefixed"
        );
        let origin_nonce = claims
            .fields
            .get("origin_nonce")
            .expect("nonce must be forwarded as origin_nonce");
        assert_eq!(
            origin_nonce.kind,
            Some(prost_wkt_types::value::Kind::StringValue(
                "device-key-thumbprint".to_string()
            ))
        );
        // A claim that isn't well-known still passes through unprefixed.
        assert!(claims.fields.contains_key("email"));
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

/// True for a GUID in its canonical 8-4-4-4-12 hex form, the only form Entra
/// ID emits a `tid` in. Nothing else may be spliced into an issuer template.
fn is_guid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The issuer a verified token must carry.
///
/// A provider whose issuer is per directory (Entra ID multi-tenant,
/// `https://login.microsoftonline.com/{tid}/v2.0`) is configured with a
/// template; "{tid}" is filled from the token's own `tid` claim, which must be
/// a GUID. The token's `iss` is then compared exactly with the result, so a
/// token from one directory cannot name another. Any other expected issuer is
/// returned unchanged.
fn resolve_expected_issuer(
    expected_issuer: &str,
    claims: &HashMap<String, serde_json::Value>,
) -> Result<String, tonic::Status> {
    if !expected_issuer.contains("{tid}") {
        return Ok(expected_issuer.to_string());
    }
    let tid = claims
        .get("tid")
        .and_then(|v| v.as_str())
        .filter(|t| is_guid(t))
        .ok_or_else(|| {
            warn!(tid = ?claims.get("tid"), "IDP id_token has no GUID tid for the issuer template");
            tonic::Status::unauthenticated("IDP id_token carries no usable tid claim")
        })?;
    Ok(expected_issuer.replace("{tid}", tid))
}

/// Drop `email` unless the provider's `email_verified_claim` is true.
///
/// Policy maps a person to a tenant by `origin_iss` + `email`, and Entra ID
/// sends an `email` it does not vouch for: it is a directory attribute any
/// tenant admin can set. `xms_edov` (email domain owner verified) is the claim
/// that says the address's domain is verified. Only a JSON `true` counts. An
/// empty `email_verified_claim` leaves the claims unchanged. `preferred_username`
/// is never promoted to `email`: Microsoft documents it as mutable and unusable
/// for authorization.
fn drop_unverified_email(claims: &mut HashMap<String, serde_json::Value>, email_verified_claim: &str) {
    if email_verified_claim.is_empty()
        || claims.get(email_verified_claim) == Some(&serde_json::Value::Bool(true))
    {
        return;
    }
    if claims.remove("email").is_some() {
        warn!(claim = %email_verified_claim, "IDP email is not verified, not forwarding it");
    }
}

/// Verify an IdP id_token and return its claims.
///
/// The chassis token library checks the signature against the JWKS key named by
/// the token's `kid`, plus alg, `exp` and `nbf`. On top of that the token is
/// bound to the provider whose code was just exchanged: a signature check alone
/// would accept a validly-signed token from one configured IdP for another
/// provider_index, since nothing else in this flow ties the two together.
///
/// `expected_issuer` may be an issuer template (see `resolve_expected_issuer`).
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

    let id_claims = parse_jwt_payload(id_token_str)
        .map_err(|e| tonic::Status::unauthenticated(format!("failed to parse IDP ID token: {e}")))?;

    let expected_issuer = resolve_expected_issuer(expected_issuer, &id_claims)?;
    let token_issuer = id_token.issuer().unwrap_or_default();
    if token_issuer.trim_end_matches('/') != expected_issuer {
        warn!(expected = %expected_issuer, got = %token_issuer, "IDP id_token issuer mismatch");
        return Err(tonic::Status::unauthenticated("IDP id_token issuer mismatch"));
    }

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

/// Check a caller-supplied `callback_url` against a provider's configured
/// redirect allowlist.
///
/// `Authorize` is unauthenticated and its `callback_url` is handed to the IdP
/// as `redirect_uri`, so an unchecked value delivers the authorization code to
/// whatever host the caller names. Matching is exact and case-sensitive:
///
///   - an entry that does not end in `/` matches only a byte-identical URL;
///   - an entry that ends in `/` also matches any URL beginning with it.
///
/// The trailing slash is what ends the prefix on a path boundary, so a bare
/// `starts_with` cannot be walked past the allowlisted origin or path segment.
/// An empty allowlist matches nothing — no provider config means no redirect.
fn callback_url_allowed(allowed_prefixes: &[String], callback_url: &str) -> bool {
    allowed_prefixes.iter().any(|entry| {
        if entry.ends_with('/') {
            callback_url.starts_with(entry.as_str())
        } else {
            callback_url == entry
        }
    })
}

/// Resolve a provider by the index the caller supplied and reject the request
/// unless its allowlist covers `callback_url`.
fn check_callback_url(
    config: &Config,
    provider_index: i32,
    callback_url: &str,
) -> Result<(), tonic::Status> {
    let provider = usize::try_from(provider_index)
        .ok()
        .and_then(|i| config.providers.get(i))
        .ok_or_else(|| {
            tonic::Status::invalid_argument(format!("unknown provider index {provider_index}"))
        })?;

    if !callback_url_allowed(&provider.allowed_redirect_uri_prefixes, callback_url) {
        warn!(
            provider = %provider.name,
            callback_url = %callback_url,
            "callback_url is not in the provider's redirect allowlist"
        );
        return Err(tonic::Status::invalid_argument(
            "callback_url is not permitted for this provider",
        ));
    }

    Ok(())
}

/// The OPA claims for an "already authenticated" CLI re-auth, read from the
/// caller's Schematic token.
///
/// Kernel copied the login's claims onto the token (every claim that is not a
/// Schematic payload type, and the origin_-prefixed IdP ones), and clones them
/// through refresh→access→service. All of them are handed back, so OPA sees the
/// same claims as on the fresh login (origin_iss, provider_iss, hd, tid,
/// groups, ...) and resolves the same tenant and namespace. Schematic's own
/// claims (iss, namespace, entitlements, azp, typ, ...) are left out, as
/// kernel's claim copy leaves them out; `sub` is the token's subject.
fn reauth_claims(token: &token::Token, subject: &str) -> prost_wkt_types::Struct {
    let mut fields: HashMap<String, prost_wkt_types::Value> = token
        .claims()
        .iter()
        .filter(|(k, _)| {
            k.starts_with("origin_") || (k.as_str() != "typ" && k.parse::<JwtPayloadType>().is_err())
        })
        .filter_map(|(k, v)| Some((k.clone(), json_to_proto_value(v)?)))
        .collect();
    fields.insert(
        "sub".to_string(),
        prost_wkt_types::Value {
            kind: Some(prost_wkt_types::value::Kind::StringValue(subject.to_string())),
        },
    );
    prost_wkt_types::Struct { fields }
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

        // Before anything is encoded or sent: the caller-supplied callback_url
        // becomes the IdP redirect_uri, so it must be one the operator
        // allowlisted for this provider.
        check_callback_url(&state.config, req.provider_index, &req.callback_url)?;

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
            .build_authorize_url(
                req.provider_index,
                &encoded_state,
                &code_verifier,
                &req.callback_url,
                &req.nonce,
                &req.login_hint,
            )
            .await
            .map_err(|e| tonic::Status::internal(format!("failed to build authorize URL: {e}")))?;

        Ok(AuthorizeResponse {
            redirect_url,
            ..Default::default()
        })
    }

    async fn classify_sign_in_email(
        &self,
        _caller: Option<&servicemanager::auth::Caller>,
        req: ClassifySignInEmailRequest,
    ) -> Result<ClassifySignInEmailResponse, tonic::Status> {
        if !self.sign_in_email_limiter.allow(&req.email, Instant::now()) {
            return Err(tonic::Status::resource_exhausted(
                "too many sign-in lookups for this address, try again in a minute",
            ));
        }
        if !self.sign_in_global_limiter.allow(Instant::now()) {
            return Err(tonic::Status::resource_exhausted("too many sign-in lookups, try again shortly"));
        }
        let guard = self.state.read().await;
        let providers = guard.as_ref().map_or(&[][..], |s| s.config.providers.as_slice());
        Ok(crate::signin_email::classify(self.dns_resolver.as_ref(), providers, &req.email).await)
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

        // 2. Re-check the callback_url the state carries. The state is
        // encrypted, so this cannot have been forged, but the redirect_uri sent
        // to the token endpoint gets its own check rather than trusting the
        // decode.
        check_callback_url(&state.config, payload.provider_index, &payload.callback_url)?;

        // 3. Exchange authorization code for IDP tokens.
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

        // 4. Verify the IDP id_token: signature against the IDP's JWKS, plus
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

        // 5. Claims come from the verified token only — a rejection here never
        // reaches MintUserToken.
        let mut id_claims =
            verify_id_token(id_token_str, &jwks, &expected_issuer, &expected_audience)?;
        // check_callback_url resolved the index, so the provider exists.
        drop_unverified_email(
            &mut id_claims,
            &state.config.providers[payload.provider_index as usize].email_verified_claim,
        );

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

        // 6. Build claims struct from IDP token.
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

        // A form_post IDP's first-authorization name, carried in the state.
        add_first_authorization_name(&mut claims, &payload);
        // check_callback_url resolved the index, so the provider exists.
        add_provider_issuer(&mut claims, &state.config.providers[payload.provider_index as usize]);

        // 7. Call kernel MintUserToken to get signed tokens.
        let mint_resp = self.sm.s2s().kernel().mint_client()
            .mint_user_token(idp_mint_request(&subject, claims.clone(), &req.trace_id))
            .await
            .map_err(|e| {
                warn!(error = %e, "kernel MintUserToken failed");
                tonic::Status::internal(format!("kernel token mint failed: {e}"))
            })?
            .into_inner();

        // 8. Compute expires_in from the tokens.
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

        // 9. If this was a CLI-originated flow, complete the nonce via the
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

    async fn broker_form_post_callback(
        &self,
        _caller: Option<&servicemanager::auth::Caller>,
        req: FormPostCallbackRequest,
    ) -> Result<FormPostCallbackResponse, tonic::Status> {
        let guard = self.require_state().await?;
        let state = guard.as_ref().unwrap();
        Ok(FormPostCallbackResponse {
            redirect_url: form_post_redirect(&state.state_codec, &state.config, &req),
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

        let claims = reauth_claims(token, &subject);

        check_pending_session(&self.pending, &req.session_id).await?;

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

    pub(super) const TEST_KID: &str = "oauth-test-key";
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

    pub(super) const TEST_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDsTCKEFvkMiN1pA+BK/UuN1fwSvh\n\
fr7bxNi63d0TNwwfz81zb9+oveuwF/Rtmfokvd/CZgYhR2RsFZ4s4LgnvQ==\n\
-----END PUBLIC KEY-----\n";

    pub(super) fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    pub(super) fn b64_pem(pem: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pem.as_bytes())
    }

    pub(super) fn signing_key() -> key::keys::ImmutableKey {
        key::keys::ImmutableKey::from_pem(TEST_KID.to_string(), &b64_pem(TEST_PRIVATE_PEM)).unwrap()
    }

    /// The JWKS the "IdP" publishes — the fixture key's public half, converted
    /// through the same chassis path a real IdP's key travels.
    pub(super) fn test_jwks() -> Vec<crate::oidc::JwkEntry> {
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
        // A real IdP id_token carries no namespace claim, and `verify_id_token`
        // never looks at one. The chassis signer is the only signer available
        // to this fixture and refuses to mint without it, so it is set purely
        // to get a signed token out of `sign()`.
        t.set_namespace("/").unwrap();
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
        t.set_namespace("/").unwrap();
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

#[cfg(test)]
mod callback_url_allowlist_tests {
    use super::*;
    use oauth_model::types::services::oauth::oauth::ProviderConfig;

    const LEGIT: &str = "https://demo.34.29.52.40.nip.io/";

    /// A provider configured the way the mock cluster configures one: the single
    /// callback URL the webapp actually passes to Authorize.
    fn provider(allowed: &[&str]) -> ProviderConfig {
        ProviderConfig {
            enable: true,
            name: "drpepper".to_string(),
            issuer: "https://keycloak.example/realms/drpepper".to_string(),
            client_id: "schematic".to_string(),
            client_secret: "secret".to_string(),
            allowed_redirect_uri_prefixes: allowed.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn config(allowed: &[&str]) -> Config {
        Config {
            enable: true,
            providers: vec![provider(allowed)],
            ..Default::default()
        }
    }

    /// The real login path: the URL the webapp sends is the allowlisted one, so
    /// Authorize proceeds to build a redirect.
    #[test]
    fn allowlisted_callback_url_is_accepted() {
        assert!(check_callback_url(&config(&[LEGIT]), 0, LEGIT).is_ok());
    }

    /// A trailing-slash entry covers deeper paths under it — the webapp may
    /// grow a route without the operator re-listing every page.
    #[test]
    fn trailing_slash_entry_covers_paths_beneath_it() {
        assert!(callback_url_allowed(
            &[LEGIT.to_string()],
            "https://demo.34.29.52.40.nip.io/console/projects"
        ));
    }

    /// The attack from the audit: an attacker-controlled host would receive the
    /// authorization code. It must be refused with invalid_argument.
    #[test]
    fn attacker_supplied_callback_url_is_rejected() {
        let err = check_callback_url(&config(&[LEGIT]), 0, "https://evil.example.com/steal")
            .expect_err("an unlisted callback_url must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// A bare `starts_with` against an entry with no trailing slash would let a
    /// lookalike host or path through. It must not.
    #[test]
    fn prefix_lookalikes_do_not_satisfy_an_entry() {
        let allowed = vec!["https://legit.example.com/app".to_string()];
        assert!(callback_url_allowed(&allowed, "https://legit.example.com/app"));
        // Host continues past the entry.
        assert!(!callback_url_allowed(&allowed, "https://legit.example.com.evil.test/app"));
        // Path segment continues past the entry.
        assert!(!callback_url_allowed(&allowed, "https://legit.example.com/app-evil/cb"));
        // Same for a trailing-slash entry: the slash must be reached honestly.
        let allowed_slash = vec!["https://legit.example.com/app/".to_string()];
        assert!(!callback_url_allowed(&allowed_slash, "https://legit.example.com/app-evil/"));
    }

    /// Fail closed: a provider with no allowlist authorizes nothing, rather
    /// than falling back to "anything goes".
    #[test]
    fn empty_allowlist_rejects_everything() {
        let err = check_callback_url(&config(&[]), 0, LEGIT)
            .expect_err("an empty allowlist must authorize nothing");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// End-to-end over the same two steps `authorize` runs, in the same order,
    /// against a real `OidcClient`: the allowlisted URL clears the check and
    /// comes back embedded in the IDP redirect as `redirect_uri`, and the
    /// attacker's URL is refused by the check — so `build_authorize_url`, and
    /// with it the IDP, never sees it.
    ///
    /// The provider points at a dead port and carries an authorization_endpoint
    /// override, so discovery fails fast and the URL is built offline.
    #[tokio::test]
    async fn only_an_allowlisted_callback_url_reaches_build_authorize_url() {
        let mut p = provider(&[LEGIT]);
        p.issuer = "https://127.0.0.1:1".to_string();
        p.authorization_endpoint = "https://idp.test/auth".to_string();
        let cfg = Config {
            enable: true,
            providers: vec![p],
            ..Default::default()
        };
        let client = crate::oidc::OidcClient::new(&cfg.providers, &[], 3600, "")
            .await
            .expect("oidc client");

        check_callback_url(&cfg, 0, LEGIT).expect("the allowlisted URL must pass the check");
        let url = client
            .build_authorize_url(0, "state", "verifier", LEGIT, "", "")
            .await
            .expect("authorize URL");
        assert!(url.starts_with("https://idp.test/auth?"), "got {url}");
        assert!(
            url.contains(&serde_urlencoded::to_string([("redirect_uri", LEGIT)]).unwrap()),
            "got {url}"
        );

        let evil = "https://evil.example.com/steal";
        assert_eq!(
            check_callback_url(&cfg, 0, evil).unwrap_err().code(),
            tonic::Code::InvalidArgument,
            "the attacker URL must never get as far as build_authorize_url"
        );
    }

    /// An out-of-range provider_index has no allowlist to check against, so it
    /// is refused before it can reach the OIDC client.
    #[test]
    fn unknown_provider_index_is_rejected() {
        let cfg = config(&[LEGIT]);
        assert_eq!(
            check_callback_url(&cfg, 1, LEGIT).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            check_callback_url(&cfg, -1, LEGIT).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
}

#[cfg(test)]
mod pending_session_binding_tests {
    use super::*;

    /// A session this instance is holding open: `broker_cli_auth` may complete
    /// its nonce.
    #[tokio::test]
    async fn a_pending_session_id_is_accepted() {
        let pending = RwLock::new(HashMap::new());
        let (tx, _rx) = oneshot::channel::<String>();
        pending.write().await.insert("nonce-1".to_string(), tx);

        check_pending_session(&pending, "nonce-1")
            .await
            .expect("a pending session_id must be completable");
    }

    /// The attack from the audit: an authenticated user who learns someone
    /// else's session_id calls BrokerCliAuth with it. With no pending session
    /// of that name, the request is refused and CompleteNonce is never sent.
    #[tokio::test]
    async fn an_unknown_session_id_is_rejected() {
        let pending = RwLock::new(HashMap::new());
        let (tx, _rx) = oneshot::channel::<String>();
        pending.write().await.insert("victims-nonce".to_string(), tx);

        let err = check_pending_session(&pending, "guessed-nonce")
            .await
            .expect_err("a session_id with no pending session must be rejected");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// Fail closed: an instance holding no sessions completes nothing.
    #[tokio::test]
    async fn an_empty_pending_map_completes_nothing() {
        let pending = RwLock::new(HashMap::new());
        assert_eq!(
            check_pending_session(&pending, "nonce-1").await.unwrap_err().code(),
            tonic::Code::NotFound
        );
    }
}

/// AuthorizeRequest's annotations, as the generated server wrapper enforces
/// them: it runs `validate()` before `authorize` and answers InvalidArgument on
/// failure, so these requests never reach the handler.
#[cfg(test)]
mod authorize_request_validation_tests {
    use super::*;

    fn request(login_hint: &str) -> AuthorizeRequest {
        AuthorizeRequest {
            callback_url: "https://console.example/".to_string(),
            login_hint: login_hint.to_string(),
            ..Default::default()
        }
    }

    /// A login_hint that is not an email address is refused.
    #[test]
    fn a_non_email_login_hint_is_rejected() {
        let err = request("not-an-email").validate().expect_err("a non-email hint must be refused");
        assert!(err.contains("invalid email address"), "got {err}");
    }

    /// login_hint is optional: empty passes, as does a real address.
    #[test]
    fn an_empty_or_email_login_hint_is_accepted() {
        request("").validate().expect("no hint is valid");
        request("a+b@example.com").validate().expect("an email hint is valid");
    }
}

#[cfg(test)]
mod apple_signin_tests {
    //! Sign in with Apple against a fake Apple: discovery, token endpoint and
    //! JWKS served over real HTTP, so the authorize URL, the form_post callback,
    //! the client-secret exchange and the id_token verification all run for
    //! real. Only kernel's MintUserToken (it needs a cluster) is not called; the
    //! claims handed to it are checked.
    use super::idp_token_verification_tests::{b64_pem, now, signing_key, TEST_KID, TEST_PUBLIC_PEM};
    use super::*;
    use crate::apple::tests::{p8_verifier, TEST_P8_PEM};
    use oauth_model::types::services::oauth::oauth::AppleSignIn;
    use prost_wkt_types::value::Kind;
    use serde_json::json;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const SERVICES_ID: &str = "com.example.console.signin";
    const TEAM_ID: &str = "TEAM123456";
    const KEY_ID: &str = "KEY1234567";
    const FORM_POST_URI: &str = "https://console.example/oauth/Auth/BrokerFormPostCallback";
    const SPA: &str = "https://console.example/";
    const APPLE_CODE: &str = "c0de.from.apple";
    const APPLE_SUB: &str = "001234.0123456789abcdef0123456789abcdef.1234";
    const RELAY_EMAIL: &str = "x7k2q9@privaterelay.appleid.com";
    const APPLE_ISSUER: &str = "https://appleid.apple.com";
    const FIRST_AUTH_USER: &str =
        r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"x7k2q9@privaterelay.appleid.com"}"#;

    struct FakeApple {
        issuer: String,
        /// Every form POSTed to the token endpoint, in order.
        token_forms: Arc<Mutex<Vec<HashMap<String, String>>>>,
    }

    /// The JWKS Apple publishes at /auth/keys: the id_token key's public half.
    fn apple_jwks() -> serde_json::Value {
        let public =
            key::keys::ImmutablePublicKey::from_pem(TEST_KID.to_string(), &b64_pem(TEST_PUBLIC_PEM))
                .unwrap();
        json!({"keys": [jwk::jwk::key_to_jwk(&public).unwrap()]})
    }

    /// An id_token with Apple's claim shapes — `email_verified` and
    /// `is_private_email` are strings, the email a private relay — signed with
    /// the key the fake publishes.
    fn apple_id_token(iss: &str) -> String {
        let mut t = token::Token::new();
        t.set_issuer(iss).unwrap();
        t.set_audience(SERVICES_ID).unwrap();
        t.set_subject(APPLE_SUB).unwrap();
        t.set_issued_at(now()).unwrap();
        t.set_expiration(now() + 600).unwrap();
        // Only so the chassis signer will sign; see `signed_id_token`.
        t.set_namespace("/").unwrap();
        t.set_custom_field("email", json!(RELAY_EMAIL)).unwrap();
        t.set_custom_field("email_verified", json!("true")).unwrap();
        t.set_custom_field("is_private_email", json!("true")).unwrap();
        t.sign(&signing_key()).unwrap();
        t.base64().unwrap().to_string()
    }

    /// What Apple's token endpoint checks before it answers: a client secret
    /// signed by the registered key for this team and Services ID, and the code
    /// and redirect_uri of the authorization it issued.
    fn apple_accepts(form: &HashMap<String, String>) -> bool {
        let field = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
        let secret = field("client_secret");
        let signed_by_p8 = token::Token::parse(secret)
            .map(|t| t.verify(&p8_verifier(KEY_ID)).is_ok())
            .unwrap_or(false);
        let Ok(claims) = parse_jwt_payload(secret) else {
            return false;
        };
        signed_by_p8
            && claims.get("iss") == Some(&json!(TEAM_ID))
            && claims.get("sub") == Some(&json!(SERVICES_ID))
            && claims.get("aud") == Some(&json!(APPLE_ISSUER))
            && field("client_id") == SERVICES_ID
            && field("grant_type") == "authorization_code"
            && field("code") == APPLE_CODE
            && field("redirect_uri") == FORM_POST_URI
    }

    /// Read one HTTP/1.1 request: (path, body).
    pub(super) async fn read_request(sock: &mut TcpStream) -> (String, String) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let n = sock.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                return (String::new(), String::new());
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
        let content_length = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            let n = sock.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8_lossy(&buf[header_end..]).to_string();
        (path, body)
    }

    async fn spawn_fake_apple() -> FakeApple {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let token_forms = Arc::new(Mutex::new(Vec::new()));

        let discovery = json!({
            "authorization_endpoint": format!("{issuer}/auth/authorize"),
            "token_endpoint": format!("{issuer}/auth/token"),
            "jwks_uri": format!("{issuer}/auth/keys"),
        })
        .to_string();
        let jwks = apple_jwks().to_string();
        let id_token = apple_id_token(&issuer);
        let forms = Arc::clone(&token_forms);

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let (discovery, jwks, id_token, forms) =
                    (discovery.clone(), jwks.clone(), id_token.clone(), Arc::clone(&forms));
                tokio::spawn(async move {
                    let (path, body) = read_request(&mut sock).await;
                    let (status, resp) = match path.as_str() {
                        "/.well-known/openid-configuration" => ("200 OK", discovery),
                        "/auth/keys" => ("200 OK", jwks),
                        "/auth/token" => {
                            let form: HashMap<String, String> =
                                serde_urlencoded::from_str(&body).unwrap_or_default();
                            forms.lock().unwrap().push(form.clone());
                            if apple_accepts(&form) {
                                let resp = json!({
                                    "id_token": id_token,
                                    "access_token": "apple-access-token",
                                    "token_type": "Bearer",
                                    "expires_in": 3600,
                                });
                                ("200 OK", resp.to_string())
                            } else {
                                ("400 Bad Request", json!({"error": "invalid_client"}).to_string())
                            }
                        }
                        _ => ("404 Not Found", "{}".to_string()),
                    };
                    let out = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                        resp.len()
                    );
                    let _ = sock.write_all(out.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        FakeApple { issuer, token_forms }
    }

    /// An Apple provider configured as the design says: Services ID as client_id,
    /// no client_secret, Apple's scope names.
    fn apple_provider(issuer: &str) -> ProviderConfig {
        ProviderConfig {
            enable: true,
            name: "apple".to_string(),
            issuer: issuer.to_string(),
            client_id: SERVICES_ID.to_string(),
            scopes: vec!["name".to_string(), "email".to_string()],
            allowed_redirect_uri_prefixes: vec![SPA.to_string()],
            apple: Some(AppleSignIn {
                team_id: TEAM_ID.to_string(),
                key_id: KEY_ID.to_string(),
                form_post_redirect_uri: FORM_POST_URI.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// A plain OIDC provider beside the Apple one, for the cases that must not
    /// take the form_post path.
    fn plain_provider() -> ProviderConfig {
        ProviderConfig {
            enable: true,
            name: "google".to_string(),
            issuer: "https://127.0.0.1:1".to_string(),
            client_id: "google-client".to_string(),
            client_secret: "google-secret".to_string(),
            authorization_endpoint: "https://idp.test/auth".to_string(),
            allowed_redirect_uri_prefixes: vec![SPA.to_string()],
            ..Default::default()
        }
    }

    fn config(providers: Vec<ProviderConfig>) -> Config {
        Config {
            enable: true,
            providers,
            ..Default::default()
        }
    }

    fn query_of(url: &str) -> HashMap<String, String> {
        serde_urlencoded::from_str(url.split_once('?').map(|(_, q)| q).unwrap_or("")).unwrap()
    }

    fn string_claim<'a>(claims: &'a prost_wkt_types::Struct, k: &str) -> Option<&'a str> {
        match claims.fields.get(k)?.kind.as_ref()? {
            Kind::StringValue(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn form(code: &str, state: &str, user: &str) -> FormPostCallbackRequest {
        FormPostCallbackRequest {
            code: code.to_string(),
            state: state.to_string(),
            id_token: "posted-id-token-is-never-used".to_string(),
            user: user.to_string(),
            ..Default::default()
        }
    }

    /// The whole browser flow, in the order the browser drives it.
    #[tokio::test]
    async fn sign_in_with_apple_end_to_end_against_a_fake_apple() {
        let apple = spawn_fake_apple().await;
        let cfg = config(vec![apple_provider(&apple.issuer)]);
        check_provider_credentials(&cfg.providers, TEST_P8_PEM).expect("apple + .p8 is complete");
        let client = OidcClient::new(&cfg.providers, &[], 3600, TEST_P8_PEM)
            .await
            .expect("oidc client");
        let codec = StateCodec::new(&cfg.providers, TEST_P8_PEM, 300);

        // 1. Authorize. Apple is sent the registered server callback and asked
        //    for form_post; the SPA URL travels only inside the state.
        check_callback_url(&cfg, 0, SPA).expect("SPA is allowlisted");
        let verifier = generate_code_verifier();
        let state = codec.encode(0, SPA, &verifier, None);
        let url = client
            .build_authorize_url(0, &state, &verifier, SPA, "", "")
            .await
            .expect("authorize URL from discovery");
        assert!(url.starts_with(&format!("{}/auth/authorize?", apple.issuer)), "got {url}");
        let q = query_of(&url);
        assert_eq!(q["response_mode"], "form_post");
        assert_eq!(q["redirect_uri"], FORM_POST_URI);
        assert_eq!(q["client_id"], SERVICES_ID);
        assert_eq!(q["scope"], "name email");
        assert_eq!(q["state"], state);

        // 2. Apple POSTs the form. The callback answers with the webapp's
        //    existing query-mode handoff, the name sealed into a fresh state.
        let redirect = form_post_redirect(&codec, &cfg, &form(APPLE_CODE, &state, FIRST_AUTH_USER));
        assert!(redirect.starts_with(&format!("{SPA}?")), "got {redirect}");
        let q = query_of(&redirect);
        assert_eq!(q["code"], APPLE_CODE);
        assert_ne!(q["state"], state, "the state is re-sealed, not echoed");
        let payload = codec.decode(&q["state"]).expect("re-sealed state decodes");
        assert_eq!(payload.provider_index, 0);
        assert_eq!(payload.callback_url, SPA);
        assert_eq!(payload.code_verifier, verifier);
        assert_eq!(payload.given_name.as_deref(), Some("Ada"));
        assert_eq!(payload.family_name.as_deref(), Some("Lovelace"));

        // 3. MintCallbackTokens' steps, as it runs them: the code exchange with
        //    a freshly minted client secret (the fake rejects anything else),
        //    then the id_token verified against Apple's JWKS and bound to the
        //    issuer and Services ID.
        let tokens = client
            .exchange_code(0, &q["code"], &payload.code_verifier, &payload.callback_url)
            .await
            .expect("the fake Apple accepts the minted client secret");
        let sent = apple.token_forms.lock().unwrap().last().cloned().unwrap();
        assert_eq!(sent["redirect_uri"], FORM_POST_URI);
        assert_eq!(sent["code_verifier"], verifier);
        let jwks = client.fetch_jwks(0).await.expect("Apple JWKS");
        let (iss, aud) = client.expected_claims(0).unwrap();
        assert_eq!(aud, SERVICES_ID);
        let id_claims = verify_id_token(tokens.id_token.as_deref().unwrap(), &jwks, &iss, &aud)
            .expect("Apple's id_token verifies");

        // 4. The claims handed to kernel: forwarded the way Google's are, plus
        //    the first-authorization name.
        let mut claims = build_claims_struct(&id_claims).unwrap();
        add_first_authorization_name(&mut claims, &payload);
        assert_eq!(string_claim(&claims, "origin_iss"), Some(apple.issuer.as_str()));
        assert_eq!(string_claim(&claims, "origin_sub"), Some(APPLE_SUB));
        assert_eq!(string_claim(&claims, "email"), Some(RELAY_EMAIL));
        assert_eq!(string_claim(&claims, "email_verified"), Some("true"));
        assert_eq!(string_claim(&claims, "is_private_email"), Some("true"));
        assert_eq!(string_claim(&claims, "given_name"), Some("Ada"));
        assert_eq!(string_claim(&claims, "family_name"), Some("Lovelace"));
        assert_eq!(string_claim(&claims, "name"), Some("Ada Lovelace"));
    }

    /// The fake is not vacuous: a client secret signed with any key but the
    /// registered .p8 is refused, as Apple refuses it, and the exchange fails.
    #[tokio::test]
    async fn a_client_secret_from_the_wrong_key_is_refused() {
        let apple = spawn_fake_apple().await;
        let cfg = config(vec![apple_provider(&apple.issuer)]);
        let other = key::keys::generate_ec_p256_key().unwrap();
        let other_p8 = std::str::from_utf8(other.pem_bytes()).unwrap();
        let client = OidcClient::new(&cfg.providers, &[], 3600, other_p8).await.unwrap();

        let err = client
            .exchange_code(0, APPLE_CODE, "verifier", SPA)
            .await
            .expect_err("Apple must refuse a secret it cannot verify");
        assert!(err.contains("invalid_client"), "got {err}");
        assert_eq!(apple.token_forms.lock().unwrap().len(), 1);
    }

    /// The literal Apple issuer, with Apple's string-typed booleans, verifies and
    /// forwards as origin_iss — what OPA's Apple arm will match on.
    #[test]
    fn apples_issuer_and_claim_shapes_verify_and_forward() {
        let jwks: Vec<crate::oidc::JwkEntry> =
            serde_json::from_value(apple_jwks()["keys"].clone()).unwrap();
        let claims = verify_id_token(&apple_id_token(APPLE_ISSUER), &jwks, APPLE_ISSUER, SERVICES_ID)
            .expect("Apple's id_token verifies");
        let forwarded = build_claims_struct(&claims).unwrap();
        assert_eq!(string_claim(&forwarded, "origin_iss"), Some(APPLE_ISSUER));
        assert_eq!(string_claim(&forwarded, "email"), Some(RELAY_EMAIL));
        assert_eq!(string_claim(&forwarded, "is_private_email"), Some("true"));

        // Bound to the Services ID: a token for another client is refused.
        assert!(verify_id_token(&apple_id_token(APPLE_ISSUER), &jwks, APPLE_ISSUER, "other.services.id").is_err());
    }

    /// GET-safe: a reload or bookmark (the gateway sends a GET as `{}`), a
    /// forged, expired or foreign state all land on "/", never on a URL taken
    /// from the request.
    #[test]
    fn an_unusable_state_redirects_to_root() {
        let cfg = config(vec![plain_provider(), apple_provider("https://appleid.apple.com")]);
        let codec = StateCodec::new(&cfg.providers, TEST_P8_PEM, 300);

        assert_eq!(form_post_redirect(&codec, &cfg, &FormPostCallbackRequest::default()), "/");
        assert_eq!(form_post_redirect(&codec, &cfg, &form(APPLE_CODE, "forged", "")), "/");

        let expired = StateCodec::new(&cfg.providers, TEST_P8_PEM, -1);
        let state = expired.encode(1, SPA, "v", None);
        assert_eq!(form_post_redirect(&expired, &cfg, &form(APPLE_CODE, &state, "")), "/");

        // A genuine state, but for the provider that does not use form_post.
        let state = codec.encode(0, SPA, "v", None);
        assert_eq!(form_post_redirect(&codec, &cfg, &form(APPLE_CODE, &state, "")), "/");

        // A genuine state whose callback_url is no longer allowlisted.
        let state = codec.encode(1, "https://evil.example/", "v", None);
        assert_eq!(form_post_redirect(&codec, &cfg, &form(APPLE_CODE, &state, "")), "/");
    }

    /// A cancelled sign-in posts `error` and no code: back to the webapp, with
    /// nothing for it to exchange.
    #[test]
    fn an_apple_error_returns_to_the_webapp_without_a_code() {
        let cfg = config(vec![apple_provider("https://appleid.apple.com")]);
        let codec = StateCodec::new(&cfg.providers, TEST_P8_PEM, 300);
        let state = codec.encode(0, SPA, "v", None);
        let req = FormPostCallbackRequest {
            state,
            error: "user_cancelled_authorize".to_string(),
            ..Default::default()
        };
        assert_eq!(form_post_redirect(&codec, &cfg, &req), SPA);
    }

    /// Apple sends `user` on the first authorization only. Without it, or with
    /// an unparsable one, the login still proceeds — just with no name.
    #[test]
    fn a_missing_or_bad_user_field_still_hands_off_the_code() {
        let cfg = config(vec![apple_provider("https://appleid.apple.com")]);
        let codec = StateCodec::new(&cfg.providers, TEST_P8_PEM, 300);
        for user in ["", "not json"] {
            let state = codec.encode(0, SPA, "v", None);
            let q = query_of(&form_post_redirect(&codec, &cfg, &form(APPLE_CODE, &state, user)));
            assert_eq!(q["code"], APPLE_CODE);
            let payload = codec.decode(&q["state"]).unwrap();
            assert_eq!((payload.given_name, payload.family_name), (None, None));
        }
    }

    /// Re-sealing keeps the original issue time, so a state that survives the
    /// callback expires when it would have anyway.
    #[test]
    fn the_resealed_state_keeps_its_original_age() {
        let cfg = config(vec![apple_provider("https://appleid.apple.com")]);
        let codec = StateCodec::new(&cfg.providers, TEST_P8_PEM, 300);
        let state = codec.encode(0, SPA, "v", None);
        let mut aged = codec.decode(&state).unwrap();
        aged.created_at -= 200;
        let aged_state = codec.seal(&aged);

        let q = query_of(&form_post_redirect(&codec, &cfg, &form(APPLE_CODE, &aged_state, "")));
        assert_eq!(codec.decode(&q["state"]).unwrap().created_at, aged.created_at);
    }

    /// A callback_url that already has a query gets the handoff appended to it.
    #[test]
    fn the_handoff_appends_to_an_existing_query() {
        let cfg = config(vec![apple_provider("https://appleid.apple.com")]);
        let codec = StateCodec::new(&cfg.providers, TEST_P8_PEM, 300);
        let state = codec.encode(0, "https://console.example/?cli=1", "v", None);
        let redirect = form_post_redirect(&codec, &cfg, &form(APPLE_CODE, &state, ""));
        assert!(redirect.starts_with("https://console.example/?cli=1&code="), "got {redirect}");
    }

    /// The name from the state never overrides a claim the id_token carries,
    /// and nothing is added when there is no name.
    #[test]
    fn the_first_authorization_name_fills_only_missing_claims() {
        let payload = StatePayload {
            provider_index: 0,
            callback_url: SPA.to_string(),
            code_verifier: "v".to_string(),
            created_at: 0,
            session_id: None,
            given_name: Some("Ada".to_string()),
            family_name: None,
        };
        let mut claims = build_claims_struct(&HashMap::from([(
            "given_name".to_string(),
            json!("FromIdToken"),
        )]))
        .unwrap();
        add_first_authorization_name(&mut claims, &payload);
        assert_eq!(string_claim(&claims, "given_name"), Some("FromIdToken"));
        assert_eq!(string_claim(&claims, "name"), Some("Ada"));
        assert!(!claims.fields.contains_key("family_name"));

        let mut empty = prost_wkt_types::Struct { fields: HashMap::new() };
        add_first_authorization_name(
            &mut empty,
            &StatePayload { given_name: None, ..payload },
        );
        assert!(empty.fields.is_empty());
    }

    /// The authorize URL of a provider without `apple` is unchanged: its own
    /// callback as redirect_uri and no response_mode.
    #[tokio::test]
    async fn a_plain_provider_is_not_sent_form_post() {
        let cfg = config(vec![plain_provider()]);
        let client = OidcClient::new(&cfg.providers, &[], 3600, TEST_P8_PEM).await.unwrap();
        let url = client.build_authorize_url(0, "s", "v", SPA, "", "").await.unwrap();
        let q = query_of(&url);
        assert_eq!(q["redirect_uri"], SPA);
        assert!(!q.contains_key("response_mode"), "got {url}");
    }

    /// The sign-up kill switch: a config with `enable` off yields no flow state,
    /// so a running instance that had sign-in on drops it on the next delivery.
    #[tokio::test]
    async fn enable_off_drops_the_flow_state() {
        let mut cfg = config(vec![plain_provider()]);
        assert!(auth_state(&cfg).await.unwrap().is_some());

        cfg.enable = false;
        assert!(auth_state(&cfg).await.unwrap().is_none());
    }

    /// Config apply refuses a provider that could never authenticate to its
    /// token endpoint, naming what is missing.
    #[test]
    fn providers_missing_their_credential_are_refused() {
        let apple = apple_provider("https://appleid.apple.com");
        let err = check_provider_credentials(&[apple.clone()], "").unwrap_err();
        assert!(err.contains("PROTO_SERVICES_OAUTH_SECRETS_APPLE_SIGNIN_KEY_P8"), "got {err}");

        let mut no_secret = plain_provider();
        no_secret.client_secret.clear();
        let err = check_provider_credentials(&[no_secret.clone()], TEST_P8_PEM).unwrap_err();
        assert!(err.contains("client_secret"), "got {err}");

        // A disabled provider is not loaded, so it is not checked.
        no_secret.enable = false;
        assert!(check_provider_credentials(&[no_secret, plain_provider(), apple], TEST_P8_PEM).is_ok());
    }

    /// An Apple provider has no static client secret, so the .p8 is what makes
    /// the state key secret. Pods sharing the Secret agree; a different (or
    /// missing) .p8 cannot decode the state.
    #[test]
    fn the_p8_keys_the_state_cipher() {
        let providers = vec![apple_provider("https://appleid.apple.com")];
        let state = StateCodec::new(&providers, TEST_P8_PEM, 300).encode(0, SPA, "v", None);

        assert!(StateCodec::new(&providers, TEST_P8_PEM, 300).decode(&state).is_ok());
        assert!(StateCodec::new(&providers, "", 300).decode(&state).is_err());
        assert!(StateCodec::new(&providers, "another p8", 300).decode(&state).is_err());
    }
}

#[cfg(test)]
mod entra_signin_tests {
    //! Microsoft Entra ID (multi-tenant) against a fake Entra: discovery, token
    //! endpoint and JWKS served over real HTTP under the `organizations` path, so
    //! the authorize URL, the code exchange and the id_token verification against
    //! the per-directory issuer template all run for real. Only kernel's
    //! MintUserToken (it needs a cluster) is not called; the claims handed to it
    //! are checked.
    use super::apple_signin_tests::read_request;
    use super::idp_token_verification_tests::{now, signing_key, test_jwks};
    use super::*;
    use prost_wkt_types::value::Kind;
    use serde_json::json;
    use std::sync::Mutex;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const CLIENT_ID: &str = "0a1b2c3d-1111-2222-3333-444455556666";
    const CLIENT_SECRET: &str = "entra-client-secret";
    const SPA: &str = "https://console.example/";
    const ENTRA_CODE: &str = "0.AXo-code-from-entra";
    const ENTRA_SUB: &str = "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ";
    const TID: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    const OTHER_TID: &str = "aaaabbbb-0000-cccc-1111-dddd2222eeee";
    /// The personal Microsoft account tenant; a `common` login can carry it.
    const MSA_TID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
    const EMAIL: &str = "ada@contoso.example";
    const TEMPLATE: &str = "https://login.microsoftonline.com/{tid}/v2.0";

    fn issuer_for(tid: &str) -> String {
        TEMPLATE.replace("{tid}", tid)
    }

    struct FakeEntra {
        /// The fake's base URL; the provider's discovery issuer and template
        /// hang off it the way they hang off login.microsoftonline.com.
        base: String,
        /// Every form POSTed to the token endpoint, in order.
        token_forms: Arc<Mutex<Vec<HashMap<String, String>>>>,
    }

    /// An Entra v2.0 id_token: `iss` per directory, `tid`, a pairwise `sub`,
    /// plus `extra` claims. Signed with the key the fake publishes.
    fn entra_id_token(iss: &str, tid: Option<&str>, extra: &[(&str, serde_json::Value)]) -> String {
        let mut t = token::Token::new();
        t.set_issuer(iss).unwrap();
        t.set_audience(CLIENT_ID).unwrap();
        t.set_subject(ENTRA_SUB).unwrap();
        t.set_issued_at(now()).unwrap();
        t.set_expiration(now() + 3600).unwrap();
        // Only so the chassis signer will sign; see `signed_id_token`.
        t.set_namespace("/").unwrap();
        if let Some(tid) = tid {
            t.set_custom_field("tid", json!(tid)).unwrap();
        }
        t.set_custom_field("ver", json!("2.0")).unwrap();
        for (k, v) in extra {
            t.set_custom_field(*k, v.clone()).unwrap();
        }
        t.sign(&signing_key()).unwrap();
        t.base64().unwrap().to_string()
    }

    /// What Entra's token endpoint checks before it answers: the app's client
    /// secret, and the code and redirect_uri of the authorization it issued.
    fn entra_accepts(form: &HashMap<String, String>) -> bool {
        let field = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
        field("client_id") == CLIENT_ID
            && field("client_secret") == CLIENT_SECRET
            && field("grant_type") == "authorization_code"
            && field("code") == ENTRA_CODE
            && field("redirect_uri") == SPA
            && !field("code_verifier").is_empty()
    }

    /// `id_token` builds the token the endpoint returns, given the fake's base URL.
    async fn spawn_fake_entra(id_token: impl FnOnce(&str) -> String) -> FakeEntra {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let token_forms = Arc::new(Mutex::new(Vec::new()));

        let discovery = json!({
            "issuer": format!("{base}/{{tenantid}}/v2.0"),
            "authorization_endpoint": format!("{base}/organizations/oauth2/v2.0/authorize"),
            "token_endpoint": format!("{base}/organizations/oauth2/v2.0/token"),
            "jwks_uri": format!("{base}/organizations/discovery/v2.0/keys"),
            "end_session_endpoint": format!("{base}/organizations/oauth2/v2.0/logout"),
        })
        .to_string();
        let keys: Vec<_> = test_jwks().iter().map(|k| k.to_json_value()).collect();
        let jwks = json!({ "keys": keys }).to_string();
        let id_token = id_token(&base);
        let forms = Arc::clone(&token_forms);

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let (discovery, jwks, id_token, forms) =
                    (discovery.clone(), jwks.clone(), id_token.clone(), Arc::clone(&forms));
                tokio::spawn(async move {
                    let (path, body) = read_request(&mut sock).await;
                    let (status, resp) = match path.as_str() {
                        "/organizations/v2.0/.well-known/openid-configuration" => ("200 OK", discovery),
                        "/organizations/discovery/v2.0/keys" => ("200 OK", jwks),
                        "/organizations/oauth2/v2.0/token" => {
                            let form: HashMap<String, String> =
                                serde_urlencoded::from_str(&body).unwrap_or_default();
                            forms.lock().unwrap().push(form.clone());
                            if entra_accepts(&form) {
                                let resp = json!({
                                    "id_token": id_token,
                                    "access_token": "entra-access-token",
                                    "token_type": "Bearer",
                                    "expires_in": 3600,
                                });
                                ("200 OK", resp.to_string())
                            } else {
                                ("401 Unauthorized", json!({"error": "invalid_client"}).to_string())
                            }
                        }
                        _ => ("404 Not Found", "{}".to_string()),
                    };
                    let out = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                        resp.len()
                    );
                    let _ = sock.write_all(out.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        FakeEntra { base, token_forms }
    }

    /// An Entra provider configured as the design says: discovery and JWKS from
    /// the `organizations` endpoint, the per-directory issuer as a template,
    /// and `email` trusted only with `xms_edov`.
    fn entra_provider(base: &str) -> ProviderConfig {
        ProviderConfig {
            enable: true,
            name: "microsoft".to_string(),
            issuer: format!("{base}/organizations/v2.0"),
            issuer_template: format!("{base}/{{tid}}/v2.0"),
            email_verified_claim: "xms_edov".to_string(),
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
            allowed_redirect_uri_prefixes: vec![SPA.to_string()],
            ..Default::default()
        }
    }

    fn config(providers: Vec<ProviderConfig>) -> Config {
        Config {
            enable: true,
            providers,
            ..Default::default()
        }
    }

    fn query_of(url: &str) -> HashMap<String, String> {
        serde_urlencoded::from_str(url.split_once('?').map(|(_, q)| q).unwrap_or("")).unwrap()
    }

    fn string_claim<'a>(claims: &'a prost_wkt_types::Struct, k: &str) -> Option<&'a str> {
        match claims.fields.get(k)?.kind.as_ref()? {
            Kind::StringValue(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn verify(token: &str) -> Result<HashMap<String, serde_json::Value>, tonic::Status> {
        verify_id_token(token, &test_jwks(), TEMPLATE, CLIENT_ID)
    }

    /// The whole browser flow, in the order the browser drives it.
    #[tokio::test]
    async fn entra_sign_in_end_to_end_against_a_fake_entra() {
        let entra = spawn_fake_entra(|base| {
            entra_id_token(
                &format!("{base}/{TID}/v2.0"),
                Some(TID),
                &[
                    ("email", json!(EMAIL)),
                    ("xms_edov", json!(true)),
                    ("preferred_username", json!(EMAIL)),
                    ("oid", json!("00000000-0000-0000-66f3-3332eca7ea81")),
                ],
            )
        })
        .await;
        let cfg = config(vec![entra_provider(&entra.base)]);
        check_provider_credentials(&cfg.providers, "").expect("a client_secret is all Entra needs");
        let client = OidcClient::new(&cfg.providers, &[], 3600, "").await.expect("oidc client");
        let codec = StateCodec::new(&cfg.providers, "", 300);

        // 1. Authorize: a plain query-mode OIDC redirect to the organizations
        //    endpoint, with the SPA as redirect_uri.
        check_callback_url(&cfg, 0, SPA).expect("SPA is allowlisted");
        let verifier = generate_code_verifier();
        let state = codec.encode(0, SPA, &verifier, None);
        let url = client
            .build_authorize_url(0, &state, &verifier, SPA, "", "")
            .await
            .expect("authorize URL from discovery");
        assert!(
            url.starts_with(&format!("{}/organizations/oauth2/v2.0/authorize?", entra.base)),
            "got {url}"
        );
        let q = query_of(&url);
        assert_eq!(q["redirect_uri"], SPA);
        assert_eq!(q["client_id"], CLIENT_ID);
        assert_eq!(q["scope"], "openid profile email");
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(!q.contains_key("response_mode"), "got {url}");

        // 2. MintCallbackTokens' steps, as it runs them: the code exchange with
        //    the static client secret (the fake rejects anything else), the
        //    id_token verified against the organizations JWKS and bound to the
        //    per-directory issuer and the app's client id, then the email gate.
        let payload = codec.decode(&state).unwrap();
        let tokens = client
            .exchange_code(0, ENTRA_CODE, &payload.code_verifier, &payload.callback_url)
            .await
            .expect("the fake Entra accepts the client secret");
        let sent = entra.token_forms.lock().unwrap().last().cloned().unwrap();
        assert_eq!(sent["redirect_uri"], SPA);
        assert_eq!(sent["code_verifier"], verifier);
        let jwks = client.fetch_jwks(0).await.expect("Entra JWKS");
        let (iss, aud) = client.expected_claims(0).unwrap();
        assert_eq!(iss, format!("{}/{{tid}}/v2.0", entra.base), "the template, not the discovery issuer");
        assert_eq!(aud, CLIENT_ID);
        let mut id_claims = verify_id_token(tokens.id_token.as_deref().unwrap(), &jwks, &iss, &aud)
            .expect("Entra's id_token verifies against the template");
        drop_unverified_email(&mut id_claims, &cfg.providers[0].email_verified_claim);

        // 3. The claims handed to kernel: forwarded the way Google's are, with
        //    the directory's own issuer as origin_iss.
        let claims = build_claims_struct(&id_claims).unwrap();
        let tenant_issuer = format!("{}/{TID}/v2.0", entra.base);
        assert_eq!(string_claim(&claims, "origin_iss"), Some(tenant_issuer.as_str()));
        assert_eq!(string_claim(&claims, "origin_sub"), Some(ENTRA_SUB));
        assert_eq!(string_claim(&claims, "tid"), Some(TID));
        assert_eq!(string_claim(&claims, "email"), Some(EMAIL));
    }

    /// login_hint is a hint only. Authorize relays whatever address the caller
    /// typed, but the person who signs in is whoever the IDP's id_token names:
    /// a hint naming someone else never reaches the claims handed to kernel.
    #[tokio::test]
    async fn a_login_hint_never_decides_who_signs_in() {
        const HINT: &str = "attacker@example.com";
        let entra = spawn_fake_entra(|base| {
            entra_id_token(
                &format!("{base}/{TID}/v2.0"),
                Some(TID),
                &[("email", json!(EMAIL)), ("xms_edov", json!(true))],
            )
        })
        .await;
        let cfg = config(vec![entra_provider(&entra.base)]);
        let client = OidcClient::new(&cfg.providers, &[], 3600, "").await.expect("oidc client");
        let codec = StateCodec::new(&cfg.providers, "", 300);

        // 1. Authorize's steps, as it runs them, with a login_hint naming
        //    someone other than who will sign in.
        let req = AuthorizeRequest {
            provider_index: 0,
            callback_url: SPA.to_string(),
            login_hint: HINT.to_string(),
            ..Default::default()
        };
        check_callback_url(&cfg, req.provider_index, &req.callback_url).expect("SPA is allowlisted");
        let verifier = generate_code_verifier();
        let state = codec.encode(req.provider_index, &req.callback_url, &verifier, None);
        let url = client
            .build_authorize_url(req.provider_index, &state, &verifier, &req.callback_url, &req.nonce, &req.login_hint)
            .await
            .expect("authorize URL from discovery");
        assert_eq!(query_of(&url)["login_hint"], HINT);

        // 2. MintCallbackTokens' steps, as it runs them.
        let payload = codec.decode(&state).unwrap();
        let tokens = client
            .exchange_code(0, ENTRA_CODE, &payload.code_verifier, &payload.callback_url)
            .await
            .expect("the fake Entra accepts the client secret");
        let jwks = client.fetch_jwks(0).await.expect("Entra JWKS");
        let (iss, aud) = client.expected_claims(0).unwrap();
        let mut id_claims = verify_id_token(tokens.id_token.as_deref().unwrap(), &jwks, &iss, &aud)
            .expect("Entra's id_token verifies");
        drop_unverified_email(&mut id_claims, &cfg.providers[0].email_verified_claim);

        // 3. The claims handed to kernel name the id_token's subject, and the
        //    hint appears nowhere in them.
        let claims = build_claims_struct(&id_claims).unwrap();
        assert_eq!(string_claim(&claims, "origin_sub"), Some(ENTRA_SUB));
        assert_eq!(string_claim(&claims, "email"), Some(EMAIL));
        for (k, v) in &claims.fields {
            assert_ne!(v.kind, Some(Kind::StringValue(HINT.to_string())), "claim {k} carries the hint");
        }
    }

    /// The fake is not vacuous: a wrong client secret is refused, as Entra
    /// refuses it, and the exchange fails.
    #[tokio::test]
    async fn a_wrong_client_secret_is_refused() {
        let entra = spawn_fake_entra(|base| entra_id_token(&format!("{base}/{TID}/v2.0"), Some(TID), &[])).await;
        let mut p = entra_provider(&entra.base);
        p.client_secret = "stale-secret".to_string();
        let client = OidcClient::new(&[p], &[], 3600, "").await.unwrap();

        let err = client
            .exchange_code(0, ENTRA_CODE, "verifier", SPA)
            .await
            .expect_err("Entra must refuse a wrong secret");
        assert!(err.contains("invalid_client"), "got {err}");
        assert_eq!(entra.token_forms.lock().unwrap().len(), 1);
    }

    /// Any directory's token verifies against the template, including a
    /// personal Microsoft account's; its own issuer is what gets checked.
    #[test]
    fn a_token_from_any_directory_verifies_against_its_own_issuer() {
        for tid in [TID, OTHER_TID, MSA_TID] {
            let claims = verify(&entra_id_token(&issuer_for(tid), Some(tid), &[]))
                .unwrap_or_else(|e| panic!("tid {tid}: {}", e.message()));
            assert_eq!(claims["iss"], json!(issuer_for(tid)));
        }
    }

    /// A token naming one directory in `iss` and another in `tid` is refused:
    /// the template is filled from `tid` and must reproduce `iss` exactly.
    #[test]
    fn an_issuer_that_does_not_match_its_tid_is_refused() {
        let err = verify(&entra_id_token(&issuer_for(OTHER_TID), Some(TID), &[]))
            .expect_err("iss and tid must name the same directory");
        assert!(err.message().contains("issuer mismatch"), "got {}", err.message());

        // The un-substituted template, or the discovery issuer, is not an issuer.
        for iss in [TEMPLATE, "https://login.microsoftonline.com/organizations/v2.0"] {
            assert!(verify(&entra_id_token(iss, Some(TID), &[])).is_err(), "iss {iss}");
        }
        // Another IDP's issuer is still refused.
        assert!(verify(&entra_id_token("https://accounts.google.com", Some(TID), &[])).is_err());
    }

    /// `tid` is spliced into a URL, so anything but a GUID is refused before
    /// substitution — even when `iss` was built to match the result.
    #[test]
    fn a_missing_or_non_guid_tid_is_refused() {
        for tid in ["organizations", "common", "../evil", "72f988bf86f141af91ab2d7cd011db47", ""] {
            let err = verify(&entra_id_token(&issuer_for(tid), Some(tid), &[]))
                .expect_err("a non-GUID tid must be refused");
            assert!(err.message().contains("tid"), "tid {tid:?}: {}", err.message());
        }
        let err = verify(&entra_id_token(&issuer_for(TID), None, &[])).expect_err("no tid");
        assert!(err.message().contains("tid"), "got {}", err.message());

        // A numeric tid is not a string GUID either.
        let err = verify(&entra_id_token(&issuer_for("42"), None, &[("tid", json!(42))]))
            .expect_err("numeric tid");
        assert!(err.message().contains("tid"), "got {}", err.message());
    }

    #[test]
    fn guid_shape() {
        assert!(is_guid(TID));
        assert!(is_guid("72F988BF-86F1-41AF-91AB-2D7CD011DB47"));
        for s in [
            "",
            "72f988bf86f141af91ab2d7cd011db47",
            "{72f988bf-86f1-41af-91ab-2d7cd011db47}",
            "72f988bf-86f1-41af-91ab-2d7cd011db4",
            "72f988bf-86f1-41af-91ab-2d7cd011db47a",
            "72f988bf-86f1-41af-91ab_2d7cd011db47",
            "g2f988bf-86f1-41af-91ab-2d7cd011db47",
            "72f988bf-86f1-41af-91ab-2d7cd011db/7",
        ] {
            assert!(!is_guid(s), "{s:?}");
        }
    }

    /// `email` survives only with `xms_edov` exactly `true`. Absent, false or a
    /// string drops it; `preferred_username` is never promoted in its place.
    #[test]
    fn email_is_forwarded_only_when_xms_edov_is_true() {
        let with = |edov: Option<serde_json::Value>| {
            let mut claims: HashMap<String, serde_json::Value> = HashMap::from([
                ("email".to_string(), json!(EMAIL)),
                ("preferred_username".to_string(), json!(EMAIL)),
            ]);
            if let Some(v) = edov {
                claims.insert("xms_edov".to_string(), v);
            }
            drop_unverified_email(&mut claims, "xms_edov");
            claims
        };

        assert_eq!(with(Some(json!(true)))["email"], json!(EMAIL));
        for edov in [None, Some(json!(false)), Some(json!("true")), Some(json!(1))] {
            let claims = with(edov.clone());
            assert!(!claims.contains_key("email"), "xms_edov {edov:?} must drop email");
            assert_eq!(claims["preferred_username"], json!(EMAIL), "left as it was, not promoted");
            let forwarded = build_claims_struct(&claims).unwrap();
            assert_eq!(string_claim(&forwarded, "email"), None);
        }

        // A provider with no email_verified_claim (Google, Keycloak) is unchanged.
        let mut claims = HashMap::from([("email".to_string(), json!(EMAIL))]);
        drop_unverified_email(&mut claims, "");
        assert_eq!(claims["email"], json!(EMAIL));
    }

    /// A login through the `organizations` provider: `origin_iss` is the
    /// directory's own issuer, `provider_iss` the configured one a tenant claim
    /// matcher names. An id_token's own `provider_iss` does not survive.
    #[test]
    fn an_organizations_login_carries_the_configured_issuer_as_provider_iss() {
        let provider = entra_provider("https://login.microsoftonline.com");
        let id_claims = verify(&entra_id_token(
            &issuer_for(TID),
            Some(TID),
            &[("provider_iss", json!("https://evil.example"))],
        ))
        .unwrap();

        let mut claims = build_claims_struct(&id_claims).unwrap();
        add_provider_issuer(&mut claims, &provider);

        assert_eq!(
            string_claim(&claims, "provider_iss"),
            Some("https://login.microsoftonline.com/organizations/v2.0")
        );
        assert_eq!(string_claim(&claims, "origin_iss"), Some(issuer_for(TID).as_str()));
        assert_eq!(string_claim(&claims, "tid"), Some(TID));
    }

    /// The cached re-auth reads the login's claims back off the Schematic
    /// token kernel minted, so a claim-matched tenant (Google `hd`, Entra
    /// `tid`, both on `provider_iss`) resolves on that path too. Schematic's own
    /// claims are not handed back to OPA as if they came from the IdP.
    #[test]
    fn the_reauth_path_forwards_the_login_claims_from_the_schematic_token() {
        let mut t = token::Token::new();
        t.set_issuer("kernel").unwrap();
        t.set_subject(ENTRA_SUB).unwrap();
        t.set_namespace("/tenants/contoso").unwrap();
        t.set_token_use("refresh").unwrap();
        t.set_azp("oauth").unwrap();
        t.set_entitlements(&["KERNEL_ANY"]).unwrap();
        for (k, v) in [
            ("typ", json!("refresh")),
            ("origin_iss", json!(issuer_for(TID))),
            ("origin_sub", json!(ENTRA_SUB)),
            ("provider_iss", json!("https://login.microsoftonline.com/organizations/v2.0")),
            ("tid", json!(TID)),
            ("hd", json!("contoso.example")),
            ("email", json!(EMAIL)),
            ("groups", json!(["admins"])),
        ] {
            t.set_custom_field(k, v).unwrap();
        }

        let claims = reauth_claims(&t, ENTRA_SUB);

        assert_eq!(string_claim(&claims, "sub"), Some(ENTRA_SUB));
        assert_eq!(
            string_claim(&claims, "provider_iss"),
            Some("https://login.microsoftonline.com/organizations/v2.0")
        );
        assert_eq!(string_claim(&claims, "origin_iss"), Some(issuer_for(TID).as_str()));
        assert_eq!(string_claim(&claims, "origin_sub"), Some(ENTRA_SUB));
        assert_eq!(string_claim(&claims, "tid"), Some(TID));
        assert_eq!(string_claim(&claims, "hd"), Some("contoso.example"));
        assert_eq!(string_claim(&claims, "email"), Some(EMAIL));
        assert!(matches!(
            claims.fields["groups"].kind.as_ref(),
            Some(Kind::ListValue(l)) if l.values.len() == 1
        ));
        for schematic in ["iss", "namespace", "token_use", "azp", "entitlements", "typ"] {
            assert!(!claims.fields.contains_key(schematic), "{schematic} must not be forwarded");
        }
    }

    /// A provider without a template keeps its fixed issuer: the discovery
    /// issuer is what its tokens are bound to.
    #[tokio::test]
    async fn a_provider_without_a_template_is_bound_to_its_issuer() {
        let mut p = entra_provider("https://127.0.0.1:1");
        p.issuer_template.clear();
        p.authorization_endpoint = "https://idp.test/auth".to_string();
        let client = OidcClient::new(&[p], &[], 3600, "").await.unwrap();
        let (iss, _) = client.expected_claims(0).unwrap();
        assert_eq!(iss, "https://127.0.0.1:1/organizations/v2.0");
    }
}
