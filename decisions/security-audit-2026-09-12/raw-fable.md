Verification is done. Kernel's RegisterNonce overwrites the nonce owner unconditionally, and the IdP provisioning scripts register wildcard redirect URIs, which confirms the two top findings. Writing up the ranked report now.

## OAuth service audit: ranked findings

Scope was the five files in `src/` plus `tests/fixtures`. There are no integration tests under `tests/`, only TLS fixtures used by the unit tests in `oidc.rs`. The id_token verification path is sound: the chassis `Token::verify` checks alg against the JWK, exp, and nbf, and `auth.rs` adds issuer and audience binding with fail-closed kid lookup. The problems are around the edges of that path.

### High

**1. Caller-controlled `callback_url` is used verbatim as the OIDC `redirect_uri`, with no allowlist.**
`src/auth.rs:338`, `src/auth.rs:342`, `src/oidc.rs:295`, `src/oidc.rs:328`. Authorize is `PUBLIC_NO_AUTH` and MintCallbackTokens is `SELF_AUTHENTICATES`, so the only thing binding where the IdP sends the code is the IdP's registered redirect list. The platform's own provisioning registers a wildcard, `https://<cluster>/*` in `mock/idp/scripts/idp-provision.sh:150` and `*` in the mock user-data template. Failure scenario: an attacker calls Authorize with a callback_url they control under the wildcard, sends the returned IdP URL to a victim, receives `code` and `state` at their endpoint, then calls MintCallbackTokens themselves and gets the victim's kernel refresh and access tokens. Even with exact-match registration at the IdP, the `callback_url` echoed back in CallbackResponse is an open redirect from the auth domain. The proto describes `callback_url` as the originating microservice's return URL, not the OIDC redirect_uri. The code conflates the two.

**2. A CLI session nonce can be hijacked by re-registering the same session_id.**
`src/service.rs:155`, `src/main.rs:139`. The pending map insert unconditionally replaces any existing sender for that session_id, and kernel's RegisterNonce likewise overwrites the owning instance (`CliTokenBrokerServiceImpl.java:192`). The session_id is carried in the browser login URL per the proto comment. Failure scenario: anyone who sees that URL before the victim finishes login opens their own BrokerSession with the same session_id. The victim's oneshot is dropped and they see "session expired". When the victim completes login, the refresh token is delivered to the attacker's stream. The insert also happens before the broker send is validated, so a rejected registration still clobbers the legitimate sender.

### Medium

**3. Pending-session map grows without bound on the unauthenticated stream.**
`src/service.rs:155` through `src/service.rs:189`. The entry is inserted before the broker send, and nothing removes it on send failure, timeout, or client disconnect. Removal only happens when kernel sends a TokenDelivery or Error for that exact nonce, which never happens for an abandoned session. Failure scenario: a client opens streams with random session_ids on this public endpoint and each leaves a map entry and a oneshot sender resident forever.

**4. Unknown kid never triggers a JWKS refetch.**
`src/oidc.rs:384` through `src/oidc.rs:388`, `src/auth.rs:211`. The cache is served whenever it is non-empty and younger than the refetch interval. Failure scenario: the IdP rotates its signing key and every login fails with "no IDP signing key matches" until the interval expires, 300s by default. Standard practice is one refetch on a kid miss.

**5. Daemon refresh loop can spin at one refresh per second.**
`src/service.rs:129`. Sleep is `max(exp - now - auto_refresh_before, 1)`. If the minted token's remaining life is shorter than `auto_refresh_before` (3600s default), the next sleep is 1s. The access-token fallback at `src/service.rs:84` produces exactly that. A parse failure at line 134 leaves `exp` stale, which also repeats immediately. Failure scenario: each connected daemon hammers kernel MintToken once per second until the client disconnects. Separately, the task only notices a disconnect on its next send, so an abandoned stream keeps a task and a live token in memory for up to `exp - auto_refresh_before`, which can be days.

**6. Logout targets the first provider with an end-session endpoint, not the user's provider.**
`src/auth.rs:523` through `src/auth.rs:536`. Failure scenario: with two providers configured, a user who logged in via the second is redirected to the first IdP's end-session URL with an id_token_hint from a different issuer, which the IdP rejects, so IdP logout silently never happens.

**7. `end_session_endpoint` bypasses the lazy-rediscovery path the rest of the file mandates.**
`src/oidc.rs:428`. The comment at `src/oidc.rs:237` says every endpoint accessor goes through `endpoint()`, but this one reads the config directly. Failure scenario: discovery fails at startup with no override configured, and logout URLs stay empty for the life of the process even after the IdP recovers.

**8. No consent step binds a CLI session to the person approving it.**
`src/auth.rs:547` through `src/auth.rs:617`, `src/auth.rs:330`. Any authenticated user who lands on a URL containing an attacker's session_id, or completes an authorize flow with it, hands their token to the attacker's CLI. This is the device-flow phishing class. It is a design gap rather than a coding error, but the service has no verification-code or confirmation hook to mitigate it.

### Low

**9. State encryption key is a hash of client secrets, so public clients get a constant key.**
`src/nonce.rs:45` through `src/nonce.rs:56`. With all client_secret values empty, the key is SHA-256 of a fixed prefix and anyone can forge state. The only field that forgery gains over a legitimate Authorize call is `created_at`, so the impact is TTL bypass. Rotating any client secret also invalidates every in-flight login, and a leaked client secret becomes a state-forgery key.

**10. IdP token-endpoint response body is echoed to the unauthenticated caller.**
`src/oidc.rs:346` and `src/auth.rs:378`. The IdP's error body, including any diagnostic detail, comes back inside a gRPC Internal status.

**11. No OIDC `nonce` is sent or checked.**
`src/oidc.rs:292`. The proto header at `oauth.proto:17` says the redirect carries "PKCE, state, and nonce". PKCE plus encrypted state covers the same injection surface for the code flow, so this is drift from the documented design rather than a live hole.

**12. Read guard held across network calls.**
`src/auth.rs:326` and `src/auth.rs:357`. The state read lock is held through discovery, token exchange, JWKS fetch, and kernel mint. Tokio's RwLock is write-preferring, so a config reload arriving during a slow callback blocks all new Authorize and Callback requests until that callback finishes.

**13. Housekeeping drift.**
Cargo.toml declares `dashmap`, `futures`, `prost`, `prost-types`, and `tracing-subscriber`, none of which are used in `src/`. The live test at `src/oidc.rs:606` skips via env var while its counterpart at `src/auth.rs:895` uses `#[ignore]`. README lists `src/session.rs` and an `oauth.Token/InstallToken` RPC that do not exist.

### Not flagged

I looked at and cleared: state replay (the IdP code is single-use and bound to the verifier), alg confusion (chassis enforces alg equals JWK alg), issuer trailing-slash handling, SSRF (all URLs come from config or the TLS-verified discovery document), and the claim forwarding in `build_claims_struct` (IdP is a trusted party by design).
