# oauth Security & Quality Audit — Consolidated Report
2026-09-12 — multimodal review: Fable 5.1 (Claude), Codex CLI (GPT), Grok 4.6 (via GitHub Copilot CLI)
Scope: `src/` (5 Rust files) + `tests/`. `target/` excluded.

`oauth` is an auth broker: OIDC identity-provider delegation, exchanging external IdP identities
for kernel-minted tokens, plus a CLI device-login flow. All three tools independently converged on
the same two vulnerability classes from different angles — strong cross-model agreement.

---

## Critical — two systemic issues, each found 2-3 ways independently

### 1. Open redirect + authorization-code theft via unvalidated `callback_url` [VERIFIED]
**Files:** `src/auth.rs:335-347` (Authorize), `src/oidc.rs:264-305` (`build_authorize_url`),
`src/auth.rs:508-516`/`src/oidc.rs:328` (token exchange), `mock/idp/scripts/idp-provision.sh:150`
**Found independently by all three tools.** I traced the full path: `Authorize` is unauthenticated
(`PUBLIC_NO_AUTH`) and accepts any non-empty `callback_url`, which is then used **verbatim as the
literal OIDC `redirect_uri`** sent to the IdP — both when building the authorize URL and again at
code-exchange time. There is no allowlist check anywhere in this path (`ProviderInfo.domains` is
declared but, per Grok's independent finding, never actually applied to anything). **I checked the
IdP registration and confirmed it's currently wide open**: the only redirect-URI registration that
exists anywhere in the repo is `mock/idp/scripts/idp-provision.sh:150`, which registers
`https://<cluster>/*` — a wildcard. This is what's actually provisioned on the live cluster today,
not a hypothetical. An attacker can start a login with a `callback_url` they control, send the
resulting IdP URL to a victim, and receive the victim's authorization code (or, if they also
control the flow end-to-end, the minted kernel refresh/access tokens) at their own endpoint.

### 2. CLI login session hijacking — no binding between requester and claimant [VERIFIED the core mechanism, 3 independent angles reported]
**Files:** `src/service.rs:154-156` (session registration), `src/auth.rs:549-625` (`broker_cli_auth`
completion, Grok's finding), kernel's `CliTokenBrokerServiceImpl.java:192` (cross-service, Fable's
finding)
**I read the registration code directly and confirmed it:** `self.pending.write().await.insert(session_id.clone(), reply_tx)`
is a plain, unconditional map insert — no check for a pre-existing entry for that `session_id`.
The `session_id` is carried in the browser login URL (per the proto's own comment), so anyone who
observes that URL before the legitimate user finishes login can open their own session with the
same id and silently steal the delivered token when the victim completes login. Fable additionally
found kernel's own `RegisterNonce` handler does the identical last-write-wins overwrite server-side
— a second, independent instance of the same bug class in the layer below. Grok separately found a
third angle: the authenticated `broker_cli_auth`/`CompleteNonce` completion path only checks that
*some* valid token was presented, not that the presenter is the one who opened that specific
session — meaning even an unrelated authenticated user's token can complete someone else's pending
nonce. Three tools, three different code paths, one systemic root cause: nothing in this flow
verifies that the party completing a session is the party that started it.

---

## High
- **Unfiltered IdP claims forwarded into the platform token** (Grok 7/10, Codex's `azp` finding is
  the same area) — after copying only the standard `iss/sub/aud/exp/nbf/iat/jti` claims explicitly,
  every *other* IdP-supplied claim is passed through to `MintUserToken`, including `groups` which
  reportedly drives OPA admin decisions. A misconfigured or compromised IdP (or one that lets users
  set custom claims) could hand itself elevated entitlements.
- **`azp` not validated** (Codex 8/10, unverified by me) — token acceptance only checks that `aud`
  contains this client's id, not that `azp` names this client specifically; could allow a token
  issued to a different authorized party to be accepted here.
- **Cross-provider subject collision** (Codex 8/10, unverified by me) — raw IdP `sub` used as the
  platform subject without the issuer, so two different IdPs issuing the same opaque subject value
  to different real people would collide onto one kernel principal.

## Medium
- No OIDC `nonce` generated or checked (Fable, Grok cross-confirmed) — PKCE covers much of the same
  surface for the code flow, so this is drift from the documented design more than an open hole on
  its own, but worth closing.
- `post_logout_redirect_url`/logout targets the first configured provider regardless of which IdP
  the user actually authenticated with, and is concatenated with no URI validation (Fable + Grok
  cross-confirmed) — open-redirect-adjacent, and logout can silently fail to reach the right IdP.
- `revoke_session` only builds an IdP logout URL — kernel/platform tokens are never actually
  revoked (Grok 9/10).
- Pending-session map entries are never cleaned up on timeout/disconnect — unbounded growth on a
  public, unauthenticated endpoint (Fable + Grok cross-confirmed).
- State-encryption AES key is derived from a hash of configured IdP client secrets — with all
  secrets empty (a plausible public-client config) the key is a fixed constant; a leaked or rotated
  secret has outsized blast radius on in-flight logins (Fable + Grok cross-confirmed).
- HTTP client used for discovery/token exchange follows redirects by default — a malicious or
  compromised token endpoint could exfiltrate the client secret via a redirect, or be used for SSRF
  (Grok 7/10, unverified by me).
- Unknown JWKS `kid` never triggers an immediate refetch — a real key rotation causes a window
  (default 300s) where every login fails (Fable, Grok cross-confirmed).
- Daemon token-refresh loop can spin at ~1 refresh/sec if `exp` is missing or unparseable (Fable +
  Grok cross-confirmed).
- Issuer/JWKS URL scheme isn't restricted to HTTPS (Grok 7/10, unverified).
- Negative `jwk_refetch_interval_seconds` config value effectively freezes the JWKS cache forever
  (Grok 8/10) — config-validation gap, not directly attacker-reachable.

## Low / pattern drift
- IdP error response bodies echoed back to unauthenticated callers (info disclosure, minor).
- Read-lock held across the entire network round-trip chain (discovery → exchange → JWKS → mint),
  so a config reload during a slow callback blocks all new logins (Fable).
- Panics on serialize/encrypt failure in the state-encoding path instead of returning a status.
- `ProviderInfo.domains` field is declared and presumably documented but never actually used to
  restrict anything.
- Dead dependencies in `Cargo.toml`; README references files/RPCs (`src/session.rs`,
  `oauth.Token/InstallToken`) that don't exist in the current code.

---

## Recommended next step
Fix the two Critical items first — both are real, both confirmed via direct code reading (not just
tool claims), and both are exploitable on the cluster as currently configured. The unfiltered-claims
forwarding (High) is worth checking next given it touches OPA admin entitlement, before the Medium
list.

## Raw per-tool output
- Codex: `codex.out.md` (14 findings)
- Fable 5.1: `fable.out.md` (13 findings — did its own internal verification pass against kernel
  source and the IdP provisioning scripts before reporting; includes a "cleared, not flagged"
  section worth reading)
- Grok 4.6: `grok.out.md` (first pass, cut short again by Copilot CLI's internal timeout, zero
  findings written) + `grok2.out.md` (completed continuation, 20 findings)
