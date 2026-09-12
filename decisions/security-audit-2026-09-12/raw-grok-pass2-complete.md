| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🟠 HIGH | src/auth.rs | 549–625 | Any authenticated caller can complete any CLI nonce | 8/10 |
| 2 | 🟠 HIGH | src/service.rs | 163–164 | Client-chosen `session_id` last-write-wins in `pending` | 8/10 |
| 3 | 🟠 HIGH | src/auth.rs | 332–347, 508–516 | `callback_url` used as OAuth `redirect_uri` with no allowlist | 8/10 |
| 4 | 🟠 HIGH | src/auth.rs | 82, 108–128, 400–430 | Unfiltered IdP claims forwarded into `MintUserToken` | 7/10 |
| 5 | 🟡 MEDIUM | src/auth.rs | 513–547 | Logout builds IdP URL from attacker `post_logout_redirect_url` | 8/10 |
| 6 | 🟡 MEDIUM | src/service.rs | 163–198 | Timeout/error paths never remove `pending` entries | 9/10 |
| 7 | 🟡 MEDIUM | src/oidc.rs | 142–165, 365–370 | HTTP client follows redirects (secret leak / SSRF) | 7/10 |
| 8 | 🟡 MEDIUM | src/oidc.rs | 304–330 | No OIDC `nonce` generated or checked on `id_token` | 8/10 |
| 9 | 🟡 MEDIUM | src/oidc.rs | 178–196, 400–412 | Endpoint overrides omit `jwks_uri`; JWKS stuck empty | 8/10 |
| 10 | 🟡 MEDIUM | src/service.rs | 119–125 | Daemon refresh tight-loops when `exp` is missing | 8/10 |
| 11 | 🟡 MEDIUM | src/nonce.rs | 40–52 | State AES key is SHA-256 of IdP client secrets | 7/10 |
| 12 | 🟡 MEDIUM | src/oidc.rs | 118 | Negative `jwk_refetch_interval_seconds` freezes JWKS cache | 8/10 |
| 13 | 🟡 MEDIUM | src/auth.rs | 513–547 | `revoke_session` does not revoke tokens | 9/10 |
| 14 | 🟡 MEDIUM | src/oidc.rs | 199–202 | Issuer/`jwks_uri` scheme not restricted to HTTPS | 7/10 |
| 15 | 🟡 MEDIUM | src/service.rs | 161, 166 | Unauthenticated client sets `offline_access` on nonce | 6/10 |
| 16 | ⚪ LOW | src/nonce.rs | 88–94 | `encode` panics on serialize/encrypt failure | 8/10 |
| 17 | ⚪ LOW | src/auth.rs | 310–321 | `domains` never used to bind login/callback | 8/10 |
| 18 | ⚪ LOW | src/main.rs | 139–147 | Broker errors delivered as empty token | 8/10 |
| 19 | ⚪ LOW | src/nonce.rs | 110–125 | Future `created_at` extends state TTL | 7/10 |
| 20 | ⚪ LOW | Cargo.toml / README.md | — | Dead dep + docs drift vs actual code | 9/10 |

### Findings

1. **🟠 HIGH — `src/auth.rs:549`** — `broker_cli_auth` only checks that the caller has *some* valid token, then `CompleteNonce`s whatever `req.session_id` they send. **Failure:** attacker opens a CLI session, tricks a logged-in victim (query param / “already authenticated” UI) into this RPC; kernel mints the victim’s token onto the attacker’s stream.

2. **🟠 HIGH — `src/service.rs:163`** — Unauthenticated `broker_session` takes a client-chosen `session_id` and `pending.insert` overwrites. **Failure:** attacker reuses a victim nonce; the new oneshot wins; the IdP login token is delivered to the attacker; the victim times out.

3. **🟠 HIGH — `src/auth.rs:332`** — `Authorize` encrypts and sends `req.callback_url` as IdP `redirect_uri` and returns it on callback with tokens; no allowlist (`domains` unused). **Failure:** any URI the IdP will accept (localhost, extra registered URI) becomes the post-auth landing place for minted tokens.

4. **🟠 HIGH — `src/auth.rs:108`** — After prefixing only `iss/sub/aud/exp/nbf/iat/jti`, every other IdP claim is copied into the kernel mint (then `groups` drives admin in OPA). **Failure:** a malicious/misissued IdP claim (`groups`, `entitlements`, a forged `origin_iss`) is preserved on the platform token.

5. **🟡 MEDIUM — `src/auth.rs:513`** — `post_logout_redirect_url` is concatenated onto the **first** provider `end_session_endpoint` with no URI check and no provider selection. **Failure:** open redirect / logout at the wrong IdP.

6. **🟡 MEDIUM — `src/service.rs:163`** — `pending` is inserted before `RegisterNonce`; timeout spawn never `remove`s; send failure returns after insert and never spawns the waiter. **Failure:** map grows forever; a late `TokenDelivery` hits a dead sender or the wrong waiter.

7. **🟡 MEDIUM — `src/oidc.rs:365`** — Default reqwest client follows redirects on discovery **and** token POST (client_secret in the body). **Failure:** `302/307` from `token_endpoint`/`jwks_uri` sends the secret to an attacker URL or hits internal SSRF targets.

8. **🟡 MEDIUM — `src/oidc.rs:304`** — Authorize URL has PKCE but no OIDC `nonce`; `verify_id_token` never checks `nonce`. **Failure:** a substituted `id_token` from the token response is not bound to this browser request.

9. **🟡 MEDIUM — `src/oidc.rs:178`** — Discovery-failure fallback sets auth/token/end-session overrides, never `jwks_uri`. **Failure:** the airgapped/self-signed path they documented still cannot verify `id_token`s.

10. **🟡 MEDIUM — `src/service.rs:119`** — `expiration().unwrap_or(0)` plus `.max(1)` sleep. **Failure:** token without `exp`, or refresh JWT that `Token::parse` rejects, → mint hammer every 1s until the client drops.

11. **🟡 MEDIUM — `src/nonce.rs:40`** — AES-GCM key is `SHA256("identity-state:" + sorted client_secrets)`. **Failure:** anyone with provider secrets (config dump) forges `state` (`callback_url`, `session_id`, `code_verifier`); rotating one secret invalidates all in-flight logins.

12. **🟡 MEDIUM — `src/oidc.rs:118`** — `Duration::from_secs(refetch_interval_secs as u64)`. **Failure:** negative config → ~136-year cache; JWKS rotation never observed.

13. **🟡 MEDIUM — `src/auth.rs:513`** — `revoke_session` only builds an IdP logout URL; kernel/platform tokens stay valid. **Failure:** “logout” leaves refresh/access tokens usable.

14. **🟡 MEDIUM — `src/oidc.rs:199`** — `issuer` is concatenated into `.well-known` with no `https` requirement. **Failure:** `http://` IdP → discovery/JWKS/token without TLS.

15. **🟡 MEDIUM — `src/service.rs:161`** — Unauthenticated stream sets `offline_access` on `RegisterNonce`. **Failure:** caller requests the long-lived mint path without proving anything.

16. **⚪ LOW — `src/nonce.rs:88`** — `serde_json::to_vec(...).unwrap()` / `encrypt(...).unwrap()` on the authorize path. **Failure:** unexpected payload/crypto error panics the worker instead of `Status`.

17. **⚪ LOW — `src/auth.rs:310`** — `ProviderInfo.domains` is advertised but never applied to email/redirect checks. **Failure:** operators think domain restriction exists; it does not.

18. **⚪ LOW — `src/main.rs:139`** — Kernel broker `Error` is `send("")`, same as empty success. **Failure:** CLI only sees generic `"authentication failed"`; pending entry still needs a delivery to free the slot.

19. **⚪ LOW — `src/nonce.rs:110`** — Expiry is `age > ttl` only. **Failure:** `created_at` in the future (forged or clock skew) makes state valid beyond TTL.

20. **⚪ LOW — pattern drift** — `dashmap` is unused; README still refers to `src/session.rs`, a nonce store, `InstallToken`, and `RevokeSession` as session invalidation. **Failure:** operators/reviewers trust docs that do not match this broker.

---

Follow-up (reply with a number):
1. Fix highest severity issues
2. Fix all issues
3. Commit a summary of findings

