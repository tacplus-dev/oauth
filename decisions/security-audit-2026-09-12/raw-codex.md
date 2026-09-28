I found 14 high-confidence issues. No files were modified.

## High severity

1. **[Security] Cross-provider subject collisions merge distinct users — [src/auth.rs:403](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:403)**  
   The broker uses the raw IdP `sub` as the platform subject without including `iss`.  
   **Failure scenario:** two configured IdPs issue the same opaque subject value to different people; both receive the same kernel principal and therefore inherit the same subject-keyed data and authorization state.

2. **[Security] ID tokens are not bound to the authorization request with an OIDC nonce — [src/oidc.rs:292](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/oidc.rs:292), [src/auth.rs:200](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:200)**  
   The authorization request contains OAuth `state` and PKCE but no OIDC `nonce`, and verification consequently checks no nonce claim.  
   **Failure scenario:** an IdP, intermediary, or buggy token endpoint substitutes a previously issued, still-valid ID token in a successful code exchange; signature, issuer, and audience checks pass and the broker mints tokens for the replayed identity rather than the current browser authentication.

3. **[Security] `azp` is not validated, permitting multi-audience token confusion — [src/auth.rs:169](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:169), [src/auth.rs:243](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:243)**  
   Verification accepts any token whose `aud` array contains this client ID, without requiring `azp` to identify this client.  
   **Failure scenario:** an ID token issued to another authorized party contains multiple audiences including this service; the broker accepts it and mints a platform token even though its `azp` names a different client.

4. **[Security] Caller-controlled callback destinations are sealed into state without validation — [src/auth.rs:335](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:335), [src/auth.rs:503](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:503)**  
   `Authorize` accepts any nonempty `callback_url`, and the authenticated callback returns that destination unchanged.  
   **Failure scenario:** an attacker initiates login with an attacker-controlled callback URL; after the victim authenticates, the consuming gateway/UI is instructed to redirect to that arbitrary destination, creating an open-redirect primitive and potentially exposing any tokens the consumer places in the redirect.

5. **[Security] Logout sends an ID-token hint to the first configured provider, not the token’s issuer — [src/auth.rs:522](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:522)**  
   Provider selection ignores `id_token_hint` and simply stops at the first provider with an end-session endpoint.  
   **Failure scenario:** a user authenticated through provider B logs out while provider A is listed first; provider A receives B’s ID token, disclosing that credential to the wrong IdP, while provider B’s session remains active.

6. **[Security] Duplicate unauthenticated session IDs silently replace the original token recipient — [src/service.rs:154](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/service.rs:154)**  
   `HashMap::insert` overwrites an existing pending sender without rejecting duplicate nonces.  
   **Failure scenario:** a second unauthenticated stream registers a known active CLI session ID; the legitimate stream is dropped, and the eventual broker delivery is routed to the second stream.

## Medium severity

7. **[Correctness/resource exhaustion] Timed-out pending sessions are never removed — [src/service.rs:155](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/service.rs:155), [src/service.rs:170](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/service.rs:170)**  
   Timeout and receiver-disconnect paths do not delete the corresponding `pending` entry.  
   **Failure scenario:** clients repeatedly open sessions that never complete; after each timeout, its key and sender remain indefinitely, allowing unauthenticated traffic to grow memory without bound. A failed broker `send` after insertion leaks the entry as well.

8. **[Correctness] `BrokerCliAuth` reports success before knowing whether the nonce matched — [src/auth.rs:607](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:607), [src/auth.rs:621](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:621)**  
   Successfully queueing `CompleteNonce` is treated as successful completion, although the broker result arrives asynchronously.  
   **Failure scenario:** the supplied session ID is expired or nonexistent; the method still returns `success: true`, leaving the web application claiming that a CLI was authorized when no token was delivered.

9. **[Correctness] Signing-key rotation causes avoidable login failures until the JWKS cache expires — [src/oidc.rs:381](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/oidc.rs:381), [src/auth.rs:211](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:211)**  
   A cache hit is returned before examining the ID token’s `kid`; an unknown `kid` does not trigger one forced JWKS refresh.  
   **Failure scenario:** the IdP begins signing with a newly published key while an older nonempty cache is fresh; every new login is rejected until `jwk_refetch_interval_seconds` elapses.

10. **[Correctness/security boundary] State accepts timestamps arbitrarily far in the future — [src/nonce.rs:115](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/nonce.rs:115)**  
    Expiration only rejects when `now - created_at > ttl`, so negative ages always pass.  
    **Failure scenario:** a state produced on a node with a badly advanced clock remains valid for the clock skew plus the configured TTL; anyone possessing it gets a much longer replay window than configured.

11. **[Availability] Authentication handlers hold the global configuration read lock across network operations — [src/auth.rs:357](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:357), [src/auth.rs:442](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/auth.rs:442)**  
    The guard remains live through IdP token exchange, JWKS fetch, kernel minting, and broker completion.  
    **Failure scenario:** a stalled kernel mint or broker send keeps the read lock indefinitely, preventing `apply_config` from acquiring its write lock; disabling OAuth or rotating compromised provider credentials cannot take effect.

12. **[Correctness] Discovered endpoints are never refreshed once populated — [src/oidc.rs:240](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/oidc.rs:240)**  
    `endpoint` rediscovery occurs only when the cached field is absent, with no expiry or retry after failures from an existing endpoint.  
    **Failure scenario:** an IdP rotates its authorization, token, JWKS, or logout endpoint; this service continues using the stale address until its configuration is reapplied or the process restarts.

## Low severity

13. **[Resource exhaustion] Authenticated daemon tasks retain disconnected streams until the next scheduled refresh — [src/service.rs:125](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/service.rs:125)**  
    The spawned task does not monitor the inbound stream or response receiver closure while sleeping.  
    **Failure scenario:** authenticated clients open streams and immediately disconnect while their tokens have long remaining lifetimes; one task, token, and session string remain allocated per connection until the refresh deadline.

14. **[Correctness/resource exhaustion] An unparseable refreshed token can create a one-second refresh loop — [src/service.rs:129](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/service.rs:129), [src/service.rs:134](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/oauth/src/service.rs:134)**  
    Parsing a newly minted token is optional; on failure, the old expiration is retained while the new opaque token becomes the next input.  
    **Failure scenario:** kernel returns a nonempty malformed token after the previous token reaches its refresh window; the task retries every second, repeatedly calling the mint service until an exchange fails or the client disconnects.
