# State: oauth

Overwritten to stay current (loopers and agents). Last updated: 2026-11-24 by looper (#35).

- **Version / line:** 0.1.6 (line 0.1); tacplus floor 2.6, pinned to 2.6.14 in tacplus.lock (gates pass on 2.6.14)
- **Works:** OAuth2/OIDC browser flows (Google, Microsoft Entra, Apple form_post, any OIDC IdP) and CLI/device
  token brokering, kernel minting the tokens; fleet-wide providers plus each tenant's IdPs from its kernel config
  slice (#2), rebuilt on every snapshot, nothing of a deleted tenant kept; sign-in state names its provider by a
  stable key (#11)
- **Released / deployed:** source tags v0.1.0, v0.1.1, v0.1.2, v0.1.3, v0.1.4, v0.1.5 and v0.1.6 (v0.1.1: the 2.6 floor and a relocked Cargo.lock, so `--locked` builds; v0.1.0's lock was stale, #20; v0.1.2: the sign-in state's AES-GCM nonce drawn with `Aes256Gcm::generate_nonce`, format unchanged, #31; v0.1.3: relocked to tacplus 2.6.13 and its build image, backoff gone from Cargo.lock with the 2.6.13 httpclient chassis, #33; v0.1.4: relocked to tacplus 2.6.14 and its build image, #34; v0.1.5: every Dockerfile base pinned by digest, a test failing on any `FROM` without `@sha256:`, #36; v0.1.6: url 2.5.9 in Cargo.lock for RUSTSEC-2026-0592, #35); no binaries or image yet
- **Known gaps:** no image (#5); Authorize still takes a list index from ListProviders (PROPOSALS.md)
- **Blocked on:** #5 on tacplus-dev/looper#12 and #1
