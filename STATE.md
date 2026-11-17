# State: oauth

Overwritten to stay current (loopers and agents). Last updated: 2026-11-17 by looper (#30).

- **Version / line:** 0.1.2 (line 0.1); tacplus floor 2.6, pinned to 2.6.1 in tacplus.lock (gates pass on 2.6.1)
- **Works:** OAuth2/OIDC browser flows (Google, Microsoft Entra, Apple form_post, any OIDC IdP) and CLI/device
  token brokering, kernel minting the tokens; fleet-wide providers plus each tenant's IdPs from its kernel config
  slice (#2), rebuilt on every snapshot, nothing of a deleted tenant kept; sign-in state names its provider by a
  stable key (#11); the release Dockerfile's base pinned by digest (debian:trixie-slim 13.7), with trixie-security's
  zlib1g 1:1.3.dfsg+really1.3.1-1+deb13u1 for CVE-2026-85091 until a base digest carries it (#30)
- **Released / deployed:** source tags v0.1.0 and v0.1.1 (v0.1.1: the 2.6 floor and a relocked Cargo.lock, so `--locked` builds; v0.1.0's lock was stale, #20); v0.1.2 (the zlib1g fix, #30) to be tagged once just gates pass on main; no binaries or image yet
- **Known gaps:** no image (#5); Authorize still takes a list index from ListProviders (PROPOSALS.md)
- **Blocked on:** #5 on tacplus-dev/looper#12 and #1
