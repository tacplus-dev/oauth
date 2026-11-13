# State: oauth

Overwritten to stay current (loopers and agents). Last updated: 2026-11-13 by looper (#5).

- **Version / line:** 0.1.1 (line 0.1); tacplus floor 2.6, pinned to 2.6.1 in tacplus.lock (gates pass on 2.6.1)
- **Works:** OAuth2/OIDC browser flows (Google, Microsoft Entra, Apple form_post, any OIDC IdP) and CLI/device
  token brokering, kernel minting the tokens; fleet-wide providers plus each tenant's IdPs from its kernel config
  slice (#2), rebuilt on every snapshot, nothing of a deleted tenant kept; sign-in state names its provider by a
  stable key (#11)
- **Released / deployed:** source tags v0.1.0 and v0.1.1 (v0.1.1: the 2.6 floor and a relocked Cargo.lock, so `--locked` builds; v0.1.0's lock was stale, #20). A tag publishes `ghcr.io/tacplus-dev/oauth:X.Y.Z` and the line tag `X.Y` (linux/arm64; amd64 off by default) and the GitHub release (`.github/workflows/release.yml`, README Releasing, #5); v0.1.0 cannot be built as tagged, so it has no image
- **Known gaps:** Authorize still takes a list index from ListProviders (PROPOSALS.md)
- **Blocked on:** nothing
