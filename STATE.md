# State: oauth

Overwritten to stay current (loopers and agents). Last updated: 2026-11-10 by looper (#22).

- **Version / line:** 0.1.2 (line 0.1); tacplus floor 2.6, pinned to 2.6.1 in tacplus.lock (gates pass on 2.6.1)
- **Works:** OAuth2/OIDC browser flows (Google, Microsoft Entra, Apple form_post, any OIDC IdP) and CLI/device
  token brokering, kernel minting the tokens; fleet-wide providers plus each tenant's IdPs from its kernel config
  slice (#2), rebuilt on every snapshot, nothing of a deleted tenant kept; sign-in state names its provider by a
  stable key (#11); the release Dockerfile runs as the fixed non-root user `oauth` 65532:65532 (it writes no
  file, so owns no directory), and `just gates` checks the Dockerfile's last `USER` is 65532:65532 (#22)
- **Released / deployed:** source tags v0.1.0, v0.1.1 (v0.1.1: the 2.6 floor and a relocked Cargo.lock, so `--locked` builds; v0.1.0's lock was stale, #20) and v0.1.2 (the image as non-root, #22); no binaries or image yet
- **Known gaps:** no image (#5), so the non-root image is not yet started anywhere; Authorize still takes a list index from ListProviders (PROPOSALS.md)
- **Blocked on:** #5 on tacplus-dev/looper#12 and #1
