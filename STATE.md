# State: oauth

Overwritten to stay current (loopers and agents). Last updated: 2026-10-29 by looper (#9).

- **Version / line:** unreleased (Cargo 0.1.0, no tag yet); tacplus floor 2.5
- **Works:** OAuth2/OIDC browser flows (Google, Microsoft Entra, Apple form_post, any OIDC IdP) and CLI/device
  token brokering, kernel minting the tokens; fleet-wide providers plus each tenant's IdPs from its kernel config
  slice (#2), rebuilt on every snapshot, nothing of a deleted tenant kept; sign-in state names its provider by a
  stable key (#11)
- **Released / deployed:** nothing released from this repository yet
- **Known gaps:** no release or image (#5); RUSTSEC-2023-0071 and RUSTSEC-2026-0387 via the
  chassis crates of the 2.5 floor (#9; oauth's own rsa dev-dependency is gone, ring signs the RS256 test cases);
  Authorize still takes a list index from ListProviders (PROPOSALS.md)
- **Blocked on:** #5 on tacplus-dev/looper#12 and #1; #9 on tacplus v2.5.2 (tacplus-dev/tacplus#216, the #186 backport), then a
  regenerate and relock
