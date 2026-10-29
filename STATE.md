# State: oauth

Overwritten to stay current (loopers and agents). Last updated: 2026-10-29 by looper (#13).

- **Version / line:** unreleased (Cargo 0.1.0, no tag yet); tacplus floor 2.5
- **Works:** OAuth2/OIDC browser flows (Google, Microsoft Entra, Apple form_post, any OIDC IdP) and CLI/device
  token brokering, kernel minting the tokens; fleet-wide providers plus each tenant's IdPs from its kernel config
  slice (#2), rebuilt on every snapshot, nothing of a deleted tenant kept; sign-in state names its provider by a
  stable key (#11)
- **Released / deployed:** nothing released from this repository yet
- **Known gaps:** no release or image (#5); RUSTSEC-2023-0071 and RUSTSEC-2026-0387 via chassis crates (#9);
  Authorize still takes a list index from ListProviders (PROPOSALS.md)
- **Blocked on:** #5 on tacplus-dev/looper#12 and #1; #9 on tacplus-dev/tacplus#186
