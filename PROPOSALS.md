# Proposals: oauth

Written by loopers. Each proposal: what, why, links. Jody promotes accepted ones into ROADMAP.md (via an agent);
the looper then marks it `promoted` or `declined` here with the date.

## Open
- **Authorize by stable provider key** (2026-10-27, #11): the sign-in state now names its provider by key, but
  `AuthorizeRequest.provider_index` is still the index ListProviders gave. If a tenant is deleted or edits its slice
  between the two calls, the index can name another provider, and the person is sent to that IdP (its allowlist
  still applies). Proposal: an additive `ProviderInfo.key` / `AuthorizeRequest.provider_key` in oauth.proto, which
  the webapp would send. That is a public contract change, so it is not made here.
- **ROADMAP.md "Now" line: tacplus floor 2.6, pinned 2.6.1** (2026-10-29, #13; 2026-11-07, #20, #21): the floor
  is 2.6 in tacplus.yaml, pinned to 2.6.1 and its build image by digest in tacplus.lock, but ROADMAP.md's "Now"
  line still says "Unreleased; tacplus floor 2.4" (v0.1.0 is tagged). #21 asks for that line to follow the floor;
  the looper may not change ROADMAP.md (its push is refused), so an agent changes it at Jody's request. Proposed:
  "Released v0.1.x (source tags); tacplus floor 2.6, pinned 2.6.1 in tacplus.lock."
- **tacplus: generate `rmcp = "3.9"` for the Rust model** (2026-11-11, #23): tacplus 2.6.1 generates
  `rmcp = "3.4.1"` (a caret requirement) in the model's Cargo.toml, so a lock may keep 3.4.x–3.8.x, which carry
  RUSTSEC-2026-0457, -0461 and -0462, until someone relocks by hand. oauth's Cargo.lock is relocked to 3.9.0 (#23);
  a floor of 3.9 in the generator would make cargo move every such lock forward. That is a change in tacplus-dev/tacplus, not here.

## Promoted / declined
