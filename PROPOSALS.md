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
- **ROADMAP.md "Later" line: #5's blockers** (2026-11-13, #25): "Release: tag from v0.1.0 and publish the image
  (#5; blocked on tacplus-dev/looper#12)" names a blocker closed 2026-10-29; #5 now waits on
  tacplus-dev/looper#115 and tacplus-dev/looper#112 (its `Blocked-by:` lines). #25 fixes the same line in
  STATE.md. Proposed: "(#5; blocked on tacplus-dev/looper#115 and tacplus-dev/looper#112)". 2026-11-15: looper#115
  closed (2026-11-15T03:16Z), so the line should now read "(#5; blocked on tacplus-dev/looper#112)". 2026-11-20:
  looper#112 closed too (2026-11-15T22:36Z); #5's open `Blocked-by:` lines are now this repository's #22, #23, #26
  and #27 (the security checks failing on main), so the line should read "(#5; blocked on #22, #23, #26 and #27)".
- **ROADMAP.md "Later" line: #9 is done on main** (2026-11-15): "RUSTSEC-2023-0071 (rsa) and RUSTSEC-2026-0387
  (crypto-bigint 0.5) via generated chassis crates (#9; blocked on tacplus-dev/tacplus#186)" names a blocker closed
  2026-10-29 and work that landed: 8c44719 (#20, 2026-11-07) relocked Cargo.lock against the tacplus 2.6.1 chassis,
  which is on aws-lc-rs; rsa, crypto-bigint and elliptic-curve are gone from the lock, and neither OSV-Scanner on
  main nor the build's security checks report either advisory (comment on #9). Proposed: drop the line, or move it
  to a done note once #9 is closed.
- **looper-scan: CodeQL findings in test code are not counted** (2026-11-17, #31; a tacplus-dev/looper change):
  the nightly's CodeQL fails oauth on 13 findings in `#[cfg(test)]` modules (literal nonces passed to
  `build_authorize_url`, a test's panic message), all CRITICAL or HIGH, so none can be baselined, and an exception
  matches by rule id, so it would also accept a real finding later. Every Rust service's tests will trip the same
  rules. Proposal: looper-scan keeps CodeQL's (and the other SAST tools') findings in test code (`#[cfg(test)]`
  modules, `tests/`, `*_test.go`, `src/test/`) aside, the way it sets the generated tree aside (looper#108), and
  reports them uncounted. Raised here for Jody to take to tacplus-dev/looper. 2026-11-17: accepted by Jody (#31),
  filed as tacplus-dev/looper#179 (SAST findings in test code listed, never blocking).
- **looper-scan: an exception scoped to a location** (2026-11-17, #31; a tacplus-dev/looper change): Jody's decision
  on #31 grants an exception for `src/nonce.rs:106` only, "scoped to that location", but looper-scan matches an
  exception by finding id alone (`id`, `reason`, `decided_by`, `expires`), and a CodeQL finding's id is its rule
  (`rust/hard-coded-cryptographic-value`): any entry would accept every such finding in the repository, a real
  hard-coded nonce included. Proposal: an optional `where` key (a path, or path:line) that an entry must also match.
  #31 rewrote the nonce (`Aes256Gcm::generate_nonce`), which should leave no literal for CodeQL to flag, so oauth
  may not need it; the next nightly says. 2026-11-18: done as tacplus-dev/looper#182 (an optional `where`, a path
  or a glob).
- **looper-scan: scan the image the Dockerfile builds, not its `FROM` tags by name** (2026-11-17, #29, #30; a
  tacplus-dev/looper change): Trivy reads the Dockerfiles' base images by name, so a build stage that ships
  nothing (`Dockerfile.cross`'s `rust:trixie`, 2695 findings) counts like the release base. A fix the Dockerfile
  applies (`apt-get upgrade`) cannot clear a finding either, until Docker Hub rebuilds the tag. Proposal: scan the
  final stage's built image (or only the final stage's base), as a release's SBOM already reads the built image.

## Promoted / declined
