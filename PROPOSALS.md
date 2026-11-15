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
  closed (2026-11-15T03:16Z), so the line should now read "(#5; blocked on tacplus-dev/looper#112)". Later on
  2026-11-15: looper#112 closed too and #5's release.yml is landing, so the line is done once #5 closes; "Now"
  should then read "Released v0.1.x (`ghcr.io/tacplus-dev/oauth`, line tag 0.1)".
- **One launcher pin for the release images and the fleets** (2026-11-15, #5): `.github/workflows/release.yml`
  builds the launcher from source at `LAUNCHER_COMMIT` (0e139ca, launcher's release v0.1.0), and
  fleet-seatrials' `images/pins.yaml` pins `launcher_commit: c575e14`. Two pins of one binary drift; kernel#7
  proposed the same. Proposal: the fleets' pin becomes a launcher release line (tacplus#180) and each service's
  release.yml pins the same release, or the release image takes the launcher from its own published image.
- **tacplus-dev/looper#17 takes the releases over** (2026-11-15, #5): release.yml departs from "no GitHub
  Actions" (tacplus-dev/roadmap decisions/ci-on-gitlab-2026-10-27.md, addendum 2026-11-07) because the GitLab
  build pipeline has no ghcr push credential. When it does, the release moves there and release.yml is retired
  with the other workflows (looper#18); the scripts under `ci/` are the parts to keep.
- **ROADMAP.md "Later" line: #9 is done on main** (2026-11-15): "RUSTSEC-2023-0071 (rsa) and RUSTSEC-2026-0387
  (crypto-bigint 0.5) via generated chassis crates (#9; blocked on tacplus-dev/tacplus#186)" names a blocker closed
  2026-10-29 and work that landed: 8c44719 (#20, 2026-11-07) relocked Cargo.lock against the tacplus 2.6.1 chassis,
  which is on aws-lc-rs; rsa, crypto-bigint and elliptic-curve are gone from the lock, and neither OSV-Scanner on
  main nor the build's security checks report either advisory (comment on #9). Proposed: drop the line, or move it
  to a done note once #9 is closed.

## Promoted / declined
