# Provenance

Copied **wholesale** on 2026-10-23 from `gitlab.com/seabeam/schematic/platform/services/oauth` at commit
`7d4d37e` (its own nested git repository; history carried over), with `proto/services/oauth.proto` and
`proto/dependencies.yaml` from `platform/proto` at `ca7c322` on branch `big8-p1-messaging`. Build outputs not copied.

Jody, 2026-10-23: *"We will copy kernel over to its github home and only make changes to it. we will
keep these as ships in the night for now. For the new stuff we want to do it the right way."* and
*"the following will also need to be ported over to tacplus-dev ... blobstore gateway kmaker letsencrypt
eventbus oauth"*. The private copy runs the launch fleet unchanged; new-design changes land here.

Divergences: headers in tacplus.yaml (Jody Scott, Apache-2.0; LICENSE added); `src: proto` (this repo
holds the service's own proto); `proto/registry.yaml` is a lock of github.com/tacplus-dev/registry.

2026-10-27, no SeaBeam (#7): tacplus-dev works by itself, so nothing outside this note and dated records
names SeaBeam. The oauth proto is this repository's own (`proto/services/oauth.proto`), not fetched: its
contract in the registry lock is `github.com/tacplus-dev/oauth` (public), as in github.com/tacplus-dev/registry,
and its dependencies (kernel, chassis) come from their tacplus-dev homes through that registry. `pkg` is
`com.github.tacplusdev.oauth` (the Rust crate is still `oauth-model`). Removed: `.gitlab-ci.yml` (SeaBeam's
GitLab pipeline and registry; release CI is #5) and the GitLab package `registry:` block of
`proto/dependencies.yaml`. `Dockerfile.cross` runs on the public `debian:trixie-slim`; the proto header and
image labels name Jody Scott and tacplus.dev; examples and tests use example.com names.
