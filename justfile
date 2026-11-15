# Local development builds only — not used in CI/CD.

TACPLUS := env_var_or_default("TACPLUS_BIN", "tacplus")

default: generate

generate:
  #!/usr/bin/env bash
  set -euo pipefail
  {{TACPLUS}} build --tag latest

# The repository's gates. `generate` runs first, so the build and the tests see
# freshly generated code from the compiler of the tacplus.yaml floor. The
# generated-code check: target/generated-sources is regenerated, never edited by
# hand, so no generated file may be tracked; that the hand-written crate builds
# and its tests pass against the regenerated model is the rest of it.
gates: generate dockerfile-user
  test -z "$(git ls-files target tacplus)"
  cargo build --all-targets --locked
  cargo test --locked

# The release image runs as the fixed non-root UID/GID the operator's
# securityContext names (runAsUser/runAsGroup 65532), not root (#22).
dockerfile-user:
  #!/usr/bin/env bash
  set -euo pipefail
  user="$(grep -E '^USER ' Dockerfile | tail -n1 | awk '{print $2}' || true)"
  test "$user" = "65532:65532" || { echo "Dockerfile: the last USER must be 65532:65532, not '${user:-root}'" >&2; exit 1; }
