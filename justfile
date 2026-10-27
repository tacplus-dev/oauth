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
gates: generate
  test -z "$(git ls-files target tacplus)"
  cargo build --all-targets --locked
  cargo test --locked
