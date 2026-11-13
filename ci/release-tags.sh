#!/usr/bin/env bash
# The image tags a release puts on ghcr.io/tacplus-dev/oauth (.github/workflows/release.yml).
#
# Usage:  ci/release-tags.sh vX.Y.Z
#
# Run in the checkout with its tags fetched. Prints the tags, space-separated: X.Y.Z, and the line tag X.Y
# only when X.Y.Z is the highest release of that line, so the line tag never moves backwards and a patch on
# one line never moves another. A pre-release (vX.Y.Z-rc.N) gets only its own tag and is not a release.
# Tested by tests/release.rs.
set -euo pipefail

ref="$1"
v="${ref#v}"
if [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z.-]+$ ]]; then
  echo "$v"
  exit 0
fi
if [[ ! "$v" =~ ^([0-9]+)\.([0-9]+)\.[0-9]+$ ]]; then
  echo "release-tags.sh: $ref is not vMAJOR.MINOR.PATCH" >&2
  exit 1
fi
line="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"

# The highest release of the line, by version, not lexically.
highest="$(git tag -l "v$line.*" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k3,3n | tail -1)"

tags="$v"
[[ "$highest" == "$ref" ]] && tags+=" $line"
echo "$tags"
