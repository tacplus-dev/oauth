#!/usr/bin/env bash
# The notes of a GitHub release (.github/workflows/release.yml): the commits since the previous release.
#
# Usage:  ci/release-notes.sh vX.Y.Z[-pre]
#
# Run in the checkout with its tags fetched. The previous release is the highest vX.Y.Z below this one by
# version (pre-releases are not releases), so a patch on an older line lists what changed on that line.
# The first release lists every commit. Tested by tests/release.rs.
set -euo pipefail

ref="$1"
if [[ ! "${ref#v}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-.+)?$ ]]; then
  echo "release-notes.sh: $ref is not vMAJOR.MINOR.PATCH" >&2
  exit 1
fi
key() { printf '%09d%09d%09d' "$((10#$1))" "$((10#$2))" "$((10#$3))"; }
this="$(key "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")"

prev=""
prevkey=""
while read -r tag; do
  [[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || continue
  k="$(key "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")"
  if [[ "$k" < "$this" && ( -z "$prevkey" || "$k" > "$prevkey" ) ]]; then
    prev="$tag"
    prevkey="$k"
  fi
done < <(git tag -l 'v*')

if [[ -n "$prev" ]]; then
  echo "Changes since $prev:"
  range="$prev..$ref"
else
  echo "Changes:"
  range="$ref"
fi
echo
git log --no-merges --format='- %s (%h)' "$range"
