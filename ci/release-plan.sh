#!/usr/bin/env bash
# What a release run (.github/workflows/release.yml) publishes, decided before anything is built.
#
# Usage:  ci/release-plan.sh vX.Y.Z[-pre] MODE NOTES
#
# MODE is how the run was started:
#   push     the tag was pushed: it is released.
#   publish  by hand, for a tag that already exists (one pushed before this workflow was, like v0.1.1): it is
#            released as if just pushed. The tag is never moved.
#   dry-run  by hand, for a version not tagged yet: HEAD is tagged in this checkout only, and nothing is published.
# Run in the checkout to release, with its tags fetched; for push and publish it must be the tag's commit. Writes
# the GitHub release's notes to NOTES (release-notes.sh) and prints, in $GITHUB_OUTPUT form, `tags=` (the image
# tags, release-tags.sh) and `flag=` (the release marked Latest is the highest release, never a patch on an
# older line; a pre-release is marked one). Tested by tests/release.rs.
set -euo pipefail

version="$1"
mode="$2"
notes="$3"
here="$(cd "$(dirname "$0")" && pwd)"

tagged() { git rev-parse -q --verify "refs/tags/$version" >/dev/null; }
case "$mode" in
  push|publish)
    tagged || { echo "release-plan.sh: there is no tag $version" >&2; exit 1; }
    if [[ "$(git rev-parse HEAD)" != "$(git rev-parse "refs/tags/$version^{commit}")" ]]; then
      echo "release-plan.sh: the checkout is not $version's commit" >&2
      exit 1
    fi
    ;;
  dry-run)
    if tagged; then echo "release-plan.sh: $version is already released" >&2; exit 1; fi
    git tag "$version"
    ;;
  *) echo "release-plan.sh: unknown mode $mode (push, publish, dry-run)" >&2; exit 1 ;;
esac

tags="$("$here/release-tags.sh" "$version")"
"$here/release-notes.sh" "$version" > "$notes"
flag=--latest=false
if [[ "$version" == *-* ]]; then
  flag=--prerelease
elif [[ "$(git tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -1)" == "$version" ]]; then
  flag=--latest
fi
echo "tags=$tags"
echo "flag=$flag"
