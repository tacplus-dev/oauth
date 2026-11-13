#!/usr/bin/env bash
# Assembles the release image (.github/workflows/release.yml) from the Dockerfile, once per architecture, and
# publishes them as one image.
#
# Usage:  ci/release-image.sh VERSION [TAG...]
#
# Run in the checkout of the source released, with its binaries built. The Dockerfile takes them from beside it,
# as the fleet's image pipeline puts them there: for each architecture this stages a build context with
# target/<triple>/release/oauth as target/release/oauth and target/launcher/launcher-linux-<arch>, and builds it
# labelled with VERSION, the checkout's commit and that commit's date. With TAGs, each architecture is pushed by
# digest and $IMAGE:<TAG> (each TAG) is pointed at them all. Without, nothing is pushed: the dry run. PLATFORMS
# names the architectures (default "arm64"; "amd64 arm64" builds both).
set -euo pipefail

version="$1"
shift
image="${IMAGE:-ghcr.io/tacplus-dev/oauth}"
root="$(git rev-parse --show-toplevel)"
revision="$(git -C "$root" rev-parse HEAD)"
created="$(git -C "$root" log -1 --format=%cI HEAD)"
# Links the package to this repository on ghcr.io; the Dockerfile of v0.1.1 and before does not set it.
source="org.opencontainers.image.source=https://github.com/tacplus-dev/oauth"

digests=()
for arch in ${PLATFORMS:-arm64}; do
  case "$arch" in
    amd64) triple=x86_64-unknown-linux-gnu ;;
    arm64) triple=aarch64-unknown-linux-gnu ;;
    *) echo "release-image.sh: unsupported architecture $arch" >&2; exit 1 ;;
  esac
  ctx="$root/target/image/$arch"
  rm -rf "$ctx"
  mkdir -p "$ctx/target/release"
  cp "$root/Dockerfile" "$ctx/"
  cp "$root/target/$triple/release/oauth" "$ctx/target/release/oauth"
  cp "$root/target/launcher/launcher-linux-$arch" "$ctx/"

  output="type=cacheonly"
  (($#)) && output="type=image,name=$image,push-by-digest=true,name-canonical=true,push=true"
  docker buildx build --platform "linux/$arch" \
    --build-arg "VERSION=$version" --build-arg "VCS_REF=$revision" --build-arg "BUILD_DATE=$created" \
    --label "$source" \
    --output "$output" --metadata-file "$ctx.json" "$ctx"
  if (($#)); then
    digest="$(jq -r '."containerimage.digest"' "$ctx.json")"
    echo "linux/$arch: $image@$digest"
    digests+=("$image@$digest")
  fi
done

(($#)) || exit 0
refs=(--annotation "index:$source")
for tag in "$@"; do refs+=(-t "$image:$tag"); done
docker buildx imagetools create "${refs[@]}" "${digests[@]}"
