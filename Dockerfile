# OAuth Release Image
# Layers the pre-built oauth binary onto a minimal runtime image.

# The base is a build argument: a fleet may hand in its own hardened base, the
# default is the public one (no private registry in a public contract's repo),
# pinned by digest (trixie-20261104-slim, 13.7): a rebuild of the tag moves nothing
# under a release; the digest moves on purpose, with the zlib1g pin below.
ARG BASE_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
FROM ${BASE_IMAGE}

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Jody Scott <jody@thescottsweb.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="tacplus.dev" \
      org.opencontainers.image.title="OAuth" \
      org.opencontainers.image.description="Session management service for Schematic control plane"

# zlib1g from trixie-security, by version: the base ships 1:1.3.dfsg+really1.3.1-1+b1,
# CVE-2026-85091 (#30). Drop it once a base digest carries the fix.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 && rm -rf /var/lib/apt/lists/*
COPY target/release/oauth /usr/local/bin/oauth

# Every service runs under the launcher (github.com/tacplus-dev/launcher): PID 1
# that forwards signals, propagates the exit code, and kills a deadlocked child
# on gRPC health. The fleet's image pipeline puts the binary beside the Dockerfile.
ARG TARGETARCH
COPY launcher-linux-${TARGETARCH} /usr/local/bin/launcher
ENV LAUNCH_CMD="oauth" HEALTH_PORT=8443
ENTRYPOINT ["launcher"]
