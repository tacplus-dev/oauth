# OAuth Release Image
# Layers the pre-built oauth binary onto a minimal runtime image.

# The base is a build argument: a fleet may hand in its own hardened base, the
# default is the public one (no private registry in a public contract's repo).
ARG BASE_IMAGE=debian:trixie-slim
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

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY target/release/oauth /usr/local/bin/oauth

# Every service runs under the launcher (github.com/tacplus-dev/launcher): PID 1
# that forwards signals, propagates the exit code, and kills a deadlocked child
# on gRPC health. The fleet's image pipeline puts the binary beside the Dockerfile.
ARG TARGETARCH
COPY launcher-linux-${TARGETARCH} /usr/local/bin/launcher
ENV LAUNCH_CMD="oauth" HEALTH_PORT=8443
ENTRYPOINT ["launcher"]
