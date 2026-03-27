# Fleetwood Release Image
# Layers the pre-built fleetwood binary onto a minimal runtime image.

FROM debian:trixie-slim

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Second Star Cavalier LLC <cloudctlplane@secondstarcavalier.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Second Star Cavalier LLC" \
      org.opencontainers.image.title="Fleetwood" \
      org.opencontainers.image.description="Session management service for Cavalier control plane"

ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    GRPCURL_VERSION=1.9.3 && \
    curl -sSL "https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_${TARGETARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin grpcurl && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY target/release/fleetwood /usr/local/bin/fleetwood
RUN chmod +x /usr/local/bin/fleetwood

ENTRYPOINT ["fleetwood"]
