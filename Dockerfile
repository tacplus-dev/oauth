# Fleetwood Release Image
# Layers the pre-built fleetwood binary onto a minimal runtime image.

FROM registry.gitlab.com/secondstarcavalier/controlplane/containers/cavalier-debian:latest

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

COPY target/release/fleetwood /usr/local/bin/fleetwood
RUN chmod +x /usr/local/bin/fleetwood

ENTRYPOINT ["fleetwood"]
