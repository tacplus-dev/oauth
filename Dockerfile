# OAuth Release Image
# Layers the pre-built oauth binary onto a minimal runtime image.

FROM registry.gitlab.com/seabeam/schematic/containers/debian/schematic-debian-1-2:latest

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Seabeam LLC <cloudctlplane@seabeam.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Seabeam LLC" \
      org.opencontainers.image.title="OAuth" \
      org.opencontainers.image.description="Session management service for Schematic control plane"

COPY target/release/oauth /usr/local/bin/oauth

ENTRYPOINT ["oauth"]
