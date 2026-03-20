# Sentinel Release Image
# Layers the sentinel binary onto a minimal Alpine base.

FROM alpine:3.21

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Second Star Cavalier LLC <cloudctlplane@secondstarcavalier.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Second Star Cavalier LLC" \
      org.opencontainers.image.title="Sentinel" \
      org.opencontainers.image.description="Sentinel monitoring service for Cavalier control plane"

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S sentinel && adduser -S sentinel -G sentinel

ARG TARGETARCH
COPY bin/sentinel-${TARGETARCH} /usr/local/bin/sentinel
RUN chmod +x /usr/local/bin/sentinel

USER sentinel

ENTRYPOINT ["sentinel"]
