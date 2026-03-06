FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S sentinel && adduser -S sentinel -G sentinel

WORKDIR /app

COPY bin/sentinel /app/sentinel

USER sentinel

ENTRYPOINT ["/app/sentinel"]
