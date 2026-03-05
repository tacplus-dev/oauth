# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

ENV GOPRIVATE=gitlab.com/secondstarcavalier/*

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=secret,id=netrc,dst=/root/.netrc go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /sentinel .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S sentinel && adduser -S sentinel -G sentinel

WORKDIR /app

COPY --from=builder /sentinel /app/sentinel

USER sentinel

ENTRYPOINT ["/app/sentinel"]
