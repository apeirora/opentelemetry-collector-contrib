# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS builder

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    ./internal/buildscripts/ocb-add-replaces.sh otelauditcol && \
    CGO_ENABLED=0 GOOS=linux go run go.opentelemetry.io/collector/cmd/builder \
      --config cmd/otelauditcol/builder-config-replaced.yaml

FROM alpine:3.21@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS certs
RUN apk --update --no-cache add ca-certificates

FROM scratch

ARG USER_UID=10001
ARG USER_GID=10001
USER ${USER_UID}:${USER_GID}

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /src/cmd/otelauditcol/otelauditcol /otelauditcol

EXPOSE 4310
ENTRYPOINT ["/otelauditcol"]
CMD ["--config", "/etc/otel/config.yaml"]
