FROM alpine:latest@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 AS prep
RUN apk --update add ca-certificates

FROM alpine:latest@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

ARG USER_UID=10001
ARG USER_GID=10001

# Create storage directory and set permissions
RUN mkdir -p /var/lib/otelcol/storage && \
    chown -R ${USER_UID}:${USER_GID} /var/lib/otelcol

USER ${USER_UID}:${USER_GID}

COPY --from=prep /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY bin/otelcontribcol_linux_amd64 /otelcontribcol
COPY auditlog-config.yaml /etc/otel/config.yaml
EXPOSE 8080 4317 4318
ENTRYPOINT ["/otelcontribcol"]
CMD ["--config", "/etc/otel/config.yaml"]
