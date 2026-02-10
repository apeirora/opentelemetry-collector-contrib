# Building Custom OpenTelemetry Collector Image

The certificate hash processor is a custom component and must be included in a custom collector build.

## Prerequisites

- Docker installed
- Make (for building the collector)

## Build Steps

1. **Ensure the processor is in builder-config.yaml:**
   The processor should be listed in `cmd/otelcontribcol/builder-config.yaml`:
   ```yaml
   processors:
     - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/certificatehashprocessor v0.145.0
   ```

2. **Build the Docker image:**
   ```bash
   docker build -f Dockerfile.certificatehash -t otelcol-certificatehash:latest .
   ```

   The Dockerfile:
   - Uses Go 1.24-alpine as builder
   - Runs `make genotelcontribcol` to generate collector code
   - Runs `make otelcontribcol` to build the binary
   - Creates a minimal alpine image with the collector binary

3. **Load into kind (if using kind cluster):**
   ```bash
   kind load docker-image otelcol-certificatehash:latest
   ```

4. **Verify the image:**
   ```bash
   docker images | grep otelcol-certificatehash
   ```

## Troubleshooting

- **Build fails with "unknown type certificatehash":**
  - Ensure the processor is added to `builder-config.yaml`
  - Run `make genotelcontribcol` manually to regenerate code

- **Image not found in cluster:**
  - For kind: Use `kind load docker-image`
  - For other clusters: Push to a registry or use `imagePullPolicy: Never`
