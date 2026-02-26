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
   
   **Important:** Run this command from the repository root directory:
   ```bash
   docker build -f processor/certificatehashprocessor/k8s/Dockerfile.certificatehash -t otelcol-certificatehash:latest .
   ```

   The Dockerfile:
   - Uses Go 1.24-alpine as builder
   - Runs `make genotelcontribcol` to generate collector code
   - Runs `make otelcontribcol` to build the binary
   - Creates a minimal alpine image with the collector binary

3. **Load the image into your Kubernetes cluster:**
   
   **For kind clusters:**
   ```bash
   kind load docker-image otelcol-certificatehash:latest --name otel-demo
   ```
   
   Note: If your cluster has a different name, replace `otel-demo` with your cluster name. Check cluster names with `kind get clusters`.
   
   **For minikube clusters:**
   ```bash
   minikube image load otelcol-certificatehash:latest
   ```
   
   **For other local clusters:**
   - Ensure `imagePullPolicy: Never` is set in your deployment YAML
   - The image should be available if Docker is shared with the cluster

4. **Verify the image:**
   ```bash
   docker images | grep otelcol-certificatehash
   ```

## Troubleshooting

- **Build fails with "unknown type certificatehash":**
  - Ensure the processor is added to `builder-config.yaml`
  - Run `make genotelcontribcol` manually to regenerate code

- **Image not found in cluster:**
  - For kind: Use `kind load docker-image otelcol-certificatehash:latest --name <cluster-name>`
  - For minikube: Use `minikube image load otelcol-certificatehash:latest`
  - For other clusters: Push to a registry or use `imagePullPolicy: Never`
