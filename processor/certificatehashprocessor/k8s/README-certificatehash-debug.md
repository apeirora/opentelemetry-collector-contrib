# Certificate Hash Processor - Deployment Guide

This guide explains how to deploy the certificate hash processor with a debug exporter to a Kubernetes cluster.

## Overview

The certificate hash processor adds cryptographic integrity verification to log records by:
- Computing a hash (SHA-256 or SHA-512) of each log record
- Signing the hash with an RSA private key
- Adding `otel.certificate.hash` and `otel.certificate.signature` attributes

## Prerequisites

- Kubernetes cluster (kind, minikube, or cloud cluster)
- kubectl configured
- Docker (for building custom image)
- Certificates (cert.pem, key.pem, ca.pem)

## Step 1: Build Custom Collector Image

The standard OpenTelemetry Collector image doesn't include custom processors. Build a custom image:

```bash
docker build -f Dockerfile.certificatehash -t otelcol-certificatehash:latest .
```

For kind clusters:
```bash
kind load docker-image otelcol-certificatehash:latest
```

See `BUILD-CUSTOM-IMAGE.md` for detailed instructions.

## Step 2: Generate Certificates

Generate test certificates using the `create-cert.ps1` script in the repo root, or use your own certificates.

## Step 3: Create Kubernetes Secret

```powershell
kubectl create namespace otel-demo
kubectl create secret generic otelcol-test-certs `
  --from-file=cert.pem=./cert.pem `
  --from-file=key.pem=./key.pem `
  --from-file=ca.pem=./ca.pem `
  -n otel-demo
```

## Step 4: Deploy Collector

```bash
kubectl apply -f processor/certificatehashprocessor/k8s/otelcol-certificatehash-debug.yaml
```

## Step 5: Verify Deployment

```bash
kubectl get pods -n otel-demo
kubectl logs -n otel-demo -l app=otelcol-certificatehash
```

## Step 6: Test the Processor

Use the test script:
```powershell
.\processor\certificatehashprocessor\k8s\test-send-log.ps1
```

Or manually port-forward and send logs:
```bash
kubectl port-forward -n otel-demo service/otelcol-certificatehash 4318:4318
```

Then send a test log using curl or the test script.

## Configuration

The processor configuration in the ConfigMap:

```yaml
processors:
  certificatehash:
    hash_algorithm: SHA256  # or SHA512
    cert_path: /etc/certs/cert.pem
    key_path: /etc/certs/key.pem
    ca_path: /etc/certs/ca.pem
```

## Expected Output

When logs are processed, you should see in the collector logs (debug exporter output) that each log record has:
- `otel.certificate.hash` - Base64-encoded hash
- `otel.certificate.signature` - Base64-encoded RSA signature

## Troubleshooting

- **Pod crashes:** Check certificate paths and file permissions
- **Processor not found:** Ensure custom image is built and loaded
- **No hash/signature:** Check processor is in the pipeline and certificates are readable

See `QUICK-FIX.md` for more troubleshooting tips.
