# Certificate Hash Processor - Kubernetes Deployment

Quick start guide for deploying the certificate hash processor to Kubernetes.

## Quick Start

1. **Build the custom collector image:**
   ```bash
   docker build -f Dockerfile.certificatehash -t otelcol-certificatehash:latest .
   ```

2. **Generate test certificates:**
   ```powershell
   # Use the create-cert.ps1 script in the repo root
   .\create-cert.ps1
   ```

3. **Create Kubernetes secret:**
   ```powershell
   kubectl create secret generic otelcol-test-certs `
     --from-file=cert.pem=./cert.pem `
     --from-file=key.pem=./key.pem `
     --from-file=ca.pem=./ca.pem `
     -n otel-demo
   ```

4. **Deploy the collector:**
   ```bash
   kubectl apply -f processor/certificatehashprocessor/k8s/otelcol-certificatehash-debug.yaml
   ```

5. **Test the processor:**
   ```powershell
   .\processor\certificatehashprocessor\k8s\test-send-log.ps1
   ```

6. **Check logs:**
   ```bash
   kubectl logs -n otel-demo -l app=otelcol-certificatehash --tail=50
   ```

## Files

- `otelcol-certificatehash-debug.yaml` - Full deployment with debug exporter
- `otelcol-certificatehash-debug-simple.yaml` - Simplified deployment
- `test-send-log.ps1` - Test script to send OTLP logs
- `BUILD-CUSTOM-IMAGE.md` - Detailed build instructions
- `README-certificatehash-debug.md` - Full deployment guide

## Configuration

The processor adds two attributes to each log record:
- `otel.certificate.hash` - Base64-encoded hash of the log record
- `otel.certificate.signature` - Base64-encoded RSA signature of the hash

## Troubleshooting

See `QUICK-FIX.md` for common issues and solutions.
