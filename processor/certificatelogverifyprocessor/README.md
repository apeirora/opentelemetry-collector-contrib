# Certificate Log Verify Processor

The Certificate Log Verify Processor verifies the integrity and authenticity of log records that have been signed with a certificate. It reads certificate-signed logs, recomputes their hash, and verifies the signature using a certificate stored in Kubernetes secrets.

## Overview

This processor:
- Fetches certificates from Kubernetes secrets
- Verifies log signatures by recomputing hashes based on the signed content (body/meta/attr)
- Validates signatures using RSA public keys from certificates
- Ensures log integrity and authenticity

## Prerequisites

- Go 1.24+ (for building)
- Kubernetes cluster with kubectl configured
- OpenTelemetry Collector Contrib repository
- Certificate and private key files (for creating K8s secrets)

## Building

### Build the Collector with the Processor

From the repository root, build the entire collector with this processor included:

```bash
make otelcontribcol
```

This will create the binary at `bin/otelcontribcol_linux_amd64`.

### Build Docker Image

A Dockerfile is provided in the `k8s/` directory. Build the Docker image from the repository root:

```bash
cd processor/certificatelogverifyprocessor/k8s
docker build -f Dockerfile -t certificatelogverify-collector:latest ../../..
```

Or from the repository root:

```bash
docker build -f processor/certificatelogverifyprocessor/k8s/Dockerfile -t certificatelogverify-collector:latest .
```

The Dockerfile uses a multi-stage build to create a minimal, secure image with the collector binary.

## Kubernetes Deployment

All Kubernetes manifests are provided in the `k8s/` directory. You can deploy everything using the provided scripts or manually with kubectl.

### Deploy to kind (After Building)

If you already built the Docker image locally (for example `certificatelogverify-collector:latest`), load it into your kind cluster before deploying:

```bash
# 1. Make sure your kind cluster exists
kind get clusters

# 2. Load the local image into kind
kind load docker-image certificatelogverify-collector:latest --name kind

# 3. Deploy collector resources
cd processor/certificatelogverifyprocessor/k8s
kubectl apply -k .

# 4. Wait for rollout and inspect logs
kubectl rollout status deployment/otelcol-certificatelogverify -n otel-demo
kubectl logs -n otel-demo -l app=otelcol-certificatelogverify
```

If your kind cluster has a different name, replace `--name kind` with your cluster name.

### Quick Deployment

The easiest way to deploy is using the provided deployment scripts:

**Linux/Mac:**
```bash
cd processor/certificatelogverifyprocessor/k8s
./deploy.sh
```

**Windows (PowerShell):**
```powershell
cd processor\certificatelogverifyprocessor\k8s
.\deploy.ps1
```

### Manual Deployment

#### Step 1: Create Kubernetes Secret

First, create a Kubernetes secret containing your certificate:

```bash
kubectl create namespace otel-demo

kubectl create secret generic otelcol-test-certs \
  --from-file=cert.pem=./cert.pem \
  --from-file=key.pem=./key.pem \
  --from-file=ca.pem=./ca.pem \
  -n otel-demo
```

Or use the provided PowerShell script:

```powershell
.\k8s\create-k8s-secret.ps1
```

#### Step 2: Deploy Kubernetes Resources

All YAML files are provided in the `k8s/` directory:

- `namespace.yaml` - Creates the `otel-demo` namespace
- `rbac.yaml` - ServiceAccount, Role, and RoleBinding for secret access
- `configmap.yaml` - Collector configuration with the certificatelogverify processor
- `deployment.yaml` - Deployment with health checks and resource limits
- `service.yaml` - ClusterIP service exposing OTLP endpoints

Deploy all resources:

```bash
cd processor/certificatelogverifyprocessor/k8s

# Deploy individually
kubectl apply -f namespace.yaml
kubectl apply -f rbac.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Or deploy all at once
kubectl apply -f namespace.yaml -f rbac.yaml -f configmap.yaml -f deployment.yaml -f service.yaml

# Or using kustomize
kubectl apply -k .
```

#### Step 3: Verify Deployment

Check if the pod is running:

```bash
kubectl get pods -n otel-demo -l app=otelcol-certificatelogverify
```

View logs:

```bash
kubectl logs -n otel-demo -l app=otelcol-certificatelogverify
```

Check service:

```bash
kubectl get svc -n otel-demo otelcol-certificatelogverify
```

### Configuration Options

The processor configuration in `configmap.yaml` can be customized. Available options:

- `hash_algorithm`: Hash algorithm used for verification (`SHA256` or `SHA512`). Default: `SHA256`
- `sign_content`: What content was signed (`body`, `meta`, or `attr`). Default: `body`
  - `body`: Only log body
  - `meta`: Body + metadata (timestamp, severity, trace_id, span_id)
  - `attr`: Body + metadata + attributes (excluding `otel.log.*` attributes)
- `k8s_secret`: Kubernetes secret configuration
  - `name`: Secret name (required)
  - `namespace`: Secret namespace (default: `default`)
  - `cert_key`: Key name in secret containing the certificate (required)

To update the configuration:

```bash
# Edit configmap.yaml, then apply
kubectl apply -f configmap.yaml

# Restart the deployment to pick up changes
kubectl rollout restart deployment/otelcol-certificatelogverify -n otel-demo
```

## How It Works

1. **Certificate Loading**: On startup, the processor fetches the certificate from the specified Kubernetes secret
2. **Log Processing**: For each log record, it:
   - Reads `otel.log.hash`, `otel.log.signature`, and `otel.log.sign_content` attributes
   - Uses `sign_content` from the log attribute (set by the signing processor) or falls back to config
   - Recomputes the hash using the same serialization logic as the signing processor
   - Compares the recomputed hash with the received hash
   - Verifies the signature using the certificate's RSA public key
3. **Error Handling**: If verification fails, an error is logged and the log record continues processing

## Expected Log Attributes

The processor expects log records to have these attributes (set by the signing processor):

- `otel.log.hash`: Base64-encoded hash of the serialized log content
- `otel.log.signature`: Base64-encoded RSA signature of the hash
- `otel.log.sign_content`: Indicates what content was signed (`body`, `meta`, or `attr`)

## Troubleshooting

### Secret Not Found

If you see errors about secrets not being found:

```bash
kubectl get secret otelcol-test-certs -n otel-demo
kubectl describe secret otelcol-test-certs -n otel-demo
```

### Permission Denied

Verify RBAC is correctly configured:

```bash
kubectl get role otelcol-secret-reader -n otel-demo
kubectl get rolebinding otelcol-secret-reader -n otel-demo
```

### Verification Failures

Check collector logs for detailed error messages. Common issues:
- Hash mismatch: Signing and verification processors using different `sign_content` values
- Signature verification failed: Certificate mismatch or corrupted signature
- Missing attributes: Logs not processed by the signing processor first

## Example: Complete Deployment

### Using Deployment Scripts (Recommended)

```bash
# 1. Build Docker image
cd processor/certificatelogverifyprocessor/k8s
docker build -f Dockerfile -t certificatelogverify-collector:latest ../..

# 2. Create secret (if not already created)
kubectl create secret generic otelcol-test-certs \
  --from-file=cert.pem=./cert.pem \
  --from-file=key.pem=./key.pem \
  -n otel-demo

# 3. Deploy everything using the script
./deploy.sh  # or .\deploy.ps1 on Windows
```

### Manual Deployment

```bash
cd processor/certificatelogverifyprocessor/k8s

# 1. Create namespace
kubectl apply -f namespace.yaml

# 2. Create secret
kubectl create secret generic otelcol-test-certs \
  --from-file=cert.pem=./cert.pem \
  --from-file=key.pem=./key.pem \
  -n otel-demo

# 3. Deploy all resources
kubectl apply -f rbac.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# 4. Check status
kubectl get pods -n otel-demo
kubectl logs -n otel-demo -l app=otelcol-certificatelogverify
```

### Using Kustomize

```bash
cd processor/certificatelogverifyprocessor/k8s

# Create secret first
kubectl create secret generic otelcol-test-certs \
  --from-file=cert.pem=./cert.pem \
  --from-file=key.pem=./key.pem \
  -n otel-demo

# Deploy everything with kustomize
kubectl apply -k .
```

## Related Components

This processor is designed to work with the certificate signing processor (on branch `signLogsInsideProcesor`) that adds the signature attributes to log records.
