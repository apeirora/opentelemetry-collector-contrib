# Certificate Log Verify Processor

The Certificate Log Verify Processor verifies Tier-2 audit log records by recomputing a JCS-canonical payload and checking `audit.integrity.value` against a configured HMAC key and/or certificate public key.

## Overview

This processor:
- Canonicalizes each log record using JCS (JSON Canonicalization Scheme)
- Verifies `audit.integrity.value` using HMAC or asymmetric signature algorithms
- Optionally validates hash-chain continuity (`audit.prev.hash`, `audit.sequence.number`) via storage
- Stamps verification outcome attributes on each record (`verify_status`, `tier2_status`, etc.)

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

Component type: `certificatelogverify`.

#### Processor settings

| Setting | Default | Description |
|---------|---------|-------------|
| `mode` | `sync` | `sync` verifies each record; `deferred` skips verification and marks records as deferred |
| `failure_mode` | `strict` | `strict` drops failed records and fails the pipeline; `mark` annotates failures and continues |
| `verification_profile` | `default` | Label written to `verification_profile` on each record; does not change verification logic |
| `hmac_key_file` | — | Path to HMAC key file (required in `sync` mode unless cert or k8s key is set) |
| `cert_file` | — | Path to PEM certificate for RSA/ECDSA verification |
| `hash_chain.enabled` | `false` | Enable sequence and previous-hash chain validation |
| `hash_chain.storage` | — | Storage extension ID (required when `hash_chain.enabled` is true) |

#### Dead letter queue (`dead_letter`)

Failed verification records can be persisted to any [storage extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/storage): `file_storage`, `redis_storage`, `db_storage` (SQLite, PostgreSQL, etc.).

| Setting | Default | Description |
|---------|---------|-------------|
| `dead_letter.enabled` | `false` | Enable dead letter persistence for verification failures |
| `dead_letter.storage` | — | Storage extension ID (required when enabled) |
| `dead_letter.key_prefix` | `dead_letter/` | Key prefix for stored entries |
| `dead_letter.include_record` | `true` | Store OTLP JSON for the failed log record |
| `dead_letter.include_resource` | `true` | Store OTLP JSON for the resource attributes |
| `dead_letter.reasons` | all | Only store failures matching these `verify_reason` values (empty = all) |
| `dead_letter.failure_modes` | `strict`, `mark` | Store failures only when processor `failure_mode` is in this list |
| `dead_letter.max_entry_size_bytes` | `0` | Reject DLQ writes above this size (`0` = unlimited) |
| `dead_letter.fail_on_storage_error` | `false` | Fail the pipeline when DLQ storage write fails |
| `dead_letter.partition_by_stream` | `false` | Key layout `prefix/{audit.source.id}/{entry_id}` |
| `dead_letter.deduplicate_by_record_id` | `false` | Use `audit.record.id` as key instead of a new UUID (overwrites prior entry) |
| `dead_letter.maintain_index` | `false` | Maintain `__dead_letter_index__` list of keys for enumeration |
| `dead_letter.ttl` | `0` | Optional expiry hint written into each entry (`0` = none); **does not delete keys** — use an external sweeper |

Each dead letter entry is JSON with metadata (`verify_reason`, `verify_details`, `audit_record_id`, `stream_id`, etc.) plus optional OTLP payloads for replay or inspection.

#### DLQ operator pitfalls

These are design constraints, not verification bugs. See also `AUDITLOG_PIPELINE_PITFALLS.md` §3.13.

| Pitfall | What happens | Operator action |
|---------|--------------|-----------------|
| `fail_on_storage_error: false` (default) | DLQ write error is logged; pipeline may still return 400 or continue without a stored copy | Set `fail_on_storage_error: true` when DLQ loss is unacceptable |
| `deduplicate_by_record_id: true` | Key is `audit.record.id`; **overwrites** prior entry for the same ID | Keep `false` unless last-failure-wins is intended; requires `audit.record.id` |
| `partition_by_stream: true` | Key is `prefix/{audit.source.id}/{id}` | Enable only when `audit.source.id` is always present |
| `maintain_index: true` | Maintains `__dead_letter_index__` via read-modify-write; not safe across replicas | Keep `false` in HA; enumerate with storage `SCAN` on `key_prefix` |
| `ttl` set | `ttl` field in JSON only — **no auto-expiry** in Redis/file storage | Run external cleanup by `stored_at` or `ttl` hint |
| `max_entry_size_bytes` | Oversized JSON rejected; may fail pipeline if `fail_on_storage_error: true` | Cap size; set `include_record: false` for large bodies |
| Shared backend | WAL, hash chain, and DLQ keys can collide without prefixes / separate db | Use `key_prefix: audit_verify_dlq/` and separate Redis db (see `example-config.yaml`) |

Use `dead_letter.reasons` to filter which failures are stored. When omitted or empty, all failure reasons are stored. See [§3.14 in pitfalls doc](../../AUDITLOG_PIPELINE_PITFALLS.md) for filter semantics. Possible `verify_reason` values:

| Reason | When it occurs |
|--------|----------------|
| `missing_integrity_value` | `audit.integrity.value` is missing on the log record |
| `missing_integrity_algorithm` | `audit.integrity.algorithm` is missing on the resource |
| `canonicalization_failed` | JCS canonicalization of the audit record failed |
| `canonical_payload_empty` | Canonical audit payload is empty after serialization |
| `unsupported_integrity_algorithm` | `audit.integrity.algorithm` is not a supported value |
| `hmac_key_unavailable` | HMAC algorithm required but no HMAC key is configured |
| `certificate_unavailable` | Signature algorithm required but no certificate is configured |
| `invalid_integrity_encoding` | `audit.integrity.value` is not valid hex or base64 |
| `hmac_compute_failed` | Internal error while computing HMAC |
| `hash_compute_failed` | Internal error while computing content hash for signature verification |
| `integrity_mismatch` | HMAC or signature does not match the canonical payload |
| `missing_stream_id` | Hash chain enabled but `audit.source.id` is missing |
| `hash_chain_storage_error` | Hash chain state could not be read from storage |
| `prev_hash_mismatch` | `audit.prev.hash` does not match the previous record in the chain |
| `sequence_not_increasing` | `audit.sequence.number` is not greater than the previous sequence |
| `unexpected_prev_hash` | `audit.prev.hash` is set but no prior record exists for the stream |
| `hash_chain_compute_failed` | Integrity hash for hash-chain commit could not be computed |

#### Kubernetes secret source (`k8s_secret`)

| Setting | Default | Description |
|---------|---------|-------------|
| `k8s_secret.name` | — | Secret name (required when using k8s) |
| `k8s_secret.namespace` | `default` | Secret namespace |
| `k8s_secret.hmac_key_entry` | — | Secret key containing the HMAC key |
| `k8s_secret.cert_key` | — | Secret key containing the certificate PEM |

In `sync` mode, at least one key source must be configured: `hmac_key_file`, `cert_file`, or `k8s_secret` with `hmac_key_entry` and/or `cert_key`. `deferred` mode does not require keys.

#### Example configuration

```yaml
processors:
  certificatelogverify:
    mode: sync
    failure_mode: strict
    verification_profile: default
    hmac_key_file: /etc/otel/hmac.key
    cert_file: /etc/otel/cert.pem
    hash_chain:
      enabled: false
      storage: file_storage
    dead_letter:
      enabled: true
      storage: file_storage
      key_prefix: audit_verify_dlq/
      reasons:
        - integrity_mismatch
        - missing_integrity_value
      partition_by_stream: true
      fail_on_storage_error: true
```

Dead letter with PostgreSQL via `db_storage`:

```yaml
extensions:
  db_storage:
    driver: pgx
    datasource: postgres://user:pass@localhost:5432/otel?sslmode=disable

processors:
  certificatelogverify:
    mode: sync
    failure_mode: mark
    hmac_key_file: /etc/otel/hmac.key
    dead_letter:
      enabled: true
      storage: db_storage
      key_prefix: audit_verify_dlq/
      maintain_index: true
      max_entry_size_bytes: 1048576

service:
  extensions: [db_storage]
```

Or with Kubernetes secrets:

```yaml
processors:
  certificatelogverify:
    mode: sync
    failure_mode: strict
    k8s_secret:
      name: otelcol-test-certs
      namespace: otel-demo
      hmac_key_entry: hmac.key
      cert_key: cert.pem
```

#### Not configurable in the processor

The following are **not** processor config fields. They are determined by log/resource attributes and fixed canonicalization logic:

- **Integrity algorithm** — read from resource attribute `audit.integrity.algorithm`
- **Signed content** — fixed JCS canonical form over audit fields, timestamps, body, and non-integrity attributes (see How It Works)

Supported `audit.integrity.algorithm` values:

| Algorithm | Key source required |
|-----------|---------------------|
| `HMAC-SHA256` | HMAC key |
| `HMAC-SHA512` | HMAC key |
| `ECDSA-P256-SHA256` | Certificate |
| `RSA-PKCS1-SHA256` | Certificate |

To update Kubernetes configuration:

```bash
# Edit configmap.yaml, then apply
kubectl apply -f configmap.yaml

# Restart the deployment to pick up changes
kubectl rollout restart deployment/otelcol-certificatelogverify -n otel-demo
```

## Key and certificate loading

HMAC keys and verification certificates are loaded **once at processor startup** (sync mode). There is **no hot reload** — updating `hmac_key_file`, `cert_file`, or a mounted Kubernetes secret does not affect a running collector until it restarts.

On startup the processor logs:

- `Loaded HMAC key for audit log verification` (with `source`)
- `Loaded certificate for audit log signature verification` (with `source`)
- `Audit integrity verification ready` with `hmac_key_loaded`, `certificate_loaded`, and `supported_algorithms`

If only one key type is configured, a **Warn** lists algorithms that will be rejected at ingest (configure both HMAC key and cert when apps may use either).

**Key rotation runbook**

1. Update the secret or key file (same material the SDK will use to sign).
2. **Rolling restart** collector pods so each instance reloads keys at startup.
3. Roll SDK/applications to the same new key.

Coordinate SDK and collector rotation: if apps sign with a new key before collectors restart, records fail verify with `integrity_mismatch` until pods pick up the new material.

## How It Works

1. **Key loading**: On startup in `sync` mode only — see [Key and certificate loading](#key-and-certificate-loading). No periodic reload.
2. **Canonicalization**: Builds a fixed JCS payload from timestamp, observed timestamp, event name, standard `audit.*` fields, log body, and all attributes except `audit.integrity.*`. See [Canonical attribute encoding](#canonical-attribute-encoding).
3. **Integrity verification**: Reads `audit.integrity.algorithm` from the resource and `audit.integrity.value` from the record, then verifies HMAC or signature against the canonical payload.
4. **Hash chain** (optional): When enabled, validates `audit.prev.hash` and `audit.sequence.number` per `audit.source.id` stream using configured storage.
5. **Outcome attributes**: Sets `verify_status`, `verify_reason`, `tier2_status`, `verification_profile`, and related fields on each record.
6. **Dead letter** (optional): When enabled, failed records are serialized to configured storage before pipeline rejection/continuation.
7. **Failure handling**:
   - `failure_mode: strict` — failed records are removed; pipeline returns a permanent error containing `rejected_verify_failed`
   - `failure_mode: mark` — failed records are annotated and passed downstream

## Canonical attribute encoding

JCS signing includes custom log attributes in an `attributes` array. Each value is converted with `canonicalAttrString` (`jcs_audit.go`) using the same rules as the Go SDK `log.Value.String()` for primitives:

| OTLP type | Canonical string |
|-----------|------------------|
| String | as-is |
| Int | decimal (`strconv.FormatInt`) |
| Bool | `true` / `false` |
| Double | `%g` format (`strconv.FormatFloat`) |

**Contract (Tier-2):** Prefer **string** attributes for custom signed fields when using `go.opentelemetry.io/otel/sdk/auditlog`. The SDK exports audit fields as strings by default. Int/bool/double are supported when OTLP types match what the signer used; map/slice/bytes encoding is not a supported signing contract — use strings for custom metadata.

`audit.sequence.number` remains a JSON **number** in the canonical payload (not stringified).

## Integrity value encoding

`audit.integrity.value` holds the HMAC or signature bytes as a string (not part of the JCS signed payload). The processor decodes with `decodeHexOrBase64` (`audit_verify.go`): **hex first**, then **base64**.

| Source | Encoding |
|--------|----------|
| Go SDK (`go.opentelemetry.io/otel/sdk/auditlog`) | **Base64** (default) |
| Processor | Accepts **hex or base64** |

Use **base64** in production to match the SDK. Hex is supported for tests and custom signers. Invalid encoding → `invalid_integrity_encoding`; wrong proof → `integrity_mismatch`.

## Post-verify outcome attributes

After verification, the processor **mutates** each record and adds outcome metadata (not part of the signed JCS payload). Outcome keys are excluded from canonicalization in `jcs_audit.go` (`isExcludedFromJCS`).

| Attribute | Description |
|-----------|-------------|
| `verify_status` | `passed`, `failed`, or `deferred` |
| `verify_reason` | Machine-readable reason (e.g. `ok`, `integrity_mismatch`) |
| `verify_details` | Error details when verification fails |
| `verified_at` | RFC3339 timestamp of verification (empty when deferred) |
| `verification_profile` | Copy of configured `verification_profile` |
| `tier2_status` | Tier-2 lifecycle status (e.g. `verified_queued`, `rejected_verify_failed`) |
| `export_status_overall` | Mirrors `tier2_status` for export routing |
| `last_state_change_at` | RFC3339 timestamp when outcome attrs were written |

**Sink contract:** expect these fields on exported audit records. With `failure_mode: mark`, filter on `verify_status` / `tier2_status` before durable storage if you only want verified records.

## Expected Log Attributes

### Required

| Attribute | Location | Description |
|-----------|----------|-------------|
| `audit.integrity.algorithm` | Resource | One of `HMAC-SHA256`, `HMAC-SHA512`, `ECDSA-P256-SHA256`, `RSA-PKCS1-SHA256` |
| `audit.integrity.value` | Log record | HMAC or signature over the JCS canonical payload; **base64** (SDK default) or hex |

### Optional (hash chain)

| Attribute | Location | Description |
|-----------|----------|-------------|
| `audit.source.id` | Log record or resource | Stream identifier for hash-chain state |
| `audit.prev.hash` | Log record | Previous record integrity hash in the chain |
| `audit.sequence.number` | Log record | Monotonic sequence number per stream |

Outcome attributes (`verify_status`, `tier2_status`, etc.) are written by the processor after verification — see [Post-verify outcome attributes](#post-verify-outcome-attributes).

### Written by the processor

| Attribute | Description |
|-----------|-------------|
| `verify_status` | `passed`, `failed`, or `deferred` |
| `verify_reason` | Machine-readable reason (e.g. `ok`, `integrity_mismatch`) |
| `verify_details` | Error details when verification fails |
| `verified_at` | RFC3339 timestamp of verification |
| `verification_profile` | Copy of configured `verification_profile` |
| `tier2_status` | Tier-2 lifecycle status (e.g. `verified_queued`, `rejected_verify_failed`) |
| `export_status_overall` | Mirrors `tier2_status` for export routing |
| `last_state_change_at` | RFC3339 timestamp when outcome attrs were written |

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
- `integrity_mismatch`: Canonical payload or key/cert does not match what the signer used
- `unsupported_integrity_algorithm`: `audit.integrity.algorithm` is missing or not supported
- `missing_integrity_value`: `audit.integrity.value` is absent on the record
- `certificate_unavailable` / `hmac_key_unavailable`: Algorithm requires a key source that is not configured
- `prev_hash_mismatch` / `sequence_not_increasing`: Hash chain validation failed

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

This processor is designed to work with the audit log receiver (`auditlogreceiver`) and an upstream signing component that populates `audit.integrity.*` attributes using the same JCS canonicalization rules.
