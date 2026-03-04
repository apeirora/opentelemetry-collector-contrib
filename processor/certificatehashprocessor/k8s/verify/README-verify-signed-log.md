# Verify Signed Log Script

This script verifies the integrity and authenticity of log records that have been processed by the certificate hash processor.

## Overview

The verification script:
1. Extracts the `otel.certificate.hash` and `otel.certificate.signature` attributes from log records
2. Reconstructs the original log record (without hash/signature attributes)
3. Serializes it the same way the processor does
4. Computes the hash and compares it with the provided hash
5. Verifies the RSA signature using the public key from the certificate

## Prerequisites

- Go compiler (for building the verification tool)
- Certificate file (cert.pem) with the public key
- Log file in JSON format (OTLP format or single log record)
- kubectl configured (if extracting certificates from Kubernetes)

## Extracting Certificates from Kubernetes

Before verifying logs, you may need to extract the certificate from the Kubernetes secret:

```powershell
# Extract all certificates (cert.pem, key.pem, ca.pem)
.\extract-cert-from-k8s.ps1

# Extract only the certificate (for verification)
.\extract-cert-from-k8s.ps1 -CertOnly

# Extract to a specific directory
.\extract-cert-from-k8s.ps1 -OutputDir ".\certs"

# Extract from a different namespace/secret
.\extract-cert-from-k8s.ps1 -Namespace "my-namespace" -SecretName "my-secret" -CertOnly
```

The script will save the extracted certificates to the current directory (or specified output directory).

## Usage

### PowerShell Script (Recommended)

```powershell
# Verify log from file with certificate file
.\verify-signed-log.ps1 -LogFile "log.json" -CertFile "cert.pem"

# Verify with SHA512 algorithm
.\verify-signed-log.ps1 -LogFile "log.json" -CertFile "cert.pem" -HashAlgorithm SHA512

# Verify with verbose output
.\verify-signed-log.ps1 -LogFile "log.json" -CertFile "cert.pem" -Verbose

# Fetch certificate from Kubernetes secret and verify
.\verify-signed-log.ps1 -LogFile "log.json" -FromK8s -Namespace otel-demo -SecretName otelcol-test-certs
```

### Go Script Directly

```bash
# Build the tool
go build -o verify-signed-log.exe verify-signed-log.go

# Verify log
.\verify-signed-log.exe -log log.json -cert cert.pem

# Verify with SHA512
.\verify-signed-log.exe -log log.json -cert cert.pem -hash SHA512

# Verify with verbose output
.\verify-signed-log.exe -log log.json -cert cert.pem -verbose

# Read from stdin
cat log.json | .\verify-signed-log.exe -log - -cert cert.pem
```

## Log File Format

The script accepts log files in two formats:

### OTLP Format (from collector debug exporter)
```json
{
  "resourceLogs": [
    {
      "scopeLogs": [
        {
          "logRecords": [
            {
              "body": "Test log message",
              "attributes": {
                "otel.certificate.hash": "base64-encoded-hash",
                "otel.certificate.signature": "base64-encoded-signature",
                "other.attribute": "value"
              },
              "timestamp": 1234567890000000000,
              "severity_number": 9,
              "severity_text": "INFO"
            }
          ]
        }
      ]
    }
  ]
}
```

### Single Log Record Format
```json
{
  "body": "Test log message",
  "attributes": {
    "otel.certificate.hash": "base64-encoded-hash",
    "otel.certificate.signature": "base64-encoded-signature",
    "other.attribute": "value"
  },
  "timestamp": 1234567890000000000,
  "severity_number": 9,
  "severity_text": "INFO"
}
```

## Output

The script will output:
- ✅ Success message for each verified log record
- ❌ Error messages for failed verifications
- Detailed information when using `-verbose` flag

Example output:
```
✅ Log record 1: Hash and signature verified successfully
✅ Log record 2: Hash and signature verified successfully

✅ All log records verified successfully!
```

## How It Works

1. **Hash Verification**: The script reconstructs the log record exactly as it was when hashed by the processor (excluding the hash and signature attributes), serializes it to JSON, and computes the hash using the same algorithm (SHA256 or SHA512). It then compares this computed hash with the `otel.certificate.hash` attribute.

2. **Signature Verification**: The script decodes the base64-encoded signature from `otel.certificate.signature`, then uses RSA PKCS1v15 verification with the public key from the certificate to verify that the signature was created by the holder of the corresponding private key.

## Troubleshooting

### Hash Mismatch
- Ensure the hash algorithm matches what was used by the processor (default is SHA256)
- Check that the log record hasn't been modified after signing
- Verify that the serialization format matches (the script uses the same logic as the processor)

### Signature Verification Failed
- Ensure you're using the correct certificate (the one matching the private key used for signing)
- Check that the certificate file is in PEM format
- Verify the certificate contains an RSA public key

### Certificate Errors
- Ensure the certificate file path is correct
- Check that the certificate is in PEM format (starts with `-----BEGIN CERTIFICATE-----`)
- Verify the certificate hasn't been corrupted

## Integration with Collector Logs

To verify logs from the collector's debug exporter:

```powershell
# Step 1: Extract certificate from Kubernetes
.\extract-cert-from-k8s.ps1 -CertOnly

# Step 2: Get logs from collector
kubectl logs -n otel-demo -l app=otelcol-certificatehash --tail=100 > collector-logs.txt

# Step 3: Extract JSON log records (you may need to parse the collector output)
# Then verify with the script
.\verify-signed-log.ps1 -LogFile "extracted-log.json" -CertFile "cert.pem"
```

Or use the `-FromK8s` flag to automatically fetch the certificate:

```powershell
# Verify logs and fetch certificate from K8s automatically
.\verify-signed-log.ps1 -LogFile "extracted-log.json" -FromK8s
```

## Notes

- The script verifies each log record independently
- Multiple log records can be verified in a single run
- The script exits with code 0 if all records verify successfully, otherwise exits with code 1
