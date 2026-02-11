# Integrity Processor

The Integrity processor adds HMAC signatures to log records for tampering detection and data integrity verification. It supports both local secret storage and OpenBao Transit for centralized key management.

## Configuration

```yaml
processors:
  integrity:
    sign:
      algorithm: HMAC-SHA256  # or HMAC-SHA512
      signature_attribute: otel.integrity.signature  # Attribute name to store signature
      include_resource_attributes: true  # Include resource attributes in signature calculation
      
      # Option 1: Local secret (simple, but requires secret management)
      local_secret:
        secret: ${INTEGRITY_SECRET}
      
      # Option 2: OpenBao Transit (recommended for production)
      # openbao_transit:
      #   address: https://openbao.example.com:8200
      #   token: ${OPENBAO_TOKEN}
      #   key_name: otel-hmac-key
      #   mount_path: transit  # Optional, defaults to "transit"
```

## Features

- **HMAC Signing**: Adds HMAC signatures to log records using SHA-256 or SHA-512
- **OpenBao Transit Integration**: Uses OpenBao Transit secrets engine for centralized key management
- **Local Secret Support**: Fallback option using local secrets stored in environment variables
- **Configurable Signature Attribute**: Choose where to store the signature in log attributes
- **Resource Attribute Inclusion**: Option to include resource attributes in signature calculation

## OpenBao Transit Setup

1. Enable the Transit secrets engine:
```bash
openbao secrets enable transit
```

2. Create a signing key:
```bash
openbao write -f transit/keys/otel-hmac-key type=hmac
```

3. Configure the processor with OpenBao credentials:
```yaml
openbao_transit:
  address: https://openbao.example.com:8200
  token: ${OPENBAO_TOKEN}
  key_name: otel-hmac-key
  mount_path: transit
```

## Usage Example

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  integrity:
    sign:
      algorithm: HMAC-SHA256
      signature_attribute: otel.integrity.signature
      openbao_transit:
        address: https://openbao.example.com:8200
        token: ${OPENBAO_TOKEN}
        key_name: otel-hmac-key
        mount_path: transit

exporters:
  otlp:
    endpoint: sink.example.com:4317

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [integrity]
      exporters: [otlp]
```

## Signature Calculation

The processor signs the following log record data:
- Log body
- Severity text and number
- Timestamps (observed and event)
- Trace ID and Span ID
- All log record attributes
- Resource attributes (if `include_resource_attributes` is true)

The signature is stored as a base64-encoded HMAC value in the configured attribute.

## Verification

To verify signatures downstream, you can:
1. Extract the signature from the log attribute
2. Recalculate the HMAC using the same secret/key
3. Compare the signatures to detect tampering

## Security Considerations

- **OpenBao Transit** (Recommended): Provides centralized key management, automatic rotation, and audit logging
- **Local Secrets**: Simpler but requires manual secret management and rotation
- Always use TLS for OpenBao Transit connections
- Store OpenBao tokens securely (environment variables, secret management systems)
- Rotate keys regularly for enhanced security
