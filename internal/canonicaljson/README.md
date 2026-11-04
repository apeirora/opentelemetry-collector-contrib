# Canonical JSON Serialization

This internal package provides RFC 8785 (JCS) canonical JSON serialization for OpenTelemetry log records. It is used by the signing and verify processors to produce deterministic JSON representations for cryptographic operations.

## Purpose

Canonical JSON serialization is required for cryptographic signing and verification of log records. Unlike standard JSON serialization (including OTLP/JSON), RFC 8785 ensures:

1. **Deterministic output**: Same input always produces identical byte-level output
2. **Lexicographic key ordering**: Map keys are sorted alphabetically
3. **Normalized numbers**: Consistent number representation
4. **No whitespace**: Minimal, predictable formatting

## Features

- ✅ RFC 8785 (JCS) compliant canonical JSON
- ✅ Configurable field exclusion (e.g., `audit.integrity.*` attributes)
- ✅ Configurable depth and size limits
- ✅ UTF-8 validation (prevents canonicalization issues)
- ✅ Type-preserving value encoding (e.g., `{"intValue": "42"}`)
- ✅ Comprehensive test coverage (43 tests)

## Usage

### Basic Serialization

```go
import "github.com/open-telemetry/opentelemetry-collector-contrib/internal/canonicaljson"

opts := canonicaljson.SerializeLogRecordOptions{
    ExcludePrefixes: []string{"audit.integrity."},
}

canonical, err := canonicaljson.SerializeLogRecord(logRecord, opts)
if err != nil {
    // Handle error
}
// canonical is deterministic, RFC 8785 compliant JSON
```

### Custom Limits

```go
opts := canonicaljson.SerializeLogRecordOptions{
    ExcludePrefixes: []string{"audit.integrity.", "audit.verification."},
    MaxDepth:        64,  // Lower depth limit
    MaxInputBytes:   1024 * 1024, // 1 MiB size limit
}
```

### Defaults

```go
// Uses default values if not specified:
// - MaxDepth: 128
// - MaxInputBytes: 2 MiB (1 << 21)
opts := canonicaljson.SerializeLogRecordOptions{
    ExcludePrefixes: []string{"audit.integrity."},
}
```

## Excluded Fields

The following log record fields are **always excluded** from serialization (by design):

- `SeverityNumber` - Should not be set on audit records per spec
- `SeverityText` - Should not be set on audit records per spec  
- `Flags` - W3C trace-context sampling bit (observability, not audit-relevant)

Attributes can be excluded by prefix via `ExcludePrefixes` option.

## Value Encoding

Values are wrapped with type information to preserve exact types during verification:

| pcommon.ValueType | JSON Encoding |
|-------------------|---------------|
| `ValueTypeStr` | `{"stringValue": "text"}` |
| `ValueTypeInt` | `{"intValue": "42"}` |
| `ValueTypeDouble` | `{"doubleValue": 3.14}` |
| `ValueTypeBool` | `{"boolValue": true}` |
| `ValueTypeBytes` | `{"bytesValue": "base64..."}` |
| `ValueTypeSlice` | `[...]` (array of wrapped values) |
| `ValueTypeMap` | `{...}` (map with wrapped values) |
| `ValueTypeEmpty` | `null` |

## Comparison with OTLP/JSON

| Feature | Canonical JSON (RFC 8785) | OTLP/JSON |
|---------|---------------------------|-----------|
| **Purpose** | Cryptographic signing | Telemetry transport |
| **Determinism** | ✅ Guaranteed | ❌ Not guaranteed |
| **Key Ordering** | ✅ Lexicographic | ❌ Unspecified |
| **Value Encoding** | Type-wrapped | Direct |
| **Use Case** | Audit integrity | Data exchange |

Example:

```json
// Canonical JSON (this package)
{
  "attributes": {
    "http.method": {"stringValue": "GET"},
    "http.status_code": {"intValue": "200"}
  },
  "body": {"stringValue": "Request processed"},
  "timestamp": "1234567890123456789"
}

// OTLP/JSON (standard format)
{
  "body": {"stringValue": "Request processed"},
  "timeUnixNano": "1234567890123456789",
  "attributes": [
    {"key": "http.method", "value": {"stringValue": "GET"}},
    {"key": "http.status_code", "value": {"intValue": 200}}
  ]
}
```

## Error Handling

The package returns errors for:

- **Depth limit exceeded**: Nested structures deeper than `MaxDepth`
- **Size limit exceeded**: Serialized JSON larger than `MaxInputBytes`
- **Invalid UTF-8**: Any string with invalid UTF-8 encoding
- **JCS transformation failure**: Internal JCS library error

## Testing

Run tests:

```bash
cd internal/canonicaljson
go test -v ./...
```

Test coverage:

- 25 serialization tests (`serialize_test.go`)
- 13 value conversion tests (`convert_test.go`)
- 5 UTF-8 validation tests (`validate_test.go`)

## Dependencies

- `github.com/gowebpki/jcs` - RFC 8785 JCS transformation
- `go.opentelemetry.io/collector/pdata` - OpenTelemetry data types

## References

- [RFC 8785 - JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785.html)
- [OTLP Specification](https://opentelemetry.io/docs/specs/otlp/)
- [OpenTelemetry Audit Logging](https://github.com/open-telemetry/oteps/blob/main/text/logs/)

## Internal Use Only

This package is in `internal/` and is **not part of the public API**. It is designed for use by:

- `processor/signingprocessor` - Signs log records with cryptographic signatures
- `processor/verifyprocessor` - Verifies cryptographic signatures on log records

External projects should **not** depend on this package. If you need canonical JSON serialization, please file an issue to discuss moving it to `pkg/`.

## License

Copyright The OpenTelemetry Authors  
SPDX-License-Identifier: Apache-2.0
