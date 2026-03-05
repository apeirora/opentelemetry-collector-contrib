# OTLP Examples for Audit Log Receiver

This directory contains examples demonstrating how to send OTLP (OpenTelemetry Protocol) requests to the audit log receiver.

## Files

- `otlp_request_example.go` - Comprehensive Go example showing different types of OTLP requests
- `test_otlp_client.go` - Test client that validates OTLP functionality
- `otlp_curl_examples.md` - Examples using curl, HTTPie, and other HTTP clients
- `README.md` - This file

## Quick Start

### 1. Run the Comprehensive Example

```bash
go run examples/otlp_request_example.go
```

This will create and send various types of OTLP requests to demonstrate the receiver's capabilities.

### 2. Run the Test Client

```bash
go run examples/test_otlp_client.go
```

This will test all supported endpoints with different scenarios.

### 3. Manual Testing with curl

```bash
# Generate OTLP data first
go run examples/otlp_request_example.go > /dev/null

# Send a simple request (you'll need to create the protobuf data)
curl -X POST http://localhost:4310/v1/logs \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @otlp_data.bin
```

## Supported Endpoints

The receiver supports these OTLP endpoints:

- `POST /v1/logs` - Standard OTLP logs endpoint
- `POST /v1/logs/` - OTLP logs endpoint with trailing slash  
- `POST /v1/logs/export` - OTLP logs export endpoint

## Content Types

The receiver accepts these content types for OTLP requests:

- `application/x-protobuf`
- `application/vnd.google.protobuf`

## Example Request Structure

An OTLP request contains:

1. **Resource Attributes** - Service-level metadata
2. **Scope Attributes** - Logger/component metadata  
3. **Log Records** - Individual log entries with:
   - Body (message)
   - Severity level
   - Timestamp
   - Attributes

## Response Format

- **Success (200 OK)**: Empty OTLP ExportResponse
- **Error (400 Bad Request)**: Error message for invalid protobuf
- **Error (500 Internal Server Error)**: Error message for processing failures

## Testing with OpenTelemetry SDKs

You can also test using official OpenTelemetry SDKs in various languages:

### Go SDK
```go
import (
    "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
)
```

### Java SDK
```java
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
```

### Python SDK
```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure the receiver is running on the correct port
2. **Content-Type Error**: Use `application/x-protobuf` header
3. **Invalid Protobuf**: Ensure data is valid OTLP protobuf format
4. **Timeout**: Check receiver processing time

### Debug Mode

Enable debug logging in the receiver configuration:

```yaml
receivers:
  auditlogreceiver:
    endpoint: ":4310"
    log_level: debug
```

### Validation

Use the OpenTelemetry Collector's validation tools:

```bash
otelcol-contrib --config=config.yaml --dry-run
```

## Advanced Examples

### Custom Resource Attributes

```go
resourceAttrs := resourceLogs.Resource().Attributes()
resourceAttrs.PutStr("service.name", "audit-service")
resourceAttrs.PutStr("service.version", "1.0.0")
resourceAttrs.PutStr("deployment.environment", "production")
```

### Custom Scope Attributes

```go
scopeAttrs := scopeLogs.Scope().Attributes()
scopeAttrs.PutStr("scope.name", "audit-logger")
scopeAttrs.PutStr("scope.version", "2.1.0")
```

### Different Severity Levels

```go
logRecord.SetSeverityNumber(plog.SeverityNumberInfo)  // INFO
logRecord.SetSeverityNumber(plog.SeverityNumberWarn)  // WARN
logRecord.SetSeverityNumber(plog.SeverityNumberError) // ERROR
logRecord.SetSeverityNumber(plog.SeverityNumberFatal)  // FATAL
```

## Performance Testing

For performance testing, you can:

1. Use the test client with multiple concurrent requests
2. Implement rate limiting in your client
3. Monitor receiver metrics and logs
4. Test with different payload sizes

## Integration Examples

### With OpenTelemetry Collector

```yaml
receivers:
  auditlogreceiver:
    endpoint: ":4310"

processors:
  batch:

exporters:
  logging:
    loglevel: debug

service:
  pipelines:
    logs:
      receivers: [auditlogreceiver]
      processors: [batch]
      exporters: [logging]
```

### With Jaeger

```yaml
receivers:
  auditlogreceiver:
    endpoint: ":4310"

exporters:
  jaeger:
    endpoint: jaeger:14250

service:
  pipelines:
    logs:
      receivers: [auditlogreceiver]
      exporters: [jaeger]
```

This provides a complete example of how to integrate the audit log receiver with other OpenTelemetry components.
