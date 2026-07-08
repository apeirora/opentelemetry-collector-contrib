# OTLP Request Examples for Audit Log Receiver

This document provides examples of how to send OTLP requests to the audit log receiver using various methods.

## Prerequisites

- Audit log receiver running on `localhost:4310`
- OTLP protobuf data (you can generate this using the Go example)

## Endpoints

The receiver supports the following OTLP endpoints:
- `POST /v1/logs` - Standard OTLP logs endpoint
- `POST /v1/logs/` - OTLP logs endpoint with trailing slash
- `POST /v1/logs/export` - OTLP logs export endpoint

## Content Types

The receiver accepts the following content types for OTLP requests:
- `application/x-protobuf`
- `application/vnd.google.protobuf`

## Example 1: Basic OTLP Request with curl

```bash
# Generate OTLP protobuf data using the Go example
go run examples/otlp_request_example.go

# Send the request (replace with actual protobuf data)
curl -X POST http://localhost:4310/v1/logs \
  -H "Content-Type: application/x-protobuf" \
  -H "User-Agent: otlp-client/1.0" \
  --data-binary @otlp_data.bin
```

## Example 2: Using HTTPie

```bash
# Install httpie if not already installed
pip install httpie

# Send OTLP request
http POST localhost:4310/v1/logs \
  Content-Type:application/x-protobuf \
  User-Agent:otlp-client/1.0 \
  < otlp_data.bin
```

## Example 3: Using wget

```bash
wget --post-file=otlp_data.bin \
  --header="Content-Type: application/x-protobuf" \
  --header="User-Agent: otlp-client/1.0" \
  -O - http://localhost:4310/v1/logs
```

## Example 4: Using PowerShell (Windows)

```powershell
# Create a simple OTLP request
$headers = @{
    "Content-Type" = "application/x-protobuf"
    "User-Agent" = "otlp-client/1.0"
}

# Send request (replace with actual protobuf data)
Invoke-RestMethod -Uri "http://localhost:4310/v1/logs" -Method POST -Headers $headers -Body (Get-Content "otlp_data.bin" -Raw -Encoding Byte)
```

## Example 5: Using Python requests

```python
import requests

# Load OTLP protobuf data
with open('otlp_data.bin', 'rb') as f:
    data = f.read()

# Send request
response = requests.post(
    'http://localhost:4310/v1/logs',
    data=data,
    headers={
        'Content-Type': 'application/x-protobuf',
        'User-Agent': 'otlp-client/1.0'
    }
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
```

## Example 6: Using Node.js

```javascript
const fs = require('fs');
const https = require('https');

// Load OTLP protobuf data
const data = fs.readFileSync('otlp_data.bin');

const options = {
  hostname: 'localhost',
  port: 4310,
  path: '/v1/logs',
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-protobuf',
    'User-Agent': 'otlp-client/1.0',
    'Content-Length': data.length
  }
};

const req = https.request(options, (res) => {
  console.log(`Status: ${res.statusCode}`);
  console.log(`Headers: ${JSON.stringify(res.headers)}`);
  
  res.on('data', (chunk) => {
    console.log(`Response: ${chunk}`);
  });
});

req.on('error', (e) => {
  console.error(`Problem with request: ${e.message}`);
});

req.write(data);
req.end();
```

## Response Format

The receiver responds with OTLP protobuf format:

- **Success (200 OK)**: Returns empty OTLP ExportResponse
- **Error (400 Bad Request)**: Returns error message for invalid protobuf
- **Error (500 Internal Server Error)**: Returns error message for processing failures

## Testing with OpenTelemetry SDK

You can also test using the official OpenTelemetry SDKs:

### Go SDK Example

```go
package main

import (
    "context"
    "log"
    "time"

    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
    "go.opentelemetry.io/otel/log"
    "go.opentelemetry.io/otel/sdk/log"
)

func main() {
    // Create OTLP HTTP exporter
    exporter, err := otlploghttp.New(
        context.Background(),
        otlploghttp.WithEndpoint("http://localhost:4310"),
        otlploghttp.WithURLPath("/v1/logs"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create logger provider
    loggerProvider := log.NewLoggerProvider(
        log.WithBatcher(exporter),
    )

    // Create logger
    logger := loggerProvider.Logger("audit-service")

    // Emit log record
    logger.Emit(context.Background(), log.Record{
        Timestamp: time.Now(),
        Severity:  log.SeverityInfo,
        Body:      log.StringValue("User authentication successful"),
    })

    // Shutdown
    loggerProvider.Shutdown(context.Background())
}
```

### Java SDK Example

```java
import io.opentelemetry.api.logs.Logger;
import io.opentelemetry.api.logs.LoggerProvider;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.export.BatchLogRecordProcessor;

public class AuditLogExample {
    public static void main(String[] args) {
        // Create OTLP HTTP exporter
        OtlpHttpLogRecordExporter exporter = OtlpHttpLogRecordExporter.builder()
            .setEndpoint("http://localhost:4310/v1/logs")
            .build();

        // Create logger provider
        LoggerProvider loggerProvider = SdkLoggerProvider.builder()
            .addLogRecordProcessor(BatchLogRecordProcessor.builder(exporter).build())
            .build();

        // Create logger
        Logger logger = loggerProvider.get("audit-service");

        // Emit log record
        logger.logRecordBuilder()
            .setBody("User authentication successful")
            .setSeverityText("INFO")
            .setSeverityNumber(9) // INFO level
            .emit();

        // Shutdown
        loggerProvider.shutdown();
    }
}
```

## Troubleshooting

### Common Issues

1. **Content-Type Error**: Make sure to set `Content-Type: application/x-protobuf`
2. **Invalid Protobuf**: Ensure the data is valid OTLP protobuf format
3. **Connection Refused**: Verify the receiver is running on the correct port
4. **Timeout**: Check if the receiver is processing requests within the timeout period

### Debugging

Enable debug logging in the receiver to see detailed request processing:

```yaml
# In your collector configuration
receivers:
  auditlogreceiver:
    endpoint: ":4310"
    # Add debug logging
    log_level: debug
```

### Validation

You can validate your OTLP requests using the OpenTelemetry Collector's built-in validation:

```bash
# Use the collector's validation tools
otelcol-contrib --config=config.yaml --dry-run
```
