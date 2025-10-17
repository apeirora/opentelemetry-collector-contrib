Write-Host "🔧 Building auditlogreceiver..."
Set-Location receiver/auditlogreceiver
go build -o ../../bin/test-receiver.exe .
Set-Location ../..

Write-Host "✅ Build complete!"
Write-Host ""
Write-Host "📋 Your auditlogreceiver is ready to test!"
Write-Host "Configuration file: ./bin/otelcol-contrib.yaml"
Write-Host "Expected endpoint: http://localhost:4310/v1/logs"
Write-Host ""
Write-Host "To test:"
Write-Host "1. Download or build the OpenTelemetry Collector"
Write-Host "2. Run: otelcol-contrib --config ./bin/otelcol-contrib.yaml"
Write-Host "3. Send POST request to http://localhost:4310/v1/logs with JSON data"
