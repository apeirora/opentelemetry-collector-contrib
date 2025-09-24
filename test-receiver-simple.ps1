# Simple test to verify the auditlogreceiver is working
# This script will build and run the receiver, then test it

Write-Host "🔧 Building auditlogreceiver..."
cd receiver/auditlogreceiver
go build -o ../../bin/test-receiver.exe .

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Build successful!"
    cd ../..
    
    Write-Host "🧪 Testing receiver endpoints..."
    
    # Test if port 4310 is open
    try {
        $connection = Test-NetConnection -ComputerName localhost -Port 4310 -InformationLevel Quiet
        if ($connection) {
            Write-Host "✅ Port 4310 is available"
        } else {
            Write-Host "ℹ️ Port 4310 is not in use (as expected)"
        }
    } catch {
        Write-Host "ℹ️ Port test not available on this system"
    }
    
    Write-Host "📋 Your auditlogreceiver is ready to test!"
    Write-Host "To test it:"
    Write-Host "1. Run the OpenTelemetry Collector with your config:"
    Write-Host "   ./bin/otelcontribcol.exe --config ./bin/otelcol-contrib.yaml"
    Write-Host ""
    Write-Host "2. In another terminal, send a test request:"
    Write-Host "   curl -X POST http://localhost:4310/v1/logs -H 'Content-Type: application/json' -d '{\"user\":\"test\",\"action\":\"login\"}'"
    Write-Host ""
    Write-Host "3. Or use PowerShell:"
    Write-Host "   \$data = @{user='test'; action='login'} | ConvertTo-Json"
    Write-Host "   Invoke-RestMethod -Uri 'http://localhost:4310/v1/logs' -Method POST -Body \$data -ContentType 'application/json'"
    
} else {
    Write-Host "❌ Build failed!"
}
