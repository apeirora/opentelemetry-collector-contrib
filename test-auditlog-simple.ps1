# Simple test script for auditlogreceiver
Write-Host "Testing AuditLog Receiver" -ForegroundColor Green
Write-Host ""

# Build the receiver
Write-Host "Building auditlogreceiver..."
Set-Location receiver/auditlogreceiver
go build -o ../../bin/test-auditlog-receiver.exe .
Set-Location ../..

Write-Host "Build complete!"
Write-Host ""

Write-Host "Test setup complete!"
Write-Host ""
Write-Host "To test your auditlogreceiver:"
Write-Host "1. Run: .\bin\test-auditlog-receiver.exe"
Write-Host "2. In another terminal, run: .\receiver\auditlogreceiver\test\test-request.ps1"
Write-Host ""
Write-Host "Test files are located in:"
Write-Host "   - receiver/auditlogreceiver/test/test-auditlog.go"
Write-Host "   - receiver/auditlogreceiver/test/test-request.ps1"