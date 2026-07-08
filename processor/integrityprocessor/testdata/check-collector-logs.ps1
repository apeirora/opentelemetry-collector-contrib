Write-Host "Collector Diagnostic Checklist" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

Write-Host "1. Check your collector terminal for these messages:" -ForegroundColor Yellow
Write-Host "   - 'Using OpenBao Transit for HMAC signing' (should appear on startup)" -ForegroundColor White
Write-Host "   - 'Failed to sign log record' (if OpenBao signing fails)" -ForegroundColor White
Write-Host "   - Any errors mentioning 'openbao', 'hmac', or 'signature'" -ForegroundColor White
Write-Host ""

Write-Host "2. Verify the pipeline is configured correctly:" -ForegroundColor Yellow
Write-Host "   - Receivers: [otlp]" -ForegroundColor White
Write-Host "   - Processors: [integrity]" -ForegroundColor White
Write-Host "   - Exporters: [debug]" -ForegroundColor White
Write-Host ""

Write-Host "3. Check if OpenBao is accessible from collector:" -ForegroundColor Yellow
$testResult = try {
    $testData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("test"))
    $body = @{ input = $testData; algorithm = "sha2-256" } | ConvertTo-Json
    $result = Invoke-RestMethod -Uri "http://localhost:8200/v1/transit/hmac/otel-hmac-key" -Method Post -Headers @{'X-Vault-Token'='dev-token'; 'Content-Type'='application/json'} -Body $body -ErrorAction Stop
    Write-Host "   ✓ OpenBao is accessible" -ForegroundColor Green
    $true
} catch {
    Write-Host "   ✗ OpenBao connection failed: $_" -ForegroundColor Red
    $false
}

Write-Host ""
Write-Host "4. Test sending a log:" -ForegroundColor Yellow
Write-Host "   Run: .\processor\integrityprocessor\testdata\send-test-log.ps1" -ForegroundColor White
Write-Host ""

Write-Host "5. What to look for in collector output:" -ForegroundColor Yellow
Write-Host "   - After sending a log, you should see debug exporter output" -ForegroundColor White
Write-Host "   - Look for 'ResourceLog', 'LogRecord', and 'Attributes' sections" -ForegroundColor White
Write-Host "   - The 'otel.integrity.signature' attribute should be present" -ForegroundColor White
Write-Host ""

if (-not $testResult) {
    Write-Host "⚠️  OpenBao is not accessible. The integrity processor will fail to sign logs." -ForegroundColor Red
    Write-Host "   Check that OpenBao is running: docker ps | findstr openbao" -ForegroundColor Yellow
}
