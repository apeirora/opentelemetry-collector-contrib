# Send one valid and one invalid audit OTLP/JSON log to the local collector.
# Run from repo root with collector up on :4310/auditlogs

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

Write-Host "Generating OTLP JSON payloads..."
go run gen_otlp_payload.go
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$uri = "http://localhost:4310/auditlogs"

Write-Host ""
Write-Host "POST valid audit log (should verify_status=passed)..."
curl.exe -s -w "`nHTTP %{http_code}`n" -X POST $uri `
  -H "Content-Type: application/json" `
  --data-binary "@otlp-valid.json"

Write-Host ""
Write-Host "POST invalid audit log (bad HMAC; should verify_status=failed with failure_mode: mark)..."
curl.exe -s -w "`nHTTP %{http_code}`n" -X POST $uri `
  -H "Content-Type: application/json" `
  --data-binary "@otlp-invalid.json"

Write-Host ""
Write-Host "Done. Check collector logs for verify_status failed on rec-curl-invalid."
