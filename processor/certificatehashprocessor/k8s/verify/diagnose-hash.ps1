param(
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "log.json"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Hash Verification Diagnostic ===" -ForegroundColor Cyan
Write-Host ""

$logContent = Get-Content $LogFile -Raw | ConvertFrom-Json

Write-Host "Log Record Data:" -ForegroundColor Yellow
Write-Host "  Body: $($logContent.body)"
Write-Host "  Timestamp: $($logContent.timestamp)"
Write-Host "  Severity Number: $($logContent.severity_number)"
Write-Host "  Severity Text: $($logContent.severity_text)"
Write-Host "  Attributes Count: $(($logContent.attributes.PSObject.Properties | Where-Object { $_.Name -ne 'otel.log.hash' -and $_.Name -ne 'otel.log.signature' }).Count)"
Write-Host ""

Write-Host "Attributes (excluding hash/signature):" -ForegroundColor Yellow
$logContent.attributes.PSObject.Properties | Where-Object { 
    $_.Name -ne 'otel.log.hash' -and $_.Name -ne 'otel.log.signature' 
} | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Value)"
}
Write-Host ""

Write-Host "Hash from log:" -ForegroundColor Yellow
Write-Host "  $($logContent.attributes.'otel.log.hash')"
Write-Host ""

Write-Host "Signature from log:" -ForegroundColor Yellow
Write-Host "  $($logContent.attributes.'otel.log.signature'.Substring(0, [Math]::Min(50, $logContent.attributes.'otel.log.signature'.Length)))..."
Write-Host ""

Write-Host "=== Verification Checklist ===" -ForegroundColor Cyan
Write-Host ""

$checks = @(
    @{ Check = "Body is present and is string"; Status = ($logContent.body -is [string] -and $logContent.body -ne "") },
    @{ Check = "Timestamp is present and non-zero"; Status = ($logContent.timestamp -ne $null -and $logContent.timestamp -ne 0) },
    @{ Check = "Severity number is present"; Status = ($logContent.severity_number -ne $null) },
    @{ Check = "Severity text is present"; Status = ($logContent.severity_text -ne $null -and $logContent.severity_text -ne "") },
    @{ Check = "Hash attribute exists"; Status = ($logContent.attributes.'otel.log.hash' -ne $null) },
    @{ Check = "Signature attribute exists"; Status = ($logContent.attributes.'otel.log.signature' -ne $null) },
    @{ Check = "Other attributes present"; Status = (($logContent.attributes.PSObject.Properties | Where-Object { $_.Name -ne 'otel.log.hash' -and $_.Name -ne 'otel.log.signature' }).Count -gt 0) }
)

foreach ($check in $checks) {
    $status = if ($check.Status) { "[OK]" } else { "[FAIL]" }
    $color = if ($check.Status) { "Green" } else { "Red" }
    Write-Host "  $status $($check.Check)" -ForegroundColor $color
}

Write-Host ""
Write-Host "=== Next Steps ===" -ForegroundColor Cyan
Write-Host "1. Verify the hash in log.json matches the hash from the collector output"
Write-Host "2. Ensure all fields match exactly what was in the original log"
Write-Host "3. Check if the log.json was created from the correct log record"
Write-Host ""
Write-Host "Run verification:" -ForegroundColor Yellow
Write-Host "  .\verify-signed-log.ps1" -ForegroundColor White
