$ErrorActionPreference = "Stop"

Write-Host "Debugging K8s Secret Data Format" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

$namespace = "otel-demo"
$secretName = "otelcol-test-certs"

$secret = kubectl get secret $secretName -n $namespace -o json | ConvertFrom-Json

Write-Host "Secret keys:" -ForegroundColor Yellow
$secret.data.PSObject.Properties.Name | ForEach-Object {
    Write-Host "  - $_" -ForegroundColor White
}

Write-Host ""
Write-Host "Certificate data (first 200 chars):" -ForegroundColor Yellow
$certBase64 = $secret.data.'cert.pem'
if ($certBase64) {
    try {
        $certBytes = [System.Convert]::FromBase64String($certBase64)
        $certText = [System.Text.Encoding]::UTF8.GetString($certBytes)
        if ($certText.Length -gt 0) {
            Write-Host $certText.Substring(0, [Math]::Min(200, $certText.Length)) -ForegroundColor Gray
        } else {
            Write-Host "  Certificate text is empty after decoding" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Error decoding base64: $_" -ForegroundColor Red
        Write-Host "  Base64 length: $($certBase64.Length)" -ForegroundColor Yellow
        Write-Host "  First 50 chars: $($certBase64.Substring(0, [Math]::Min(50, $certBase64.Length)))" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Certificate data is null or empty" -ForegroundColor Red
}

Write-Host ""
Write-Host "Certificate line endings:" -ForegroundColor Yellow
if ($certText -match "`r`n") {
    Write-Host "  Windows line endings (CRLF) detected" -ForegroundColor Yellow
} elseif ($certText -match "`n") {
    Write-Host "  Unix line endings (LF) detected" -ForegroundColor Green
} else {
    Write-Host "  No line endings detected" -ForegroundColor Red
}

Write-Host ""
Write-Host "Private key data (first 200 chars):" -ForegroundColor Yellow
$keyBase64 = $secret.data.'key.pem'
if ($keyBase64) {
    try {
        $keyBytes = [System.Convert]::FromBase64String($keyBase64)
        $keyText = [System.Text.Encoding]::UTF8.GetString($keyBytes)
        if ($keyText.Length -gt 0) {
            Write-Host $keyText.Substring(0, [Math]::Min(200, $keyText.Length)) -ForegroundColor Gray
        } else {
            Write-Host "  Private key text is empty after decoding" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Error decoding base64: $_" -ForegroundColor Red
        Write-Host "  Base64 length: $($keyBase64.Length)" -ForegroundColor Yellow
        Write-Host "  First 50 chars: $($keyBase64.Substring(0, [Math]::Min(50, $keyBase64.Length)))" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Private key data is null or empty" -ForegroundColor Red
}

Write-Host ""
Write-Host "Private key line endings:" -ForegroundColor Yellow
if ($keyText -match "`r`n") {
    Write-Host "  Windows line endings (CRLF) detected" -ForegroundColor Yellow
} elseif ($keyText -match "`n") {
    Write-Host "  Unix line endings (LF) detected" -ForegroundColor Green
} else {
    Write-Host "  No line endings detected" -ForegroundColor Red
}

Write-Host ""
Write-Host "Certificate PEM header check:" -ForegroundColor Yellow
if ($certText -match "-----BEGIN CERTIFICATE-----") {
    Write-Host "  ✓ Valid PEM header found" -ForegroundColor Green
} else {
    Write-Host "  ✗ Invalid PEM header" -ForegroundColor Red
}

Write-Host ""
Write-Host "Private key PEM header check:" -ForegroundColor Yellow
if ($keyText -match "-----BEGIN.*PRIVATE KEY-----") {
    Write-Host "  ✓ Valid PEM header found" -ForegroundColor Green
    $keyType = if ($keyText -match "-----BEGIN RSA PRIVATE KEY-----") { "RSA PRIVATE KEY" } else { "PRIVATE KEY" }
    Write-Host "  Key type: $keyType" -ForegroundColor Cyan
} else {
    Write-Host "  ✗ Invalid PEM header" -ForegroundColor Red
}
