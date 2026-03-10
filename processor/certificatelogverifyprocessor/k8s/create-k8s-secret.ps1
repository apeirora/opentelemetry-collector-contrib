$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Create K8s Secret for Certificates" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$namespace = "otel-demo"
$secretName = "otelcol-test-certs"

Write-Host "Step 1: Generate certificates and create Kubernetes secret..." -ForegroundColor Yellow
Push-Location $PSScriptRoot\..\..\..
if (Test-Path "create-cert.ps1") {
    .\create-cert.ps1 -namespace $namespace -secretName $secretName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to create certificate in Kubernetes" -ForegroundColor Red
        Pop-Location
        exit 1
    }
} else {
    Write-Host "Error: create-cert.ps1 not found in repo root" -ForegroundColor Red
    Pop-Location
    exit 1
}

Write-Host ""
Write-Host "Step 2: Verify secret exists..." -ForegroundColor Yellow
kubectl get secret $secretName -n $namespace

Write-Host ""
Write-Host "Step 3: Verify secret keys..." -ForegroundColor Yellow
$secret = kubectl get secret $secretName -n $namespace -o jsonpath='{.data}' | ConvertFrom-Json
Write-Host "Secret contains keys:" -ForegroundColor Cyan
$secret.PSObject.Properties.Name | ForEach-Object {
    Write-Host "  - $_" -ForegroundColor White
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SUCCESS! Secret is ready" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Secret Name: $secretName" -ForegroundColor White
Write-Host "Namespace: $namespace" -ForegroundColor White
Write-Host ""
Write-Host "You can now deploy the collector with K8s secret configuration." -ForegroundColor Yellow

Pop-Location
