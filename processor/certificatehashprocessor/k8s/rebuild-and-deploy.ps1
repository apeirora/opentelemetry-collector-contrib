$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Rebuild and Deploy Collector" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptPath "..\..\..\")
$imageName = "otelcol-certificatehash:latest"
$dockerfilePath = "processor/certificatehashprocessor/k8s/Dockerfile.certificatehash"
$deploymentFile = "otelcol-certificatehash-k8s-secret.yaml"

Write-Host "Step 1: Building Docker image..." -ForegroundColor Yellow
Write-Host "This will compile the collector with your latest code changes..." -ForegroundColor Gray
Write-Host "Building from: $repoRoot" -ForegroundColor Gray
Push-Location $repoRoot
try {
    docker build -f $dockerfilePath -t $imageName .

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Docker build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "Image built successfully!" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Step 2: Checking cluster type..." -ForegroundColor Yellow
$clusterType = kubectl config current-context 2>&1
if ($clusterType -match "kind") {
    Write-Host "Detected kind cluster, loading image..." -ForegroundColor Cyan
    kind load docker-image $imageName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARNING: Failed to load image into kind. Continuing anyway..." -ForegroundColor Yellow
    } else {
        Write-Host "Image loaded into kind cluster!" -ForegroundColor Green
    }
} else {
    Write-Host "Not a kind cluster. If using a remote cluster, push the image to a registry." -ForegroundColor Yellow
    Write-Host "For local clusters, the image should be available." -ForegroundColor Gray
}

Write-Host ""
Write-Host "Step 3: Deleting existing pods to force new image pull..." -ForegroundColor Yellow
kubectl delete pod -n otel-demo -l app=otelcol-certificatehash --ignore-not-found=true | Out-Null
Write-Host "Old pods deleted" -ForegroundColor Green

Write-Host ""
Write-Host "Step 4: Applying deployment..." -ForegroundColor Yellow
Push-Location $scriptPath
try {
    kubectl apply -f $deploymentFile
} finally {
    Pop-Location
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Deployment failed!" -ForegroundColor Red
    exit 1
}
Write-Host "Deployment applied successfully!" -ForegroundColor Green

Write-Host ""
Write-Host "Step 5: Waiting for pod to be ready..." -ForegroundColor Yellow
kubectl wait --for=condition=ready pod -n otel-demo -l app=otelcol-certificatehash --timeout=60s

if ($LASTEXITCODE -eq 0) {
    Write-Host "Pod is ready!" -ForegroundColor Green
} else {
    Write-Host "WARNING: Pod may not be ready yet. Check with: kubectl get pods -n otel-demo" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Step 6: Checking pod status..." -ForegroundColor Yellow
kubectl get pods -n otel-demo -l app=otelcol-certificatehash

Write-Host ""
Write-Host "Step 7: Checking logs for initialization..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
$logs = kubectl logs -n otel-demo -l app=otelcol-certificatehash --tail=10 2>&1
if ($logs -match "Using Kubernetes secret|Everything is ready") {
    Write-Host "SUCCESS: Collector is running with K8s secret!" -ForegroundColor Green
} else {
    Write-Host "Recent logs:" -ForegroundColor Cyan
    $logs | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To view logs:" -ForegroundColor Yellow
Write-Host "  kubectl logs -n otel-demo -l app=otelcol-certificatehash -f" -ForegroundColor White
Write-Host ""
Write-Host "To test:" -ForegroundColor Yellow
Write-Host "  .\test-k8s-secret-processor.ps1" -ForegroundColor White
