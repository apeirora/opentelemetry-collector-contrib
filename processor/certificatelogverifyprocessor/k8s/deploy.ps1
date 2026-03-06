$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Deploy Certificate Log Verify Processor" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$namespace = "otel-demo"
$secretName = "otelcol-test-certs"

Write-Host "Step 1: Creating namespace..." -ForegroundColor Yellow
kubectl apply -f namespace.yaml

Write-Host ""
Write-Host "Step 2: Creating RBAC resources..." -ForegroundColor Yellow
kubectl apply -f rbac.yaml

Write-Host ""
Write-Host "Step 3: Creating ConfigMap..." -ForegroundColor Yellow
kubectl apply -f configmap.yaml

Write-Host ""
Write-Host "Step 4: Creating Deployment..." -ForegroundColor Yellow
kubectl apply -f deployment.yaml

Write-Host ""
Write-Host "Step 5: Creating Service..." -ForegroundColor Yellow
kubectl apply -f service.yaml

Write-Host ""
Write-Host "Step 6: Waiting for deployment to be ready..." -ForegroundColor Yellow
kubectl wait --for=condition=available --timeout=300s deployment/otelcol-certificatelogverify -n $namespace

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "SUCCESS! Deployment is ready" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Pods:" -ForegroundColor Cyan
    kubectl get pods -n $namespace -l app=otelcol-certificatelogverify
    Write-Host ""
    Write-Host "Service:" -ForegroundColor Cyan
    kubectl get svc -n $namespace otelcol-certificatelogverify
    Write-Host ""
    Write-Host "To view logs:" -ForegroundColor Yellow
    Write-Host "  kubectl logs -n $namespace -l app=otelcol-certificatelogverify" -ForegroundColor White
} else {
    Write-Host ""
    Write-Host "WARNING: Deployment not ready within timeout" -ForegroundColor Yellow
    Write-Host "Checking pod status..." -ForegroundColor Yellow
    kubectl get pods -n $namespace -l app=otelcol-certificatelogverify
    kubectl describe pod -n $namespace -l app=otelcol-certificatelogverify | Select-String -Pattern "Error|Warning" -Context 2
}
