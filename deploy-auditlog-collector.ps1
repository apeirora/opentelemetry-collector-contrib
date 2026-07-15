param(
    [switch]$UsePublishedImage,
    [string]$ImageTag = "latest"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Audit-Log Collector Image Build & Deploy ===" -ForegroundColor Cyan
Write-Host ""

$namespace = "otel-audit"
$publishedImage = "ghcr.io/apeirora/opentelemetry-collector-contrib/otelauditcol:$ImageTag"
$localImage = "otelauditcol:$ImageTag"
$deploymentManifest = "cmd/otelauditcol/k8s/deployment.yaml"

if ($UsePublishedImage) {
    $imageName = $publishedImage
} else {
    $imageName = $localImage
}

function Test-Docker {
    try {
        $null = docker version 2>&1
        return $true
    } catch {
        Write-Host "ERROR: Docker not found. Please install Docker." -ForegroundColor Red
        return $false
    }
}

function Test-Kubectl {
    try {
        $null = kubectl version --client 2>&1
        return $true
    } catch {
        Write-Host "WARNING: kubectl not found. Image build will continue; deploy will be skipped." -ForegroundColor Yellow
        return $false
    }
}

function Build-CollectorImage {
    if ($UsePublishedImage) {
        Write-Host "Step 1: Pulling published image from GHCR..." -ForegroundColor Yellow
        docker pull $publishedImage
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to pull $publishedImage"
        }
        Write-Host "  Image ready: $publishedImage" -ForegroundColor Green
        return
    }

    Write-Host "Step 1: Building minimal audit collector image with otel-collector-builder..." -ForegroundColor Yellow
    Write-Host "  Components: auditlogreceiver, certificatelogverify, redis storage, otlphttpexporter" -ForegroundColor Cyan
    Write-Host "  This may take several minutes on first build..." -ForegroundColor Cyan

    docker build -f cmd/otelauditcol/Dockerfile -t $localImage .

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build Docker image"
    }

    Write-Host "  Image built: $localImage" -ForegroundColor Green
}

function Load-ImageToKind {
    if ($UsePublishedImage) {
        Write-Host "`nStep 2: Skipping kind load (using published GHCR image in manifest)." -ForegroundColor Yellow
        return
    }

    Write-Host "`nStep 2: Loading image to kind (if present)..." -ForegroundColor Yellow

    $kindClusters = kind get clusters 2>&1
    if ($LASTEXITCODE -eq 0 -and $kindClusters) {
        Write-Host "  Kind cluster detected. Loading image..." -ForegroundColor Cyan
        kind load docker-image $localImage
        Write-Host "  Image loaded to kind." -ForegroundColor Green
    } else {
        Write-Host "  No kind cluster detected. Skipping image load." -ForegroundColor Yellow
    }
}

function Deploy-Kubernetes {
    param([bool]$HasKubectl)

    if (-not $HasKubectl) {
        Write-Host "`nSkipping Kubernetes deploy (kubectl unavailable)." -ForegroundColor Yellow
        return
    }

    Write-Host "`nStep 3: Deploying to Kubernetes..." -ForegroundColor Yellow
    Write-Host "  Image: $imageName" -ForegroundColor Cyan
    Write-Host "  IMPORTANT: Replace placeholder values in Secret otelcol-audit-secrets before production use." -ForegroundColor Yellow
    Write-Host "  HMAC key and verification cert are read via Kubernetes API (k8s_secret); TLS certs are mounted for the receiver." -ForegroundColor Yellow

    kubectl apply -f $deploymentManifest

    if (-not $UsePublishedImage) {
        kubectl set image deployment/otelcol-audit otelcol=$localImage -n $namespace 2>&1 | Out-Null
        kubectl patch deployment otelcol-audit -n $namespace -p '{"spec":{"template":{"spec":{"containers":[{"name":"otelcol","imagePullPolicy":"IfNotPresent"}]}}}}' 2>&1 | Out-Null
    }

    Write-Host "  Waiting for deployment..." -ForegroundColor Cyan
    kubectl wait --for=condition=available --timeout=300s deployment/otelcol-audit -n $namespace 2>&1 | Write-Host

    Write-Host "`nPods:" -ForegroundColor Cyan
    kubectl get pods -n $namespace -l app=otelcol-audit

    Write-Host "`nService:" -ForegroundColor Cyan
    kubectl get svc -n $namespace otelcol-audit
}

try {
    if (-not (Test-Docker)) { exit 1 }
    $hasKubectl = Test-Kubectl

    Build-CollectorImage
    Load-ImageToKind
    Deploy-Kubernetes -HasKubectl $hasKubectl

    Write-Host "`n=== Done ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "Published:   docker pull $publishedImage" -ForegroundColor Cyan
    Write-Host "Local build: docker build -f cmd/otelauditcol/Dockerfile -t otelauditcol ." -ForegroundColor Cyan
    Write-Host "Compose demo:  cd cmd/otelauditcol; docker compose up --build" -ForegroundColor Cyan
    Write-Host "View logs:     kubectl logs -n $namespace -l app=otelcol-audit -f" -ForegroundColor Cyan
} catch {
    Write-Host "`nERROR: $_" -ForegroundColor Red
    exit 1
}
