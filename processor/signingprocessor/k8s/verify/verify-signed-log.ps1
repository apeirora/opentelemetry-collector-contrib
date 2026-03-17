param(
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "",
    
    [Parameter(Mandatory=$false)]
    [string]$CertFile = "",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("SHA256", "SHA512")]
    [string]$HashAlgorithm = "SHA256",
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowVerbose,
    
    [Parameter(Mandatory=$false)]
    [string]$Namespace = "otel-demo",
    
    [Parameter(Mandatory=$false)]
    [string]$SecretName = "otelcol-test-certs",
    
    [Parameter(Mandatory=$false)]
    [switch]$FromK8s
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$goScript = Join-Path $scriptDir "verify-signed-log.go"

if (-not (Test-Path $goScript)) {
    Write-Host "Error: verify-signed-log.go not found at $goScript" -ForegroundColor Red
    exit 1
}

$tempCertFile = $null
if ($FromK8s) {
    Write-Host "Fetching certificate from Kubernetes secret..." -ForegroundColor Cyan
    
    $certData = kubectl get secret $SecretName -n $Namespace -o jsonpath='{.data.cert\.pem}' 2>$null
    if (-not $certData) {
        Write-Host "Error: Failed to fetch certificate from secret $SecretName in namespace $Namespace" -ForegroundColor Red
        exit 1
    }
    
    $certBytes = [System.Convert]::FromBase64String($certData)
    $certPem = [System.Text.Encoding]::UTF8.GetString($certBytes)
    
    $tempCertFile = [System.IO.Path]::GetTempFileName() + ".pem"
    [System.IO.File]::WriteAllText($tempCertFile, $certPem)
    
    Write-Host "Certificate saved to temporary file: $tempCertFile" -ForegroundColor Green
    
    $CertFile = $tempCertFile
}

if (-not $CertFile) {
    if ($FromK8s -and $tempCertFile) {
        $CertFile = $tempCertFile
    } else {
        $defaultCert = Join-Path $scriptDir "cert.pem"
        if (Test-Path $defaultCert) {
            $CertFile = $defaultCert
            Write-Host "Using default certificate: $CertFile" -ForegroundColor Yellow
        } else {
            Write-Host "Error: Certificate file is required. Use -CertFile or -FromK8s" -ForegroundColor Red
            Write-Host "  Or place cert.pem in the same directory as this script" -ForegroundColor Yellow
            exit 1
        }
    }
}

if (-not (Test-Path $CertFile)) {
    Write-Host "Error: Certificate file not found: $CertFile" -ForegroundColor Red
    exit 1
}

if (-not $LogFile) {
    $defaultLog = Join-Path $scriptDir "log.json"
    if (Test-Path $defaultLog) {
        $LogFile = $defaultLog
        Write-Host "Using default log file: $LogFile" -ForegroundColor Yellow
    } else {
        Write-Host "Error: Log file is required. Use -LogFile or pipe JSON data" -ForegroundColor Red
        Write-Host "  Or place log.json in the same directory as this script" -ForegroundColor Yellow
        exit 1
    }
}

try {
    Write-Host "Building verify-signed-log tool..." -ForegroundColor Cyan
    $exePath = Join-Path $scriptDir "verify-signed-log.exe"

    $buildOutput = & go build -o $exePath $goScript 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error building Go script:" -ForegroundColor Red
        Write-Host $buildOutput
        exit 1
    }

    Write-Host "Verifying signed log..." -ForegroundColor Cyan
    Write-Host ""

    $args = @(
        "-log", $LogFile,
        "-cert", $CertFile,
        "-hash", $HashAlgorithm
    )

    if ($ShowVerbose) {
        $args += "-verbose"
    }

    & $exePath $args
    $exitCode = $LASTEXITCODE
}
finally {
    if ($tempCertFile -and (Test-Path $tempCertFile)) {
        Remove-Item $tempCertFile -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
