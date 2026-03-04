param(
    [Parameter(Mandatory=$false)]
    [string]$Source = "k8s",
    [Parameter(Mandatory=$false)]
    [string]$Namespace = "otel-demo",
    [Parameter(Mandatory=$false)]
    [string]$SecretName = "otelcol-test-certs",
    [Parameter(Mandatory=$false)]
    [string]$OpenBaoAddr = "http://openbao.openbao.svc.cluster.local:8200",
    [Parameter(Mandatory=$false)]
    [string]$OpenBaoPath = "certs/data/test1",
    [Parameter(Mandatory=$false)]
    [string]$OpenBaoToken = "",
    [Parameter(Mandatory=$false)]
    [string]$OpenBaoNamespace = "",
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".",
    [Parameter(Mandatory=$false)]
    [switch]$CertOnly,
    [Parameter(Mandatory=$false)]
    [switch]$All
)

$ErrorActionPreference = "Stop"

function Extract-FromK8s {
    param(
        [string]$SecretName,
        [string]$Namespace,
        [string]$OutputDir
    )
    
    Write-Host "Extracting certificate from Kubernetes secret..." -ForegroundColor Cyan
    Write-Host "  Secret: $SecretName" -ForegroundColor White
    Write-Host "  Namespace: $Namespace" -ForegroundColor White
    Write-Host ""
    
    try {
        $secretJson = kubectl get secret $SecretName -n $Namespace -o json 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error: Failed to get secret '$SecretName' from namespace '$Namespace'" -ForegroundColor Red
            Write-Host "  kubectl error: $secretJson" -ForegroundColor Red
            return $false
        }
        
        if (-not $secretJson -or $secretJson.Trim() -eq "") {
            Write-Host "Error: Secret '$SecretName' not found in namespace '$Namespace'" -ForegroundColor Red
            return $false
        }
        
        $secretObj = $secretJson | ConvertFrom-Json
        if (-not $secretObj -or -not $secretObj.data) {
            Write-Host "Error: Secret data not found or invalid JSON" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Error parsing secret data: $_" -ForegroundColor Red
        return $false
    }
    
    $extracted = @{
        Cert = $false
        Key = $false
        CA = $false
    }
    
    Write-Host "Available keys in secret: $($secretObj.data.PSObject.Properties.Name -join ', ')" -ForegroundColor Gray
    Write-Host ""
    
    $certKey = 'cert.pem'
    if ($secretObj.data.PSObject.Properties.Name -contains $certKey) {
        try {
            $certData = $secretObj.data.$certKey
            $certBytes = [System.Convert]::FromBase64String($certData)
            $certPem = [System.Text.Encoding]::UTF8.GetString($certBytes)
            $certPath = Join-Path $OutputDir "cert.pem"
            [System.IO.File]::WriteAllText($certPath, $certPem)
            Write-Host "  [OK] Certificate saved to: $certPath" -ForegroundColor Green
            $extracted.Cert = $true
        }
        catch {
            Write-Host "  [ERROR] Failed to decode/save certificate: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  [WARN] cert.pem not found in secret" -ForegroundColor Yellow
    }
    
    if ($All -or (-not $CertOnly)) {
        if ($secretObj.data.PSObject.Properties.Name -contains 'key.pem') {
            $keyData = $secretObj.data.'key.pem'
            $keyBytes = [System.Convert]::FromBase64String($keyData)
            $keyPem = [System.Text.Encoding]::UTF8.GetString($keyBytes)
            $keyPath = Join-Path $OutputDir "key.pem"
            [System.IO.File]::WriteAllText($keyPath, $keyPem)
            Write-Host "  [OK] Private key saved to: $keyPath" -ForegroundColor Green
            $extracted.Key = $true
        }
        
        if ($secretObj.data.PSObject.Properties.Name -contains 'ca.pem') {
            $caData = $secretObj.data.'ca.pem'
            $caBytes = [System.Convert]::FromBase64String($caData)
            $caPem = [System.Text.Encoding]::UTF8.GetString($caBytes)
            $caPath = Join-Path $OutputDir "ca.pem"
            [System.IO.File]::WriteAllText($caPath, $caPem)
            Write-Host "  [OK] CA certificate saved to: $caPath" -ForegroundColor Green
            $extracted.CA = $true
        }
    }
    
    return $extracted.Cert
}

function Extract-FromOpenBao {
    param(
        [string]$OpenBaoAddr,
        [string]$OpenBaoPath,
        [string]$OpenBaoToken,
        [string]$OpenBaoNamespace,
        [string]$OutputDir
    )
    
    Write-Host "Extracting certificate from OpenBao..." -ForegroundColor Cyan
    Write-Host "  Address: $OpenBaoAddr" -ForegroundColor White
    Write-Host "  Path: $OpenBaoPath" -ForegroundColor White
    Write-Host ""
    
    if (-not $OpenBaoToken) {
        Write-Host "Error: OpenBao token is required. Set -OpenBaoToken parameter" -ForegroundColor Red
        return $false
    }
    
    $headers = @{
        "X-Vault-Token" = $OpenBaoToken
    }
    
    if ($OpenBaoNamespace) {
        $headers["X-Vault-Namespace"] = $OpenBaoNamespace
    }
    
    try {
        $url = "$OpenBaoAddr/v1/$OpenBaoPath"
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop
        
        $certPem = $null
        if ($response.data.data.certificate) {
            $certPem = $response.data.data.certificate
        } elseif ($response.data.certificate) {
            $certPem = $response.data.certificate
        } elseif ($response.data.data.cert) {
            $certPem = $response.data.data.cert
        } elseif ($response.data.cert) {
            $certPem = $response.data.cert
        }
        
        if (-not $certPem) {
            Write-Host "Error: Certificate not found in OpenBao response" -ForegroundColor Red
            return $false
        }
        
        $certPath = Join-Path $OutputDir "cert.pem"
        [System.IO.File]::WriteAllText($certPath, $certPem)
        Write-Host "  [OK] Certificate saved to: $certPath" -ForegroundColor Green
        
        if (-not $CertOnly) {
            $keyPem = $null
            if ($response.data.data.private_key) {
                $keyPem = $response.data.data.private_key
            } elseif ($response.data.private_key) {
                $keyPem = $response.data.private_key
            } elseif ($response.data.data.key) {
                $keyPem = $response.data.data.key
            } elseif ($response.data.key) {
                $keyPem = $response.data.key
            }
            
            if ($keyPem) {
                $keyPath = Join-Path $OutputDir "key.pem"
                [System.IO.File]::WriteAllText($keyPath, $keyPem)
                Write-Host "  [OK] Private key saved to: $keyPath" -ForegroundColor Green
            }
            
            $caPem = $null
            if ($response.data.data.ca_chain) {
                if ($response.data.data.ca_chain -is [Array]) {
                    $caPem = ($response.data.data.ca_chain -join "`n")
                } else {
                    $caPem = $response.data.data.ca_chain
                }
            } elseif ($response.data.ca_chain) {
                if ($response.data.ca_chain -is [Array]) {
                    $caPem = ($response.data.ca_chain -join "`n")
                } else {
                    $caPem = $response.data.ca_chain
                }
            } elseif ($response.data.data.ca) {
                $caPem = $response.data.data.ca
            } elseif ($response.data.ca) {
                $caPem = $response.data.ca
            }
            
            if ($caPem) {
                $caPath = Join-Path $OutputDir "ca.pem"
                [System.IO.File]::WriteAllText($caPath, $caPem)
                Write-Host "  [OK] CA certificate saved to: $caPath" -ForegroundColor Green
            }
        }
        
        return $true
    }
    catch {
        Write-Host "Error fetching from OpenBao: $_" -ForegroundColor Red
        return $false
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Extract Certificate" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Resolve the output directory to an absolute path
if ($OutputDir -eq "." -or $OutputDir -eq "") {
    $OutputDir = (Get-Location).Path
}
else {
    $OutputDir = (Resolve-Path $OutputDir -ErrorAction SilentlyContinue).Path
    if (-not $OutputDir) {
        $OutputDir = (Join-Path (Get-Location).Path $OutputDir)
    }
}

if (-not (Test-Path $OutputDir)) {
    Write-Host "Creating output directory: $OutputDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$success = $false

switch ($Source.ToLower()) {
    "k8s" {
        $success = Extract-FromK8s -SecretName $SecretName -Namespace $Namespace -OutputDir $OutputDir
    }
    "openbao" {
        $success = Extract-FromOpenBao -OpenBaoAddr $OpenBaoAddr -OpenBaoPath $OpenBaoPath -OpenBaoToken $OpenBaoToken -OpenBaoNamespace $OpenBaoNamespace -OutputDir $OutputDir
    }
    default {
        Write-Host "Error: Source must be 'k8s' or 'openbao'" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""

if ($success) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Extraction Complete" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Certificate saved to: $OutputDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now verify logs with:" -ForegroundColor Yellow
    Write-Host "  .\verify-signed-log.ps1" -ForegroundColor White
}
else {
    Write-Host "Extraction failed. Check the errors above." -ForegroundColor Red
    exit 1
}
