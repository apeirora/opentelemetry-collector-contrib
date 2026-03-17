$ErrorActionPreference = "Stop"

$namespace = "otel-demo"
$serviceName = "otelcol-certificatehash"
$endpoint = "http://localhost:4318/v1/logs"

Write-Host "Port-forwarding to $serviceName..." -ForegroundColor Cyan
$portForward = Start-Process -FilePath "kubectl" -ArgumentList "port-forward", "-n", $namespace, "service/$serviceName", "4318:4318" -PassThru -NoNewWindow

Start-Sleep -Seconds 3

try {
    Write-Host "`nSending test log to $endpoint..." -ForegroundColor Cyan
    
    $logBody = @{
        resourceLogs = @(
            @{
                resource = @{
                    attributes = @(
                        @{
                            key = "service.name"
                            value = @{
                                stringValue = "test-service"
                            }
                        }
                    )
                }
                scopeLogs = @(
                    @{
                        scope = @{}
                        logRecords = @(
                            @{
                                timeUnixNano = [math]::Floor(([DateTimeOffset](Get-Date).ToUniversalTime()).ToUnixTimeMilliseconds() * 1000000).ToString()
                                severityNumber = 9
                                severityText = "INFO"
                                body = @{
                                    stringValue = "Test log message from PowerShell"
                                }
                                attributes = @(
                                    @{
                                        key = "test.attribute"
                                        value = @{
                                            stringValue = "test-value"
                                        }
                                    }
                                )
                            }
                        )
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 10

    $headers = @{
        "Content-Type" = "application/json"
    }

    $response = Invoke-RestMethod -Uri $endpoint -Method Post -Body $logBody -Headers $headers
    
    Write-Host "`nLog sent successfully!" -ForegroundColor Green
    Write-Host "Response: $($response | ConvertTo-Json)" -ForegroundColor Yellow
    
    Write-Host "`nChecking collector logs for hash and signature..." -ForegroundColor Cyan
    Start-Sleep -Seconds 2
    kubectl logs -n $namespace -l app=$serviceName --tail=50 | Select-String -Pattern "otel.certificate"
    
} catch {
    Write-Host "`nError: $_" -ForegroundColor Red
} finally {
    if ($portForward -and -not $portForward.HasExited) {
        Stop-Process -Id $portForward.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "`nPort-forward stopped." -ForegroundColor Yellow
}
