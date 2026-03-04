param(
    [Parameter(Mandatory=$false)]
    [string]$Namespace = "otel-demo",
    [Parameter(Mandatory=$false)]
    [string]$ServiceName = "otelcol-certificatehash",
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "log-from-collector.json"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test and Verify Signed Log" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$endpoint = "http://localhost:4318/v1/logs"

Write-Host "Step 1: Port-forwarding to $ServiceName..." -ForegroundColor Yellow
$portForward = Start-Process -FilePath "kubectl" -ArgumentList "port-forward", "-n", $Namespace, "service/$ServiceName", "4318:4318" -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 5

try {
    Write-Host "Step 2: Sending test log to $endpoint..." -ForegroundColor Yellow
    
    $timestamp = [math]::Floor(([DateTimeOffset](Get-Date).ToUniversalTime()).ToUnixTimeMilliseconds() * 1000000)
    
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
                                timeUnixNano = $timestamp.ToString()
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

    try {
        $response = Invoke-RestMethod -Uri $endpoint -Method Post -Body $logBody -Headers $headers -ErrorAction Stop
        Write-Host "  [OK] Log sent successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "  [WARN] Request may have succeeded (collector often returns empty response)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Step 3: Waiting for collector to process log..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    
    Write-Host "Step 4: Extracting signed log from collector output..." -ForegroundColor Yellow
    
    # Get collector logs - specify container explicitly and get more lines
    $logs = kubectl logs -n $Namespace -l app=$ServiceName -c otelcol --tail=200 2>&1
    
    if (-not $logs) {
        Write-Host "  [ERROR] No logs found from collector" -ForegroundColor Red
        exit 1
    }
    
    # The debug exporter outputs logs in a structured format
    # Look for the log record with our test message and hash/signature
    $logLines = $logs -split "`n"
    $foundLogJson = $null
    
    # Method 1: Look for JSON-like structure with our test message
    $allLogs = $logs -join "`n"
    
    # Try to find JSON structure containing our test message and hash
    if ($allLogs -match '(?s)\{[^}]*"body"[^}]*"Test log message from PowerShell"[^}]*"otel\.log\.hash"[^}]*\}') {
        $foundLogJson = $matches[0]
    }
    # Try broader pattern
    elseif ($allLogs -match '(?s)\{[^}]{0,3000}"otel\.log\.hash"[^}]{0,3000}\}') {
        $foundLogJson = $matches[0]
    }
    
    # Method 2: Parse debug exporter format line by line
    if (-not $foundLogJson) {
        Write-Host "  [INFO] Parsing debug exporter text format..." -ForegroundColor Gray
        
        # Find the most recent log record with our test message
        $logRecord = @{
            body = $null
            attributes = @{}
            timestamp = $null
            severity_number = $null
            severity_text = $null
        }
        
        $foundHash = $false
        $foundSignature = $false
        
        $logRecordStartIndex = -1
        for ($i = $logLines.Count - 1; $i -ge 0; $i--) {
            if ($logLines[$i] -match 'LogRecord #\d+') {
                $logRecordStartIndex = $i
                break
            }
        }
        
        if ($logRecordStartIndex -eq -1) {
            Write-Host "  [DEBUG] No LogRecord marker found" -ForegroundColor Yellow
        } else {
            $inAttributes = $false
            
            for ($i = $logRecordStartIndex; $i -lt $logLines.Count; $i++) {
                $line = $logLines[$i]
                
                if ($line -match 'LogRecord #\d+') {
                    continue
                }
                
                if ($line -match 'Body:\s*Str\(([^)]+)\)') {
                    $bodyValue = $matches[1]
                    if ($bodyValue -eq "Test log message from PowerShell") {
                        $logRecord.body = $bodyValue
                    }
                }
                
                if ($line -match 'Timestamp:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\+\d{4}\s+UTC') {
                    try {
                        $dateStr = $matches[1]
                        $date = [DateTimeOffset]::Parse($dateStr + " +00:00")
                        $logRecord.timestamp = $date.ToUnixTimeMilliseconds() * 1000000
                    } catch {
                        Write-Host "  [DEBUG] Failed to parse timestamp: $dateStr" -ForegroundColor Gray
                    }
                }
                
                if ($line -match 'SeverityText:\s*(\w+)') {
                    $logRecord.severity_text = $matches[1]
                }
                if ($line -match 'SeverityNumber:\s*Info\((\d+)\)') {
                    $logRecord.severity_number = [int]$matches[1]
                }
                
                if ($line -match '^Attributes:') {
                    $inAttributes = $true
                    continue
                }
                
                if ($inAttributes -and $line -match '^\s+->\s+([^:]+):\s*Str\(([^)]+)\)') {
                    $key = $matches[1].Trim()
                    $value = $matches[2]
                    
                    if ($key -eq 'otel.log.hash') {
                        $logRecord.attributes['otel.log.hash'] = $value
                        $foundHash = $true
                    }
                    elseif ($key -eq 'otel.log.signature') {
                        $logRecord.attributes['otel.log.signature'] = $value
                        $foundSignature = $true
                    }
                    elseif ($key -ne 'otel.log.hash' -and $key -ne 'otel.log.signature') {
                        $logRecord.attributes[$key] = $value
                    }
                }
                
                if ($line -match '^(ResourceLog|ScopeLogs|InstrumentationScope|LogRecord #)') {
                    if ($i -gt $logRecordStartIndex) {
                        break
                    }
                }
                
                if ($logRecord.body -eq "Test log message from PowerShell" -and $foundHash -and $foundSignature -and $logRecord.timestamp) {
                    Write-Host "  [DEBUG] Found complete log record" -ForegroundColor Gray
                    break
                }
            }
        }
        
        if ($logRecord.attributes.ContainsKey('otel.log.hash') -and 
            $logRecord.attributes.ContainsKey('otel.log.signature') -and
            $logRecord.body -eq "Test log message from PowerShell") {
            # Convert to JSON
            $foundLogJson = $logRecord | ConvertTo-Json -Depth 10
            Write-Host "  [OK] Successfully parsed log record from debug exporter format" -ForegroundColor Green
            Write-Host "  [DEBUG] Body: $($logRecord.body)" -ForegroundColor Gray
            Write-Host "  [DEBUG] Timestamp: $($logRecord.timestamp)" -ForegroundColor Gray
            Write-Host "  [DEBUG] Hash: $($logRecord.attributes['otel.log.hash'].Substring(0, 20))..." -ForegroundColor Gray
        } else {
            Write-Host "  [DEBUG] Missing fields - Body: $($logRecord.body), Hash: $foundHash, Sig: $foundSignature, TS: $($logRecord.timestamp)" -ForegroundColor Yellow
        }
    }
    
    if (-not $foundLogJson) {
        Write-Host "  [ERROR] Could not extract signed log from collector output" -ForegroundColor Red
        Write-Host "  Searching for hash in logs..." -ForegroundColor Yellow
        $hashLines = $logs | Select-String -Pattern "otel\.log\.(hash|signature)" | Select-Object -First 10
        if ($hashLines) {
            $hashLines
        } else {
            Write-Host "  No hash found in logs" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  Searching for test message..." -ForegroundColor Yellow
        $testLines = $logs | Select-String -Pattern "Test log message" | Select-Object -First 5
        if ($testLines) {
            $testLines
        } else {
            Write-Host "  Test message not found" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  Full collector logs (last 50 lines):" -ForegroundColor Yellow
        $logs | Select-Object -Last 50
        Write-Host ""
        Write-Host "  Note: The log might not have been processed yet. Try running again or check collector status." -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "  [OK] Found signed log record" -ForegroundColor Green
    
    # Parse and format the log
    try {
        $logObj = $foundLogJson | ConvertFrom-Json -ErrorAction Stop
        
        # Ensure proper format for verify-signed-log.go
        $outputRecord = @{
            body = $logObj.body
            attributes = @{}
            timestamp = $logObj.timestamp
            severity_number = $logObj.severity_number
            severity_text = $logObj.severity_text
        }
        
        # Handle attributes
        if ($logObj.attributes) {
            if ($logObj.attributes -is [PSCustomObject]) {
                $logObj.attributes.PSObject.Properties | ForEach-Object {
                    $outputRecord.attributes[$_.Name] = $_.Value
                }
            }
            elseif ($logObj.attributes -is [Hashtable]) {
                $outputRecord.attributes = $logObj.attributes
            }
        }
        
        $outputJson = $outputRecord | ConvertTo-Json -Depth 10 -Compress:$false
        
        $outputPath = Join-Path (Get-Location).Path $OutputFile
        [System.IO.File]::WriteAllText($outputPath, $outputJson)
        
        Write-Host "  [OK] Log saved to: $outputPath" -ForegroundColor Green
        Write-Host ""
        
        Write-Host "Step 5: Verifying signed log..." -ForegroundColor Yellow
        Write-Host ""
        
        # Run verification with certificate from Kubernetes
        & ".\verify-signed-log.ps1" -LogFile $OutputFile -FromK8s -Namespace $Namespace
        
    }
    catch {
        Write-Host "  [ERROR] Failed to parse log JSON: $_" -ForegroundColor Red
        Write-Host "  Raw log data:" -ForegroundColor Yellow
        Write-Host $foundLogJson
        exit 1
    }
    
} catch {
    Write-Host "`n[ERROR] $_" -ForegroundColor Red
    exit 1
} finally {
    # Keep port-forward running for a bit longer in case verification needs it
    Start-Sleep -Seconds 2
    if ($portForward -and -not $portForward.HasExited) {
        Stop-Process -Id $portForward.Id -Force -ErrorAction SilentlyContinue
        Write-Host "`nPort-forward stopped." -ForegroundColor Yellow
    }
}
