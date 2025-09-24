# Test script to send audit log data to the receiver
$auditData = @{
    resource = "system"
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    user = "test-user"
    action = "login"
    details = @{
        ip = "192.168.1.100"
        user_agent = "test-client"
    }
} | ConvertTo-Json

Write-Host "Sending audit log data to receiver..."
Write-Host $auditData

try {
    $response = Invoke-RestMethod -Uri "http://localhost:4310/v1/logs" -Method POST -Body $auditData -ContentType "application/json"
    Write-Host "Response: $response"
    Write-Host "✅ Test successful!"
} catch {
    Write-Host "❌ Test failed: $($_.Exception.Message)"
    Write-Host "Make sure the audit log receiver is running on port 4310"
}
