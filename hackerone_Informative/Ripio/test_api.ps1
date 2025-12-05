$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzY0NjExMDQ0LCJpYXQiOjE3NjQ2MTA0NDQsImp0aSI6IjQ0ZTc3ZmE3NDc2MDRiNzZhODY4MGU5MmNkYTQyYzU3IiwidXNlcl91c2VyX3V1aWQiOiI2OTFlMjEzNi00OGJiLTRlNTUtOTMxOC1hNTk0YWM5YzNjZWMiLCJwcml2YXRlIjoiZ0FBQUFBQnBMZEdNazdFbnhLc3VtN2VkLXMxZlVvN3Y2Wld1UTVnTzlodHh6anJKMC1VX0RtSW1abVFwVldic0xqYWlRRTRDVE9IZ2E5dnRaSW5RT1paamFGZnZJVmJtRDVqcmFZbHRLZXpESGJqQ1A5bjhvU0RCTnRnaWhpOVBzRkZ6S1ZuZHR5Qndfakl5dVJPZDl2NDV5NUJRUG4wNlMxYVpNSWJBUDlZY20zVEp5SlU2ME42b3JwTW1uT2RzT19yR25EdXhhZEpiNjZVbXhiX0FGS2xBRTM5dnJieVVZcU05Mkl5V2N2UVFCVTAycXl5RWVVZUhaaEE0eGRiMVg0WUxSd2J4Z253dkRlTkh2Nnl2ZUNDWFM4cTV3ZHM0ZUw2a090eXkzNjVKbEtnRVdlUFc4XzBzazN1THJ0NWRDX2xZUjF3LXNOcjMiLCJ1YV9oYXNoIjoiZ0FBQUFBQnBMZEdNUE02VlNMTHlDM2ZMN2Y1QjNmeFkxSHVIamVpRjd3QUpKNms5YzR6WGpHLXR5V09iUjlvLTFicHBBQzB0TzdpRm16RTB2WFV5clNHZ05FTUxFMGU3Y2xmTVk0cEU3MEFvdndWdVVrSTJCRmQ4eTRQamZjVE1jUDA3dVlyaGw1OVVfTUMya3hoV0Q1d2tlZ2VDRlVjV0JmeEVTSlpua0ZhSlA0NWF0c1llaUlBPSIsImJhY2siOiJSSVBJTyIsImZpbmdlcnByaW50IjoiMTQ2Y2M0OGQwMTkwMTMzNTI4OTg1NzEzNjgzMzZiZTNkYWExNTk1OTAwZWVhNWE3NzE0ZmVmMTY4MzIyNTAyNCIsImhhc18yZmEiOmZhbHNlLCJpc19zdGFmZiI6ZmFsc2V9.Nf8x8jNII4oEVlhFAVkNz8mBNGlCOgmDUrT1X0TVF83Wr8xHVB0kFVT58aUz_A9KXKK_G0Ca04rAFWflzFWMVM5CaUsrxwq0dkpDlx-yvfUvN1AX7PzmgEqOM4o9JnT6DOmdfMnJFyT6vhJ5Z3sSMAyahiX_tXQJhnowdDX1HUlz_EzQzvzE_O9rW4pj6LWrGcHQbohUQm_79pUuUYkUSJQf7TyulHFawbn2BS69K3q-iSVgeAWgo5NFwjwQ5Wy9NSPwkZCNFDcnEeMw27vToNO0CgEu58YMXljUVz3-DS8-i6HHME0qWcbAEQIKAy2g5hzeRUgUY6L4lf-cwi_tWQ"

$headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
}

$endpoints = @(
    "https://api.ripio.com/exchange/users/balances/",
    "https://api.ripio.com/exchange/wallets/",
    "https://api.ripio.com/exchange/transactions/",
    "https://api.ripio.com/core/users/me/",
    "https://api.ripio.com/core/wallets/",
    "https://api.ripio.com/payments/withdrawals/",
    "https://auth.ripio.com/api/users/otp/",
    "https://auth.ripio.com/api/users/security/",
    "https://auth.ripio.com/api/users/change-password/"
)

foreach ($url in $endpoints) {
    Write-Host "`n=== Testing: $url ===" -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET -ErrorAction Stop
        Write-Host "SUCCESS:" -ForegroundColor Green
        $response | ConvertTo-Json -Depth 3
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}
