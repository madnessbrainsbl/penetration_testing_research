# Test app.ripio.com API with session cookies
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$cookie1 = New-Object System.Net.Cookie("sessionid", "bklle8gup6ivkxopqoo7vhlkozmxcl8h", "/", ".ripio.com")
$cookie2 = New-Object System.Net.Cookie("csrftoken", "iUdTREJfgGZNRlcoRlidVkSC2f8RZwQY3B8RCdU65sQSfzniL0FzPvQJNHuiEjrV", "/", ".ripio.com")
$cookie3 = New-Object System.Net.Cookie("sessionid_status", "authenticated", "/", ".ripio.com")
$session.Cookies.Add($cookie1)
$session.Cookies.Add($cookie2)
$session.Cookies.Add($cookie3)

$endpoints = @(
    "https://app.ripio.com/api/v3/accounts/me/",
    "https://app.ripio.com/api/v3/balance/",
    "https://app.ripio.com/api/v3/transactions/?limit=5",
    "https://auth.ripio.com/api/users/me/"
)

foreach ($url in $endpoints) {
    Write-Host "`n=== Testing: $url ===" -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri $url -WebSession $session -Method GET -ErrorAction Stop
        Write-Host "SUCCESS:" -ForegroundColor Green
        $response | ConvertTo-Json -Depth 2
    } catch {
        Write-Host "Error: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
    }
}
