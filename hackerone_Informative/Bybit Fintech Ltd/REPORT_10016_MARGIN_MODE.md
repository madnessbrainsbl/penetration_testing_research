# Improper Input Validation in set-margin-mode Causes Internal Server Error

## Summary
The `/v5/account/set-margin-mode` API endpoint fails to properly validate the `setMarginMode` parameter, resulting in an Internal Server Error (retCode: 10016) when invalid values are submitted instead of returning an appropriate validation error.

## Severity
**Low** - Improper Input Validation / Information Disclosure

## Vulnerability Type
- CWE-20: Improper Input Validation
- CWE-209: Generation of Error Message Containing Sensitive Information

## Affected Endpoint
```
POST https://api.bybit.com/v5/account/set-margin-mode
```

## Steps to Reproduce

### 1. Obtain API credentials
- Create a Bybit account
- Generate API key with Trade permissions

### 2. Send malformed request
```bash
# Using curl with HMAC authentication
curl -X POST "https://api.bybit.com/v5/account/set-margin-mode" \
  -H "X-BAPI-API-KEY: YOUR_API_KEY" \
  -H "X-BAPI-SIGN: GENERATED_SIGNATURE" \
  -H "X-BAPI-SIGN-TYPE: 2" \
  -H "X-BAPI-TIMESTAMP: CURRENT_TIMESTAMP" \
  -H "X-BAPI-RECV-WINDOW: 5000" \
  -H "Content-Type: application/json" \
  -d '{"setMarginMode": "-1"}'
```

### 3. Observe response
```json
{
  "retCode": 10016,
  "retMsg": "Server error",
  "result": null
}
```

## Proof of Concept

### Values that trigger 10016:
| Input | Expected Response | Actual Response |
|-------|-------------------|-----------------|
| `-1` | 10001 (Illegal parameter) | **10016 (Server error)** |
| `-999` | 10001 (Illegal parameter) | **10016 (Server error)** |
| `abc` | 10001 (Illegal parameter) | **10016 (Server error)** |
| `null` | 10001 (Illegal parameter) | **10016 (Server error)** |
| `NaN` | 10001 (Illegal parameter) | **10016 (Server error)** |
| `undefined` | 10001 (Illegal parameter) | **10016 (Server error)** |

### Valid values (for comparison):
| Input | Response |
|-------|----------|
| `REGULAR_MARGIN` | 0 (Success) |
| `PORTFOLIO_MARGIN` | 0 (Success) |

## Technical Analysis

The vulnerability indicates that:

1. **Input validation is performed after the request reaches backend business logic**, not at the API gateway/validation layer

2. **The backend code throws an unhandled exception** when encountering unexpected input types or values

3. **Error handling catches the exception** but returns a generic "Server error" instead of a proper validation message

4. This suggests the `setMarginMode` value is **being processed/parsed by backend code** (likely converted to enum or database lookup) before validation

## Impact

### Direct Impact (Low)
- Information disclosure about internal error handling
- Indicates backend code structure (server-side validation gap)
- Could assist attackers in understanding system architecture

### Potential Escalation
- If server error handling is weak, repeated requests could:
  - Fill error logs (log flooding)
  - Consume server resources
  - Potentially expose stack traces in certain conditions

### Chaining Potential
- This input validation gap could be combined with other vectors
- If the value reaches a database query or internal function without sanitization, more severe vulnerabilities may exist

## Recommendation

1. **Input Validation at API Gateway**
```python
# Validate before processing
VALID_MARGIN_MODES = ["REGULAR_MARGIN", "PORTFOLIO_MARGIN", "ISOLATED_MARGIN"]
if margin_mode not in VALID_MARGIN_MODES:
    return {"retCode": 10001, "retMsg": f"Illegal setMarginMode. Valid values: {VALID_MARGIN_MODES}"}
```

2. **Type Checking**
- Ensure `setMarginMode` is a string
- Reject numeric or null values with proper error messages

3. **Exception Handling**
- Catch specific exceptions and return appropriate error codes
- Never expose "Server error" without proper logging and alerting

## Environment
- **Target**: api.bybit.com
- **API Version**: v5
- **Date**: November 25, 2025
- **Authentication**: Required (API Key + HMAC Signature)

## Supporting Materials
- `poc_10016_margin.sh` - Bash script to reproduce the vulnerability
- HTTP request/response logs available upon request

---

**Researcher**: [Your Name]  
**Date**: 2025-11-25
