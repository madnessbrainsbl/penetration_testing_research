# Bybit Bug Bounty - Final Findings Report
## Date: November 25, 2025

---

## 🎯 CONFIRMED FINDINGS (Ready to Report)

### 1. Internal System Error on Negative Amount (Medium/Low)

**Status:** ✅ CONFIRMED (poc_output.txt)
**Endpoint:** `POST /v5/asset/transfer/inter-transfer`
**Severity:** Low-Medium ($150-$600)

**Description:**
Sending negative amount value causes Internal System Error (retCode: 10016) instead of proper validation error. This indicates improper input validation on the backend.

**Payload:**
```json
{
  "transferId": "uuid",
  "coin": "USDT",
  "amount": "-100",
  "fromMemberId": 1000,
  "toMemberId": 1000
}
```

**Response:**
```json
{"retCode":10016,"retMsg":"Internal System Error.","result":{},"retExtInfo":{},"time":1764002412124}
```

**Impact:**
- Information Disclosure: Reveals internal error handling
- Potential DoS: Repeated requests may stress backend
- Code Quality Issue: Missing input validation

**Note:** Currently blocked by 10005 Permission Denied for our API key, but the bug was confirmed earlier in the session.

---

### 2. CORS Misconfiguration (Informational)

**Status:** ⚠️ CONFIRMED but LOW IMPACT
**Endpoint:** All `api.bybit.com/*` endpoints

**Evidence:**
```
curl -I "https://api.bybit.com/v5/market/time" -H "Origin: https://evil.com"

Response:
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
```

**Why Low Impact:**
Bybit API uses API keys in headers (X-BAPI-API-KEY), NOT cookies for authentication. Therefore, CORS with credentials:true cannot be exploited to steal user data, as the attacker cannot send the victim's API keys automatically.

**Bounty Estimate:** $0-$150 (Informational)

---

## ❌ TESTED BUT NOT EXPLOITABLE

| Vector | Result | Reason |
|--------|--------|--------|
| IDOR on User endpoints | ❌ | API key determines user, params ignored |
| WebSocket Auth Bypass | ❌ | Requires auth ("Request not authorized") |
| OAuth Open Redirect | ❌ | redirect_uri whitelisted |
| S3 Bucket Listing | ❌ | Access Denied (403) |
| Subdomain Takeover | ❌ | Dev subdomains unreachable |
| Lazarus Fund Recovery | ❌ | All traced funds swept |
| Negative Order Qty | ❌ | Blocked by KYC (10024) |
| Rate Limit Bypass | ❌ | Rate limiting active |

---

## 🔧 LIMITATIONS

1. **KYC Block (10024):** Cannot test order/trade logic
2. **Permission Denied (10005):** Cannot test transfers, affiliate, earn
3. **No Mobile Device:** Cannot test P2P bypass (Frida)
4. **Testnet Keys:** Mainnet keys don't work on testnet

---

## 📋 RECOMMENDED ACTIONS

### Option A: Submit 10016 Bug
- **Risk:** May be marked as Low/Informational/Duplicate
- **Reward:** $150-$300
- **Effort:** Ready to submit

### Option B: Get Full Access Account
1. Complete KYC verification
2. Generate API key with all permissions
3. Deposit test funds
4. Re-run business logic tests

### Option C: Switch Target
- Bitget, BloFin, MEXC have similar scope
- Less post-hack hardening
- More open permissions

---

## 📁 EVIDENCE FILES

1. `poc_output.txt` - 10016 Internal Error proof
2. `CORS_EXPLOIT_POC.html` - CORS test page
3. `p2p_bypass_v2.js` - P2P Frida script (needs device)
4. `comprehensive_scan.sh` - Full scan script
5. `recon_data/` - JS analysis, subdomains

---

## 💰 REALISTIC BOUNTY ESTIMATE

| Finding | Probability | Amount |
|---------|-------------|--------|
| 10016 Internal Error | 60% | $150-$300 |
| CORS (Informational) | 20% | $0-$150 |
| P2P Bypass (if tested) | 70% | $5,000-$10,000 |

**Current Position:** Without KYC/Permissions, max potential is ~$300.
**With Full Access:** Potential increases to $5,000+.

---

## FINAL VERDICT

Bybit post-hack (Feb 2025) is one of the most hardened exchanges.
The 10016 bug is real but minor.
For serious bounty, either:
1. Get KYC + permissions, OR
2. Test P2P on mobile device, OR
3. Move to different target.
