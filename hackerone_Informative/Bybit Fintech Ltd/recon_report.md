# Bybit Reconnaissance Report

## Interesting Assets
- **Logger API**: `https://api.ffbbbdc6d3c353211fe2ba39c9f744cd.com` (Tencent WAF, `/p/admin` returns 500)
- **Static Assets**: `https://static.ffbbbdc6d3c353211fe2ba39c9f744cd.com` (Amazon S3, bucket listing disabled, but `/admin` exists)
- **Internal IP Leak**: Found `10.110.185.208:30859` in `chunk_7953.js`
- **Testnet API v5**: `https://api-testnet.bybit.com` (Openresty/Cloudfront, requires signatures)

## Potential Vulnerabilities to Investigate (Requires Auth)
1. **Blind XSS in Logger**: Attempt to bypass WAF on `/p/front` and inject XSS payloads.
2. **DOM XSS via localStorage**: `complianceSDKApi2Host` key in localStorage controls API host. If controllable -> data exfiltration.
3. **S3 Bucket Enumeration**: Use dictionary attack on `static.ffbb...` to find exposed config files.
4. **IDOR on `/v2/private/user/profile`**: Check if accessible with low-privilege token or without signature (unlikely, but worth checking).

## Decompiled Logic
- **Compliance SDK**: Loads host from `localStorage`.
- **Dev Flags**: `Dev: !0` found in `globals.js`.

## Next Steps
1. Register an account on Testnet using a browser.
2. Obtain valid `X-BAPI-API-KEY` and `X-BAPI-SIGN`.
3. Fuzz `/v5` endpoints with valid auth but invalid parameters (IDOR).
4. Attempt to set `complianceSDKApi2Host` in browser console and see where traffic goes.
