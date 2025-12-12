# Zooplus Pentest Checklist (execution tracker)

## Preliminaries
- [ ] Create 2+ test accounts (A/B) with different countries/locales.
- [ ] Configure proxy (Burp/ZAP/mitmproxy); save traffic to `Zooplus/reports/`.
- [ ] Note scope exclusions and avoid real charges; stop before payment capture.

## Authentication & Sessions
- [ ] Login/registration: check account enumeration messages and rate limiting.
- [ ] Password reset: token length/entropy, single-use, expiry, no leakage in Referer/logs.
- [ ] Session cookies: `HttpOnly`, `Secure`, `SameSite`, domain scoping; session invalidation on logout.

## CSRF
- [ ] Critical POST/PUT/DELETE endpoints (cart add, address edit, email/phone change, payment add, checkout confirm) require valid anti-CSRF; test Origin/Referer enforcement and double-submit tokens.

## Authorization / IDOR
- [ ] Orders/history details and invoice PDFs: swap IDs with account B.
- [ ] Saved addresses/profile data: change `addressId`/`userId` and observe.
- [ ] Saved payment methods/loyalty points: verify ownership enforcement.
- [ ] Downloads/attachments (receipts, labels): ensure authorized access only.

## Cart / Checkout Logic
- [ ] Tamper price/quantity/shipping/promo fields in requests; server must recompute totals.
- [ ] Ensure coupons/discounts apply only once and to eligible users/items.
- [ ] Block duplicate/expired promo use; prevent negative totals.
- [ ] Verify address/payment belong to the active user during checkout.

## XSS / HTML & CSS Injection
- [ ] Inputs: search, reviews/ratings, profile fields, gift messages, order notes.
- [ ] Try stored and reflected payloads; include CSS-context payloads (`</style>...`) to mirror Ripio lesson.
- [ ] Check email/PDF templates for unsanitized user data.
- [ ] Confirm CSP presence/effectiveness and output encoding.

## API / Mobile / GraphQL
- [ ] Discover `api.*`, `m.*`, `graphql` endpoints via traffic and recon.
- [ ] Test CORS (no wildcard on authenticated data), preflight handling, token scoping.
- [ ] Run IDOR/BOLA with dual tokens; try GraphQL introspection and field-level auth.
- [ ] Rate-limit API calls (login, reset, order lookups, coupon checks).

## Rate Limiting & Brute Force
- [ ] Login/password reset/email verification endpoints enforce throttling/captcha.
- [ ] Order ID or invoice ID enumeration blocked.
- [ ] Promo code brute-force blocked or delayed.

## Promo Codes / Campaigns
- [ ] CSRF on apply/remove.
- [ ] Server-side validation of eligibility/expiry; no client-only checks.
- [ ] Prevent reuse across accounts when disallowed.

## Notifications (Email/SMS)
- [ ] Reset/confirm/unsubscribe links: strong, single-use tokens; no open redirect.
- [ ] Referrer-policy protects tokens; links expire properly.

## Headers / Transport / Framing
- [ ] HTTPS enforced with HSTS; no mixed content.
- [ ] `X-Frame-Options`/`frame-ancestors` to block clickjacking on checkout/profile.
- [ ] `Referrer-Policy` restrictive on sensitive pages.
- [ ] Cache-control on authenticated responses.

## File Uploads (if present)
- [ ] Content-type/extension checks; AV/sandbox; no SVG/HTML execution.
- [ ] Path traversal/LFI blocked; URLs require auth.

## Recon / Asset Hygiene
- [ ] Subdomain takeover scan for unused CNAMEs.
- [ ] Exposed buckets/repos/configs; robots.txt/sitemaps for hidden paths.

## Logging / Evidence
- [ ] Capture PoC requests/responses with timestamps.
- [ ] Note impact and reproduction steps per finding in `Zooplus/reports/`.

