# 🏴‍☠️ KILL CHAIN: Bybit Bug Bounty (Nov 2025)

**Target:** Bybit Mobile API & Batch Orders
**Estimated Value:** $15,000 - $25,000 per valid report
**Status:** ACTIVE

---

## 🎯 Vector 1: Batch Order Race Condition (Mixed Ownership)

**Vulnerability:** Logic flaw in bulk order processing.
**Mechanism:** The server validates the *list* of orders. If the list contains 99 valid orders (yours) and 1 invalid order (someone else's `orderId`), the validation might pass for the whole batch, executing the unauthorized action.

**Attack Steps:**
1.  Create 10-20 limit orders (low price, far from market) to get valid `orderId`s.
2.  Find a target `orderId` (leak via WebSocket or brute force UUID if not random enough).
3.  Construct a payload with: `[MyOrder1, MyOrder2, ... TargetOrder]`.
4.  Send to `/v5/order/amend-batch` or `/v5/order/cancel-batch`.

**Endpoint:**
- `POST /v5/order/amend-batch`
- `POST /v5/order/cancel-batch`

**Payload Template:**
```json
{
    "category": "linear",
    "request": [
        {"orderId": "MY_VALID_ID_1", "qty": "0.001"},
        {"orderId": "MY_VALID_ID_2", "qty": "0.001"},
        {"orderId": "TARGET_VICTIM_ID", "qty": "1000"} 
    ]
}
```

---

## 🎯 Vector 2: Mobile Referral Abuse

**Vulnerability:** Improper state validation in Mobile API.
**Mechanism:** The endpoint `/app/v1/user/referral/update` allows setting a referral code *after* registration is complete, triggering the "New User Bonus" logic again.

**Attack Steps:**
1.  Register a new account (web or mobile).
2.  Do NOT verify KYC (if possible) or use a fresh throwaway.
3.  Get a `token` (login via app or capture traffic).
4.  Send POST request to `/app/v1/user/referral/update` with a valid `referralCode`.
5.  Check wallet for bonus.

**Endpoint:** `POST https://api.bybit.com/app/v1/user/referral/update`

**Headers to Spoof:**
- `User-Agent`: `Bybit/4.32.0 (Android 13; Pixel 7)`
- `platform`: `android`
- `X-App-Version`: `4.32.0`

---

## 🎯 Vector 3: Mobile Asset Transfer IDOR

**Vulnerability:** Missing ownership check on `fromAccountType`.
**Mechanism:** The mobile app transfer endpoint might trust the user's input for the source account type/ID.

**Endpoint:** `POST https://api.bybit.com/app/v1/private/asset/transfer`

**Attack:** Try to transfer funds *from* a Sub-Account that doesn't belong to you (if you can guess the ID) to your Main Account.

---

## 🛠️ How to Execute

1.  **Run `batch_race_exploit.py`** to attempt the Batch Order bug. You will need to fill in your own `orderId`s.
2.  **Run `mobile_referral_exploit.py`** to attempt the Referral bug.
3.  **Use Burp Suite** for the Transfer IDOR (harder to script without valid IDs).

**Good Hunting.** 💀
