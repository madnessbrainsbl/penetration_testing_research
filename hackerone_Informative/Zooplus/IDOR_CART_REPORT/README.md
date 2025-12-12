# IDOR Cart Vulnerability - Complete Report Package

## Folder Structure

```
IDOR_CART_REPORT/
├── report/              # Full HackerOne report
│   └── HACKERONE_IDOR_CART.md
├── scripts/             # Reproduction scripts
│   ├── idor_read_cart.js      # Read another user's cart
│   ├── idor_write_cart.js     # Modify another user's cart
│   └── idor_complete_test.js  # Complete test (read + write)
├── screenshots/         # Evidence screenshots
│   ├── cart_idor_accountB.png
│   └── cart_response_start.txt
└── logs/                # Logs and outputs
    ├── console_output_read.txt
    ├── console_output_write.txt
    ├── api_response_read.json
    ├── api_response_write_before.json
    └── api_response_write_after.json
```

## Quick Start

### 1. Read IDOR Test

1. Login as Account B (`suobup@dunkos.xyz`)
2. Open browser console (F12)
3. Execute code from `scripts/idor_read_cart.js`

**Result**: Account B gains full access to Account A's cart

### 2. Write IDOR Test

1. Login as Account B (`suobup@dunkos.xyz`)
2. Open browser console (F12)
3. Execute code from `scripts/idor_write_cart.js`

**Result**: Account B modifies Account A's cart (price changes)

### 3. Complete Test

Execute `scripts/idor_complete_test.js` for automated read + write testing.

## Confirmed Data

### Test Accounts
- **Account A (Victim)**: `duststorm155@doncong.com` (customerId: 53260509)
- **Account B (Attacker)**: `suobup@dunkos.xyz` (customerId: 53260633)

### Target Cart
- **Cart UUID**: `6bd223b4-5040-4faa-ba85-6a85c1ec2d50`
- **Owner**: Account A (customerId: 53260509)

### Confirmed Results
- **Read IDOR**: ✅ Account B can read Account A's cart
- **Write IDOR**: ✅ Account B modified Account A's cart (330.15 EUR → 277.16 EUR)

## Endpoints

### Read
```
GET /checkout/api/cart-api/v2/cart/{cartUuid}
```

### Write
```
PUT /semiprotected/api/checkout/state-api/v2/set-article-quantity
Payload: {"articleId": 2966422, "quantity": 2}
```

## Logs

All logs saved in `logs/` folder:
- `console_output_read.txt` - console output for read test
- `console_output_write.txt` - console output for write test
- `api_response_*.json` - API JSON responses

## Report

Full HackerOne report: `report/HACKERONE_IDOR_CART.md`



