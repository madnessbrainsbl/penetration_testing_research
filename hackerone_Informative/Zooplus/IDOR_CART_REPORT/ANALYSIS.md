# IDOR Cart Vulnerability - Status Analysis

## Situation

**HackerOne Response**: This vulnerability was previously reported in **2023-05-29** as "informative" severity.

**Our Finding**: The vulnerability **still exists** in **December 2025** (2+ years later).

## Key Differences

### Original Report (2023)
- Title: "[IDOR] - Manipulate any user's cart by adding/removing products"
- State: **Informative**
- Date: 2023-05-29

### Our Report (2025)
- **Read IDOR**: ✅ Confirmed - Account B can read Account A's cart
- **Write IDOR**: ✅ Confirmed - Account B modified Account A's cart (330.15 EUR → 277.16 EUR)
- **Endpoint**: `PUT /semiprotected/api/checkout/state-api/v2/set-article-quantity`
- **Impact**: Critical (CVSS 9.1)

## Analysis

### Why Still Exists?

1. **Partial Fix**: Company may have fixed some endpoints but missed others
2. **New Endpoint**: The `state-api/v2/set-article-quantity` endpoint may be newer than 2023
3. **Different Attack Vector**: Our write endpoint differs from the original report
4. **Regression**: Fix was incomplete or reverted

### What This Means

- **If vulnerability still exists after 2 years**: This is a serious security issue
- **If it's a different endpoint**: This could be a new vulnerability
- **If it's a regression**: This shows poor security maintenance

## Recommendations

### Option 1: Verify Current Status
Test if the original vulnerability vectors still work:
- Try adding/removing products via different endpoints
- Test if read-only access was fixed but write access wasn't
- Check if `state-api` endpoint is new or was missed in original fix

### Option 2: Find Additional Vectors
Since the original was marked "informative", look for:
- **Higher impact scenarios**: Can we complete orders? Change delivery addresses?
- **Mass exploitation**: Can we enumerate cart UUIDs?
- **Account takeover**: Can we link carts to accounts and escalate?

### Option 3: Focus on Other Vulnerabilities
Move to other attack surfaces:
- Checkout process vulnerabilities
- Payment manipulation
- Order modification
- Profile/account IDOR
- CSRF on critical actions

## Next Steps

1. **Test original vectors** - See if they still work
2. **Document regression** - If it's the same issue, this is a regression
3. **Find new vectors** - If it's different, it's a new vulnerability
4. **Escalate impact** - Try to find ways to complete orders or cause financial damage

## Conclusion

Even though this was reported before, **the fact that it still exists 2+ years later** is concerning. This could be:
- A **regression** (fix was incomplete)
- A **new vulnerability** (different endpoint/vector)
- A **missed fix** (original fix didn't cover all endpoints)

We should investigate further to determine which case this is.

