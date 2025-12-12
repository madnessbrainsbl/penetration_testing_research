# Execute Tests - Step by Step

## Test Plan

1. **Test Original 2023 Vectors** - Check if original attack still works (regression)
2. **Test Higher Impact** - Find ways to complete orders, change addresses, etc.
3. **Test Checkout Flow** - Test if we can complete checkout for victim
4. **Test Order Modification** - Test if we can modify existing orders

## Instructions

### Step 1: Test Original Vectors

1. Login as Account B (`suobup@dunkos.xyz`)
2. Open browser console (F12)
3. Execute: Copy and paste code from `scripts/test_original_vectors.js`

**What to look for:**
- If any test returns HTTP 200/201 → **REGRESSION CONFIRMED**
- If all return 404/403 → Original vectors fixed, but our vector still works

### Step 2: Test Higher Impact

1. Still logged in as Account B
2. Execute: Copy and paste code from `scripts/test_higher_impact.js`

**What to look for:**
- Can we apply coupons? → Financial impact
- Can we change delivery address? → Order hijacking
- Can we complete orders? → **CRITICAL**
- Can we modify payment? → Financial fraud

### Step 3: Test Checkout Flow

1. Still logged in as Account B
2. Execute: Copy and paste code from `scripts/test_checkout_flow.js`

**What to look for:**
- Can we get checkout state for victim's cart?
- Can we submit checkout?
- Can we create orders?

### Step 4: Test Order Modification

1. Still logged in as Account B
2. Execute: Copy and paste code from `scripts/test_order_modification.js`

**What to look for:**
- Can we list victim's orders?
- Can we modify/cancel orders?

## Expected Results

### Best Case Scenario
- ✅ Original vectors still work → **REGRESSION** (worth reporting)
- ✅ Can complete orders → **CRITICAL IMPACT** (worth reporting)
- ✅ Can modify orders → **CRITICAL IMPACT** (worth reporting)

### Good Case Scenario
- ❌ Original vectors fixed
- ✅ Our vector works (different endpoint)
- ✅ Can change addresses/coupons → **HIGHER IMPACT**

### Worst Case Scenario
- ❌ All tests return 404/403
- ✅ Only our basic write works
- → Focus on other vulnerabilities

## Next Steps After Testing

1. **Document all findings** in logs folder
2. **If regression found**: Prepare regression report
3. **If higher impact found**: Update report with new impact
4. **If nothing new**: Move to other vulnerability types

## Time Estimate

- Step 1: 5 minutes
- Step 2: 10 minutes
- Step 3: 10 minutes
- Step 4: 10 minutes
- **Total: ~35 minutes**





