# КРИТИЧЕСКИ ВАЖНО: Найти точный payload из Network tab

## Проблема:
Тест вернул HTTP 200, но ответ был HTML (не JSON), и корзина не изменилась. Это значит, что payload неправильный.

## Решение:
Нужно найти **точный payload** который отправляется когда вы изменяете количество в СВОЕЙ корзине.

## Пошаговая инструкция:

### Шаг 1: Подготовка
1. Откройте DevTools (F12)
2. Перейдите на вкладку **Network**
3. Очистите запросы (кнопка Clear или Ctrl+L)
4. Добавьте фильтр: введите `set-article-quantity` в поле фильтра

### Шаг 2: Измените количество в СВОЕЙ корзине
1. Откройте корзину: https://www.zooplus.de/checkout/cart
2. Измените количество любого товара (например, с 1 на 2)
3. ИЛИ удалите товар из корзины

### Шаг 3: Найдите запрос
1. В Network tab должен появиться запрос `set-article-quantity`
2. Кликните на него
3. Откройте вкладку **Payload** (или **Request**)
4. Скопируйте **весь JSON payload**

### Шаг 4: Скопируйте также Headers
1. В том же запросе откройте вкладку **Headers**
2. Скопируйте все заголовки (особенно важны):
   - `Content-Type`
   - `Accept`
   - `X-Requested-With`
   - Любые другие кастомные заголовки

### Шаг 5: Используйте точный payload
Вставьте скопированный payload в тест и замените:
- `articleId` на ID товара из корзины Account A
- `cartUuid` (если есть) на UUID корзины Account A: `6bd223b4-5040-4faa-ba85-6a85c1ec2d50`

## Пример того что нужно найти:

```
POST /semiprotected/api/checkout/state-api/v2/set-article-quantity
Headers:
  Content-Type: application/json
  Accept: application/json
  ...

Body (Payload):
{
  "articleId": 2966422,
  "quantity": 2,
  "cartUuid": "ваш-uuid-корзины"
}
```

## После получения точного payload:

Выполните этот код в консоли (Account B залогинен):

```javascript
const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

// Получить корзину Account A
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
  credentials: 'include'
})
.then(r => r.json())
.then(cart => {
  const articleId = cart.articles[0]?.id;
  console.log(`Before: ${cart.articles.length} items, ${cart.summary.grandTotal} EUR`);
  
  // ИСПОЛЬЗУЙТЕ ТОЧНЫЙ PAYLOAD ИЗ NETWORK TAB!
  return fetch(`https://www.zooplus.de/semiprotected/api/checkout/state-api/v2/set-article-quantity`, {
    method: "POST",
    credentials: "include",
    headers: {
      // ВСТАВЬТЕ ТОЧНЫЕ HEADERS ИЗ NETWORK TAB
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      // ВСТАВЬТЕ ТОЧНЫЙ PAYLOAD ИЗ NETWORK TAB
      // Замените только articleId и cartUuid
      articleId: articleId,
      quantity: 2,
      cartUuid: CART_UUID
    })
  });
})
.then(async r => {
  const text = await r.text();
  console.log(`Status: ${r.status}`);
  console.log(`Response: ${text.substring(0, 500)}`);
  
  if (r.status === 200 && text.includes("json") || !text.includes("<!DOCTYPE")) {
    console.log("[!!!] SUCCESS! Got JSON response!");
  }
  
  // Проверить корзину
  return fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  });
})
.then(r => r.json())
.then(cart => {
  console.log(`After: ${cart.articles.length} items, ${cart.summary.grandTotal} EUR`);
});
```

