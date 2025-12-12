# Как найти реальные endpoints для модификации корзины

## Критически важно: найти через Network tab

Все тесты вернули 404/405, кроме state API который вернул 200 но HTML. Нужно найти реальные endpoints.

## Инструкция:

1. **Откройте DevTools** (F12) → вкладка **Network**
2. **Очистите запросы** (кнопка Clear)
3. **Добавьте фильтр**: `cart` или `api`
4. **Добавьте товар в свою корзину** (Account B) через интерфейс сайта:
   - Перейдите на страницу товара
   - Нажмите "В корзину" / "Add to cart"
   - ИЛИ перейдите в корзину и измените количество товара
5. **Найдите запрос** который отправляется при добавлении/изменении:
   - Ищите POST/PUT запросы
   - URL должен содержать `cart` или `article`
   - Проверьте Request payload
6. **Скопируйте**:
   - Полный URL endpoint
   - Method (POST/PUT/DELETE)
   - Headers (особенно важные)
   - Request payload (body)

## Что искать:

- `POST /checkout/api/cart-api/...`
- `PUT /checkout/api/cart-api/...`
- `POST /api/cart/...`
- `POST /semiprotected/api/...`
- Любые запросы с `article`, `add`, `update`, `remove` в URL

## После нахождения:

Используйте тот же endpoint и payload, но с UUID корзины Account A вместо своей.

## Пример:

Если нашли:
```
POST https://www.zooplus.de/checkout/api/cart-api/v2/cart/YOUR_CART_UUID/articles
Body: {"offerId": 12345, "quantity": 1}
```

То попробуйте:
```javascript
fetch('https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({offerId: 2966095, quantity: 1})
}).then(r => r.json()).then(console.log);
```

