# Инструкция: Выполнить тест в консоли браузера

## Шаг 1: Открыть консоль
1. Убедитесь что залогинены под **Account B** (suobup@dunkos.xyz)
2. Нажмите **F12** (или Ctrl+Shift+I)
3. Перейдите на вкладку **Console**
4. Введите: `allow pasting` (если требуется)

## Шаг 2: Выполнить код
Скопируйте весь код из файла `test_cart_write_console.js` и вставьте в консоль, затем нажмите Enter.

## Шаг 3: Проверить результат
Код автоматически:
1. Получит текущее состояние корзины Account A
2. Попробует добавить товар через `/articles` endpoint
3. Если не сработает - попробует через `/add` endpoint
4. Проверит корзину после модификации
5. Выведет результат в консоль

## Шаг 4: Сделать скриншоты
Если тест успешен:
1. Скриншот консоли с результатами
2. Скриншот Network tab с успешным запросом
3. Скриншот Response в Network tab

## Альтернативный вариант (если первый не работает)
Выполните по одному:

```javascript
// 1. Получить корзину
fetch('https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50', {credentials: 'include'}).then(r => r.json()).then(c => console.log('Before:', c.articles.length, 'items'));

// 2. Добавить товар
fetch('https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json', 'x-requested-with': 'XMLHttpRequest'},
  body: JSON.stringify({offerId: 2966095})
}).then(r => {console.log('Status:', r.status); return r.text();}).then(t => console.log('Response:', t.substring(0, 300)));

// 3. Проверить корзину снова
fetch('https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50', {credentials: 'include'}).then(r => r.json()).then(c => console.log('After:', c.articles.length, 'items'));
```

