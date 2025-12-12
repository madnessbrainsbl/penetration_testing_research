# Что нужно для реального пентеста Zooplus

## 🎯 Цель: Найти ЭКСПЛУАТИРУЕМЫЕ уязвимости с реальным impact

Не defense-in-depth (headers), а:
- Account Takeover
- Data Breach  
- IDOR на sensitive data
- XSS с кражей cookies
- CSRF на critical actions
- Business logic bypass

---

## 📋 Что мне нужно от вас:

### 1. Session Cookies для обоих аккаунтов

**Account A: duststorm155@doncong.com**
```
Нужен session cookie после login
```

**Account B: suobup@dunkos.xyz**
```
Нужен session cookie после login
```

#### Как получить:
1. Открыть браузер
2. Залогиниться на www.zooplus.de
3. F12 → Application → Cookies → www.zooplus.de
4. Найти cookie `sid` или `session`
5. Скопировать **полное значение**

**Формат:**
```
ACCOUNT_A_COOKIE="sid=eyJhbGc..."
ACCOUNT_B_COOKIE="sid=eyJhbGc..."
```

---

### 2. Свежие Password Reset Tokens

**Для обоих аккаунтов:**

#### Как получить:
1. Перейти на https://www.zooplus.de
2. Кликнуть "Passwort vergessen"
3. Ввести email аккаунта
4. Открыть письмо
5. Скопировать **ПОЛНУЮ ссылку** из письма

**Формат:**
```
ACCOUNT_A_RESET_URL="https://mailing.zooplus.de/lnk/..."
ACCOUNT_B_RESET_URL="https://mailing.zooplus.de/lnk/..."
```

---

### 3. Bearer Tokens (если есть)

Из `report.txt` видно что вы получали access tokens через PKCE.

**Если есть - предоставьте:**
```
ACCOUNT_A_BEARER="Bearer eyJhbGc..."
ACCOUNT_B_BEARER="Bearer eyJhbGc..."
```

---

## 🔥 Что я буду тестировать с этими данными:

### IDOR Tests (CRITICAL)

С двумя session cookies:

```python
# Account A gets order ID: 12345
GET /api/orders/12345
Cookie: account_a_session

# Account B tries to access it
GET /api/orders/12345
Cookie: account_b_session
→ If 200 OK = CRITICAL IDOR!
```

**Тестирую:**
- Orders/Invoices
- Saved addresses
- Payment methods
- Customer config
- Loyalty points

---

### Password Reset IDOR (CRITICAL)

С двумя reset tokens:

```python
# Get Account A reset token
# Decode JWT, extract user_id

# Get Account B reset token  
# Try to reset Account A password using Account B token
→ If works = CRITICAL ACCOUNT TAKEOVER!
```

---

### Stored XSS (HIGH)

С session cookie:

```python
# Inject XSS in profile
POST /api/profile/update
Cookie: session
{"firstName": "<img src=x onerror=alert(1)>"}

# View profile
GET /myaccount/profile
→ If XSS executes = HIGH severity!
```

**Тестирую:**
- Profile fields
- Address fields
- Product reviews
- Gift messages
- Order notes

---

### CSRF (HIGH)

```python
# Without CSRF token
POST /api/profile/update
Cookie: session
{"email": "attacker@evil.com"}

→ If 200 OK = Email hijacking via CSRF!
```

**Тестирую:**
- Password change
- Email change
- Add payment method
- Change address
- Place order

---

### Business Logic (CRITICAL)

```python
# Price manipulation
POST /api/cart/add
{"productId": "123", "price": 0.01}

# Negative quantity
POST /api/cart/update
{"quantity": -10}

# Promo code reuse
POST /api/cart/apply-promo
{"code": "SAVE50"}
# Use same code 10 times
```

---

## 📊 Ожидаемые находки:

| Vulnerability | Severity | Impact |
|--------------|----------|--------|
| IDOR on Orders | CRITICAL | View any user's orders |
| IDOR on Invoices | HIGH | Download any PDF invoice |
| Password Reset IDOR | CRITICAL | Account takeover |
| Stored XSS | HIGH | Session hijacking |
| CSRF Password Change | HIGH | Account takeover |
| Price Manipulation | CRITICAL | Free products |
| Promo Code Reuse | MEDIUM | Unlimited discounts |

---

## 🚀 Как предоставить данные:

### Вариант 1: Создать файл

```bash
# Zooplus/test_credentials.txt

ACCOUNT_A_EMAIL=duststorm155@doncong.com
ACCOUNT_A_COOKIE=sid=eyJhbGc...
ACCOUNT_A_RESET_URL=https://mailing.zooplus.de/lnk/...
ACCOUNT_A_BEARER=Bearer eyJhbGc...

ACCOUNT_B_EMAIL=suobup@dunkos.xyz  
ACCOUNT_B_COOKIE=sid=eyJhbGc...
ACCOUNT_B_RESET_URL=https://mailing.zooplus.de/lnk/...
ACCOUNT_B_BEARER=Bearer eyJhbGc...
```

### Вариант 2: Прямо в chat

Просто пришлите мне:
```
Session cookies:
Account A: ...
Account B: ...

Reset links:
Account A: ...
Account B: ...
```

---

## ⚡ После получения данных:

Я **немедленно** запущу:

1. ✅ `test_idor_comprehensive.py` - IDOR на все endpoints
2. ✅ `test_xss_full.py` - XSS во всех формах
3. ✅ `test_csrf.py` - CSRF на critical actions  
4. ✅ `real_attack_account_takeover.py` - Password reset IDOR
5. ✅ `test_business_logic.py` - Price manipulation, promo abuse

**Результат:** Готовые HackerOne репорты с:
- Proof of Concept
- Impact assessment
- CVSS scores
- Remediation steps

---

## 🎯 Итог:

**Без этих данных** - могу только сканить public endpoints (уже сделал, ничего не нашел)

**С этими данными** - найду реальные критичные уязвимости за 10-15 минут!

Что мне прислать? 👆

