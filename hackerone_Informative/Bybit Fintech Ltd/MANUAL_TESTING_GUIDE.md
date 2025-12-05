# 🎯 Manual Testing Guide - Bybit Bug Bounty

## Приоритет 1: OAuth Flow Testing (30 минут)

### Подготовка:
1. Открой Burp Suite (или включи прокси в браузере)
2. Перейди на https://www.bybit.com/login
3. Настрой Intercept ON

### Тест 1: OAuth Open Redirect
**Шаги:**
1. Нажми "Continue with Google" (или Apple)
2. Intercept запрос в Burp
3. Найди параметр `redirect_uri` или `callback_url`
4. Измени на: `https://evil.com`
5. Forward запрос
6. **Проверь:** Редиректит ли на evil.com с authorization code?

**Если ДА → CRITICAL vulnerability!**

```
Payload examples:
- https://evil.com
- https://evil.com@bybit.com
- https://bybit.com.evil.com
- //evil.com
- https://bybit.com/../../../evil.com
```

### Тест 2: OAuth State Parameter Bypass (CSRF)
**Шаги:**
1. Начни OAuth flow
2. Intercept запрос с `state` parameter
3. Удали параметр `state` полностью
4. Forward
5. **Проверь:** Проходит ли авторизация без state?

**Если ДА → HIGH vulnerability (OAuth CSRF)**

### Тест 3: Authorization Code Leakage
**Шаги:**
1. Завершить OAuth flow
2. Посмотри в History на redirect URL после callback
3. **Проверь:** Есть ли `code=` в URL после редиректа?
4. **Проверь:** Есть ли `access_token=` в URL (implicit flow)?

**Если authorization code в URL → MEDIUM vulnerability**

---

## Приоритет 2: Account Pre-Takeover (45 минут)

### Подготовка:
1. Нужен второй email (используй temp mail: https://temp-mail.org)
2. Или создай email с typo: `youremail+typo@gmail.com`

### Сценарий атаки:
```
Цель: Захватить аккаунт жертвы ДО того как она зарегистрируется
```

**Шаги:**
1. **Создай аккаунт с email жертвы** (без верификации):
   - Регистрация: victim@gmail.com
   - НЕ верифицируй email

2. **Привяжи Google OAuth к этому аккаунту**:
   - Settings → Security → Link Google
   - Используй ТВОЙ Google аккаунт

3. **Симулируй что жертва регистрируется через Google**:
   - Выйди из аккаунта
   - Нажми "Continue with Google"
   - Используй ДРУГОЙ Google (или создай новый)
   - Email должен совпадать: victim@gmail.com

4. **Проверка:**
   - В какой аккаунт попал?
   - Если в ТВОЙ (созданный в шаге 1) → **CRITICAL vulnerability!**
   - Это значит атакующий может pre-link OAuth и захватить аккаунт

---

## Приоритет 3: Sub-Account IDOR (60 минут)

### Подготовка:
1. В твоём основном аккаунте создай 2 sub-accounts:
   - Sub1
   - Sub2

2. Для каждого sub-account создай API key

### Тест 1: Cross-Sub-Account Access
**Используя API key от Sub1, попробуй получить данные Sub2:**

```python
# Используй API key Sub1
API_KEY_SUB1 = "..."
SECRET_SUB1 = "..."

# Попробуй получить:
# 1. Wallet balance Sub2
# 2. Orders Sub2  
# 3. API keys Sub2

# Endpoints:
# /v5/account/wallet-balance?accountType=UNIFIED
# /v5/order/history?category=linear
# /v5/user/query-api
```

**Если получаешь данные Sub2 с ключом Sub1 → CRITICAL IDOR!**

### Тест 2: Sub → Master Escalation
**Используя API key от Sub1, попробуй изменить настройки Master:**

```python
# С ключом Sub1 попробуй:
# 1. Изменить email Master
# 2. Создать новый sub-account
# 3. Изменить API permissions Master
# 4. Transfer из Master wallet

# Endpoints:
# POST /v5/user/update-email
# POST /v5/user/create-sub-member
# POST /v5/user/update-api
# POST /v5/asset/transfer/inter-transfer
```

**Если что-то работает → CRITICAL Privilege Escalation!**

---

## Приоритет 4: 2FA Bypass (30 минут)

### Подготовка:
1. Включи 2FA на твоём аккаунте
2. Сохрани backup codes

### Тест 1: Code Reuse
**Шаги:**
1. Login с правильным паролем
2. Введи 2FA code
3. Сохрани этот code
4. Logout
5. Login снова
6. **Попробуй использовать СТАРЫЙ code**

**Если работает → MEDIUM vulnerability (code reuse)**

### Тест 2: Brute Force 2FA
**Шаги:**
1. Login с правильным паролем
2. Попробуй brute force 2FA код (000000 - 999999)
3. **Проверь:** Есть ли rate limiting?
4. **Проверь:** Блокируется ли аккаунт после N попыток?

```bash
# Automated test:
for i in {000000..000100}; do
    echo "Testing: $i"
    curl -X POST https://api.bybit.com/user/v1/2fa/verify \
         -d "code=$i" \
         -d "session=YOUR_SESSION"
done
```

**Если нет rate limit → MEDIUM/HIGH vulnerability**

### Тест 3: Backup Code Bypass
**Шаги:**
1. Login с паролем (без 2FA)
2. На странице 2FA нажми "Use backup code"
3. **Не вводи код, а просто:**
   - Измени URL
   - Или нажми "Skip"
   - Или используй expired session

**Если проходит авторизация → HIGH vulnerability**

---

## Приоритет 5: Referral/Affiliate Abuse (45 минут)

### Тест 1: Self-Referral
**Шаги:**
1. Получи свой referral link: https://www.bybit.com/invite?ref=YOURCODE
2. Logout
3. Создай НОВЫЙ аккаунт используя свой же referral link
4. **Проверь:** Получил ли bonus на ОБА аккаунта?

**Если ДА → MEDIUM business logic bug (self-referral abuse)**

### Тест 2: Mass Registration
**Шаги:**
1. Создай 10+ аккаунтов с temp emails
2. Все через твой referral link
3. **Проверь:** 
   - Есть ли limit на количество referrals?
   - Можно ли использовать один IP?
   - Требуется ли KYC для bonus?

**Если нет лимитов → MEDIUM abuse vector**

### Тест 3: Bonus Manipulation
**Шаги:**
1. Зарегистрируйся через referral
2. Получи welcome bonus (например 10 USDT)
3. Попробуй:
   - Withdraw сразу
   - Transfer на другой аккаунт
   - Trade и вывести profit

**Проверь условия:** 
- Требуется ли trading volume?
- Можно ли обойти через internal transfer?

---

## Автоматизированные скрипты

Я создам скрипты для тестирования Sub-Account IDOR и 2FA:
