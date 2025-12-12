# ⚡ IMMEDIATE ACTION PLAN

**Программа ПУБЛИЧНАЯ с 17 ноября 2025. Начинаем тестирование СЕЙЧАС.**

---

## 🎯 ЧТО ДЕЛАТЬ ПРЯМО СЕЙЧАС

### ✅ Подготовка завершена
- [x] Тест-план создан (TestPlan.md - 12 блоков)
- [x] Инструменты готовы (scripts/)
- [x] Документация обновлена
- [x] CFEngine план создан
- [x] Сессия запланирована

### ⚡ НАЧАТЬ ТЕСТИРОВАНИЕ

---

## 📋 ШАГИ НА СЕГОДНЯ

### ШАГ 1: Создать аккаунты (10 минут)

```bash
# Открыть в браузере:
# https://staging.hosted.mender.io

# Создать Account 1:
# Email: [твой_h1_username]@wearehackerone.com
# Password: [сильный пароль]

# Создать Account 2:
# Email: [твой_h1_username]+victim@wearehackerone.com
# Password: [сильный пароль]
```

**ВАЖНО**: Сохрани credentials в notes/session_20251123_initial.md

---

### ШАГ 2: Получить токены (5 минут)

```bash
# Терминал 1 - получить токен Account 1
export H1_USER="твой_username"

curl -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: $H1_USER" \
  -d '{"email":"твой_email@wearehackerone.com","password":"твой_пароль"}'

# Сохрани токен
export TOKEN_A="полученный_токен"

# Терминал 2 - получить токен Account 2
curl -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: $H1_USER" \
  -d '{"email":"твой_email+victim@wearehackerone.com","password":"пароль_2"}'

export TOKEN_B="полученный_токен"
```

**Проверь токены работают**:
```bash
curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" | jq

curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "X-HackerOne-Research: $H1_USER" | jq
```

---

### ШАГ 3: Получить ID для IDOR тестов (5 минут)

```bash
# Account 1 - узнать свои IDs
curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" | jq > account1_me.json

# Account 2 - узнать ID жертвы
curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "X-HackerOne-Research: $H1_USER" | jq > account2_me.json

# Сохрани user_id из account2_me.json
export VICTIM_USER_ID=$(jq -r '.id' account2_me.json)
echo "Victim User ID: $VICTIM_USER_ID"

# Попробуй получить устройства (могут быть пустыми, это ОК)
curl -s https://staging.hosted.mender.io/api/management/v2/devauth/devices \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "X-HackerOne-Research: $H1_USER" | jq > account2_devices.json
```

---

### ШАГ 4: ПЕРВЫЙ IDOR ТЕСТ (5 минут) ⚡

**КРИТИЧЕСКИЙ ТЕСТ**: Может ли Account A получить данные Account B?

```bash
# ТЕСТ 1: Получить инфо о пользователе жертвы
echo "=== TEST 1: Cross-tenant user IDOR ==="
curl -v -X GET "https://staging.hosted.mender.io/api/management/v1/useradm/users/$VICTIM_USER_ID" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" \
  2>&1 | grep "< HTTP"

# Ожидается: 403 или 404
# Если 200 → 🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!

# ТЕСТ 2: Получить список пользователей
echo "=== TEST 2: List users cross-tenant ==="
curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" | jq

# Проверь: видны ли пользователи из Account B?
# Если да → 🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!

# ТЕСТ 3: Получить устройства
echo "=== TEST 3: List devices cross-tenant ==="
curl -s https://staging.hosted.mender.io/api/management/v2/devauth/devices \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: $H1_USER" | jq

# Должны видеть только свои устройства
# Если видны чужие → 🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ!
```

**Если нашел IDOR → немедленно документируй в Findings.md!**

---

### ШАГ 5: Автоматический IDOR тест (10 минут)

```bash
cd /media/sf_vremen/hackerone/Northern.tech

python3 scripts/test_idor.py

# Введи:
# - H1 username: твой_username
# - Token A (attacker): $TOKEN_A
# - Token B (victim): $TOKEN_B  
# - Victim User ID: $VICTIM_USER_ID
# - Victim Device ID: (если есть)
# - Victim Deployment ID: (если есть)

# Скрипт автоматически проверит:
# - Доступ к устройствам
# - Доступ к deployments
# - Доступ к пользователям
# - Возможность изменения
# - Возможность удаления
```

---

### ШАГ 6: Настроить Burp Suite (15 минут)

```bash
# 1. Запустить Burp Suite
# 2. Proxy → Options → Import CA certificate
# 3. Установить в браузер
# 4. Открыть https://staging.hosted.mender.io
# 5. Войти в Account 1
# 6. Пройти по всем разделам UI:
#    - Dashboard
#    - Devices
#    - Deployments
#    - Users
#    - Settings
# 7. В Burp HTTP History увидишь все запросы
```

---

### ШАГ 7: Экспорт и анализ endpoints (10 минут)

```bash
# В Burp Suite:
# 1. HTTP History → фильтр "staging.hosted.mender.io"
# 2. Select all requests (Ctrl+A)
# 3. Right-click → Copy requests
# 4. Вставить в файл: burp_export.txt

# Парсить:
python3 scripts/burp_request_parser.py burp_export.txt

# Результат в endpoint_tests/:
ls endpoint_tests/
cat endpoint_tests/api_catalog.md
cat endpoint_tests/test_matrix.md
```

---

## 🎯 ПЕРВЫЕ ЦЕЛИ

### Цель 1: Найти Cross-Tenant IDOR ⚡ TOP PRIORITY
- Используй 2 аккаунта
- Пробуй получить доступ между org
- **Bounty**: $1000-$3000 (Critical/High)

### Цель 2: Privilege Escalation
- Mass assignment (добавить role: "admin")
- User → Admin через API
- **Bounty**: $500-$1000 (High/Medium)

### Цель 3: RCE через Artifacts
- Требует больше времени
- Изучи source code
- **Bounty**: $3000 (Critical)

---

## 📊 ОТСЛЕЖИВАНИЕ

### Обновляй документы:
```bash
# После каждой находки:
vim Findings.md

# После каждой сессии:
vim TestPlan.md  # отметить прогресс
vim ProgressTracker.csv  # обновить endpoints
vim notes/session_20251123_initial.md  # заметки
```

---

## 🚨 ЕСЛИ НАШЕЛ УЯЗВИМОСТЬ

### 1. Немедленно документируй
```bash
vim Findings.md
# Заполни шаблон в соответствующей секции (Critical/High/Medium/Low)
```

### 2. Создай детальный PoC
```bash
# Сохрани все curl команды
# Сделай скриншоты
# Запиши видео если нужно
```

### 3. Проверь scope exclusions
```bash
cat Introduction.txt | grep -A 50 "Scope exclusions"
# Убедись что твоя находка НЕ в списке exclusions
```

### 4. Подготовь репорт
- Используй шаблон из TestPlan.md блок 11
- Title: четкий и понятный
- Asset: точный URL/компонент
- Steps: детальные, воспроизводимые
- Impact: в терминах бизнеса Northern.tech
- PoC: curl команды, скриншоты

### 5. Submit на HackerOne
- Через кнопку "Submit report" на странице программы
- Приложи все доказательства
- Укажи severity по CVSS

---

## 📝 КОМАНДЫ ДЛЯ КОПИРОВАНИЯ

### Сохрани в файл commands.sh:
```bash
#!/bin/bash

# Configuration
export H1_USER="твой_username"
export TOKEN_A="токен_account_1"
export TOKEN_B="токен_account_2"
export VICTIM_USER_ID="user_id_account_2"

# Quick tests
alias mender-me-a='curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me -H "Authorization: Bearer $TOKEN_A" -H "X-HackerOne-Research: $H1_USER" | jq'

alias mender-me-b='curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me -H "Authorization: Bearer $TOKEN_B" -H "X-HackerOne-Research: $H1_USER" | jq'

alias mender-devices-a='curl -s https://staging.hosted.mender.io/api/management/v2/devauth/devices -H "Authorization: Bearer $TOKEN_A" -H "X-HackerOne-Research: $H1_USER" | jq'

alias mender-users-a='curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users -H "Authorization: Bearer $TOKEN_A" -H "X-HackerOne-Research: $H1_USER" | jq'

# IDOR test
alias idor-user='curl -v https://staging.hosted.mender.io/api/management/v1/useradm/users/$VICTIM_USER_ID -H "Authorization: Bearer $TOKEN_A" -H "X-HackerOne-Research: $H1_USER" 2>&1 | grep "< HTTP"'

echo "Mender testing aliases loaded!"
echo "Commands: mender-me-a, mender-me-b, mender-devices-a, mender-users-a, idor-user"
```

Загрузи: `source commands.sh`

---

## ⏱️ TIMELINE НА СЕГОДНЯ

```
[10 min] Создать 2 аккаунта
[5 min]  Получить токены
[5 min]  Получить IDs для тестов
[5 min]  Первый IDOR тест вручную
[10 min] Автоматический IDOR тест
[15 min] Настроить Burp Suite
[10 min] Пройти по UI и экспортировать endpoints

ИТОГО: ~60 минут для начального тестирования
```

---

## 🎯 SUCCESS CRITERIA

### Минимальный успех сегодня:
- [x] 2 аккаунта созданы
- [x] Токены получены
- [x] IDOR тесты выполнены
- [x] Endpoints задокументированы
- [x] Burp настроен

### Хороший успех:
- [ ] Найдена хотя бы 1 уязвимость
- [ ] PoC подготовлен
- [ ] Репорт отправлен

### Отличный успех:
- [ ] Найден Critical/High IDOR
- [ ] Репорт триажнут
- [ ] Bounty получен

---

## 🔗 БЫСТРЫЕ ССЫЛКИ

- **Staging**: https://staging.hosted.mender.io
- **Session notes**: notes/session_20251123_initial.md
- **Findings**: Findings.md
- **Test Plan**: TestPlan.md
- **Checklist**: CHECKLIST.md
- **CFEngine Plan**: CFEngine_TestPlan.md

---

## ❓ ВОПРОСЫ?

- Правила программы: `cat Introduction.txt`
- Быстрый старт: `cat QUICKSTART.md`
- Краткая справка: `cat CHECKLIST.md`
- Полный план: `cat TestPlan.md`

---

# 🚀 НАЧИНАЙ ПРЯМО СЕЙЧАС!

```bash
# Открой браузер:
firefox https://staging.hosted.mender.io &

# Открой терминал для команд:
cd /media/sf_vremen/hackerone/Northern.tech

# Открй notes для записей:
vim notes/session_20251123_initial.md

# GO! 🎯
```

**Вся подготовка завершена. Инструменты готовы. Начинай тестирование!**

Good hunting! 🔍💰
