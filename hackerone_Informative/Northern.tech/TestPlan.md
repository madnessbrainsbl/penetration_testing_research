# 🎯 Northern.tech Bug Bounty Test Plan

## Важная информация о программе
- **SaaS тестирование**: staging.hosted.mender.io (НЕ PROD!)
- **Email для регистрации**: h1username@wearehackerone.com
- **Заголовок в запросах**: `X-HackerOne-Research: [H1 username]`
- **Rewards**: $200 (Low) - $3000 (Critical)

---

## 0️⃣ ОПРЕДЕЛЕНИЕ SCOPE

### ✅ Checklist
- [ ] Изучить вкладку Scope на HackerOne
- [ ] Выписать все in-scope домены (SaaS)
  - [ ] Mender: staging.hosted.mender.io
  - [ ] CFEngine: (проверить scope)
- [ ] Записать 3 репозитория SourceCode
  - [ ] Mender Server
  - [ ] Mender Client
  - [ ] CFEngine Community
- [ ] Определить Executable (агент/CLI)
- [ ] **КРИТИЧНО**: Прочитать Program Guidelines
- [ ] **КРИТИЧНО**: Прочитать Safe Harbor
  - [ ] Лимиты по трафику (НЕТ bruteforce/DoS)
  - [ ] Запрет тестов на прод
  - [ ] Запрет на excessive network traffic

### 📋 Известные Scope Exclusions (НЕ РЕПОРТИТЬ!)
- ❌ Functionality disabled in UI but accessible via API
- ❌ All users can add pending devices
- ❌ REST APIs showing extra info to low-privilege users (`/iot-manager/integrations`, `/useradm/roles`)
- ❌ Username/email enumeration
- ❌ Missing rate limits (они есть, просто высокие)
- ❌ Comments and non-product code
- ❌ Subscription model bypass
- ❌ Old/deprecated functionality (disabled by default)
- ❌ Package manager dependency/typo squatting
- ❌ Email verification not enforced

### 📝 Заметки
```
Scope домены:

Scope репозитории:

Scope executable:

Запреты:
```

---

## 1️⃣ ПОНЯТЬ ПРОДУКТ И АРХИТЕКТУРУ

### ✅ Checklist
- [ ] Изучить страницу продуктов Northern.tech
  - [ ] **Mender**: OTA-обновления устройств (IoT)
  - [ ] **CFEngine**: управление серверами
- [ ] Понять концепцию multi-tenancy в Mender
- [ ] Зафиксировать ключевые сущности:
  - [ ] Организации/тенанты
  - [ ] Пользователи и роли
  - [ ] Устройства
  - [ ] Группы устройств
  - [ ] Релизы (артефакты)
  - [ ] Кампании обновлений (deployments)
  - [ ] API токены
  - [ ] Device authentication keys

### 🎯 Areas of Focus (из программы)
- Authentication bypass / Account takeover
- Access control bypass
- Remote code execution
- Bypassing signature check for artifacts
- Taking over Mender Server from device

### 📝 Заметки
```
Архитектура:

Ключевые endpoints:

Роли и права:
```

---

## 2️⃣ ПОДГОТОВКА СТЕНДА

### ✅ Checklist
- [ ] Завести аккаунт #1 на staging.hosted.mender.io
  - Email: `h1username@wearehackerone.com`
- [ ] Завести аккаунт #2 для проверки изоляции
  - Email: `h1username+2@wearehackerone.com`
- [ ] Создать минимум 2 изолированные организации/тенанта
- [ ] Настроить тестовые устройства:
  - [ ] Опция 1: Реальный девайс (если разрешено)
  - [ ] Опция 2: Эмуляция (проверить разрешения)
- [ ] **Burp Suite**: настроить прокси
  - [ ] Импортировать CA сертификат в браузер
  - [ ] Проверить перехват HTTPS
- [ ] Настроить инструменты:
  - [ ] Browser (Firefox/Chrome + расширения)
  - [ ] httpie / curl / Postman
  - [ ] git для клонирования репозиториев
  - [ ] VM/контейнер для агента (опционально)

### 📝 Учетные записи
```
Account 1:
  Email: 
  Password: 
  Org ID: 
  User ID: 

Account 2:
  Email: 
  Password: 
  Org ID: 
  User ID: 

Devices:
  Device 1 ID: 
  Device 2 ID: 
```

---

## 3️⃣ РЕКОГНОСЦИРОВКА ВЕБ-ЧАСТИ

### ✅ Checklist
- [ ] Пройти как обычный пользователь все экраны:
  - [ ] Регистрация
  - [ ] Логин
  - [ ] Сброс пароля
  - [ ] Приглашения пользователей
  - [ ] Dashboard
  - [ ] Список устройств
  - [ ] Создание/просмотр релизов
  - [ ] Создание/управление кампаниями (deployments)
  - [ ] Настройки организации
  - [ ] Управление пользователями/ролями
  - [ ] API keys management
- [ ] В Burp: сохранить все эндпоинты
- [ ] Сгруппировать функционал:
  - [ ] Authentication
  - [ ] Account management
  - [ ] Organization/roles management
  - [ ] Devices/groups management
  - [ ] Releases/artifacts management
  - [ ] Deployment campaigns
  - [ ] API access (keys, tokens)

### 📝 Карта API endpoints
```
Authentication:
- POST /api/management/v1/useradm/auth/login
- POST /api/management/v1/useradm/auth/logout
- ...

Devices:
- GET /api/management/v2/devauth/devices
- POST /api/management/v2/devauth/devices/{id}/auth/{aid}/status
- ...

Deployments:
- ...

(заполнить по мере обнаружения)
```

---

## 4️⃣ ТЕСТ АУТЕНТИФИКАЦИИ

### ✅ Checklist: Логин/Регистрация/Сброс пароля
- [ ] Проверить rate-limit на login
- [ ] Проверить rate-limit на registration
- [ ] Проверить rate-limit на password reset
- [ ] ❌ Username/email enumeration (OUT OF SCOPE!)
- [ ] Слабые пароли (если принимаются)
- [ ] SQL injection в форме логина

### ✅ Checklist: Сессии и токены
- [ ] Переиспользование устаревших токенов после logout
- [ ] Инвалидация токена при смене пароля
- [ ] Session fixation
- [ ] JWT analysis (если используется):
  - [ ] Weak signature algorithm
  - [ ] `alg: none`
  - [ ] Key confusion attack
  - [ ] Expiration check
- [ ] Cookie security:
  - [ ] HttpOnly flag
  - [ ] Secure flag
  - [ ] SameSite attribute

### 📝 Находки
```
Endpoint: 
Issue: 
PoC: 
Impact: 
```

---

## 5️⃣ ТЕСТ АВТОРИЗАЦИИ И ИЗОЛЯЦИИ ТЕНАНТОВ ⚡ ПРИОРИТЕТ #1

### ✅ Checklist: IDOR / BOLA
Использовать 2 аккаунта/организации. Меняем ID во всех запросах:

#### Организации
- [ ] Просмотр настроек чужой org (`GET /organizations/{org_id}`)
- [ ] Редактирование настроек чужой org (`PUT /organizations/{org_id}`)
- [ ] Удаление чужой org

#### Устройства
- [ ] Просмотр списка устройств чужой org
- [ ] Просмотр деталей чужого устройства
- [ ] Изменение статуса чужого устройства (accept/reject/decommission)
- [ ] Удаление чужого устройства
- [ ] "Кража" устройства (смена org_id)

#### Deployments (кампании OTA)
- [ ] Просмотр чужих deployments
- [ ] Запуск deployment на чужие устройства
- [ ] Изменение существующего чужого deployment
- [ ] Отмена чужого deployment
- [ ] Доступ к артефактам чужой org

#### Пользователи и роли
- [ ] Просмотр списка пользователей чужой org
- [ ] Приглашение пользователя в чужую org
- [ ] Изменение роли пользователя в чужой org
- [ ] Повышение собственных привилегий
- [ ] Удаление пользователей из чужой org

### ✅ Checklist: Mass Assignment
- [ ] Добавление `role` / `is_admin` в запросах на создание/изменение
- [ ] Подмена `org_id` / `tenant_id` в теле запроса
- [ ] Добавление скрытых полей из ответов API

### ✅ Checklist: Токены и API keys
- [ ] Использование токена низкоприоритетной роли для admin-операций
- [ ] Device token для доступа к management API
- [ ] Переиспользование revoked API keys
- [ ] Утечка токенов в ответах API

### 📝 Критичные находки (топ приоритет для репорта)
```
IDOR Example:
  Endpoint: 
  Org A ID: 
  Org B ID: 
  Request: 
  Response: 
  Impact: Cross-tenant data leak
```

---

## 6️⃣ ТЕСТ БИЗНЕС-ЛОГИКИ OTA / УСТРОЙСТВ

### ✅ Checklist: Операции с устройствами
- [ ] Энроллмент устройства:
  - [ ] Можно ли зарегистрировать устройство от имени чужой org
  - [ ] Можно ли "переместить" устройство между org
- [ ] Де-регистрация:
  - [ ] Удаление чужого устройства без прав
- [ ] Смена группы:
  - [ ] Перемещение устройства в чужую группу
- [ ] Device authentication:
  - [ ] Переиспользование device keys
  - [ ] Подделка device identity

### ✅ Checklist: OTA-кампании
- [ ] Запуск обновления на чужие устройства
- [ ] Изменение активной кампании (смена артефакта)
- [ ] Rollback чужой кампании
- [ ] Upload вредоносного артефакта:
  - [ ] Bypass signature verification ⚡ CRITICAL
  - [ ] Path traversal в артефакте
  - [ ] Command injection через metadata

### ✅ Checklist: Логирование и история
- [ ] Утечка device IDs чужих org в логах
- [ ] Утечка org IDs
- [ ] Утечка внутренних URL/IP
- [ ] Утечка ключей/токенов в логах

### 📝 Находки
```
Business Logic Issue:
  Scenario: 
  Steps: 
  Impact: 
```

---

## 7️⃣ ТЕСТ КЛИЕНТСКОГО СЛОЯ (XSS/CSRF/ИНЪЕКЦИИ)

### ✅ Checklist: XSS
Поля для тестирования:
- [ ] Названия устройств
- [ ] Описания устройств
- [ ] Названия групп устройств
- [ ] Названия релизов
- [ ] Описания кампаний
- [ ] Metadata артефактов
- [ ] Поля профиля пользователя
- [ ] Названия организаций

Типы XSS:
- [ ] Stored XSS
- [ ] Reflected XSS
- [ ] DOM-based XSS

Контексты:
- [ ] HTML context: `<script>alert(1)</script>`
- [ ] Attribute context: `" onload=alert(1) "`
- [ ] JavaScript context: `'; alert(1); //`
- [ ] URL context: `javascript:alert(1)`

### ✅ Checklist: CSRF
- [ ] Создание пользователя
- [ ] Изменение роли пользователя
- [ ] Запуск deployment
- [ ] Изменение настроек организации
- [ ] Удаление устройства
- [ ] Генерация API key

### ✅ Checklist: Injection
- [ ] SQL Injection в параметрах поиска/фильтрации
- [ ] NoSQL Injection (если используется MongoDB и т.д.)
- [ ] Command Injection в полях, обрабатываемых на сервере
- [ ] LDAP Injection (если есть интеграция)
- [ ] XML/XXE Injection

### 📝 Находки
```
XSS:
  Location: 
  Payload: 
  Type: 
  Impact: 
```

---

## 8️⃣ ТЕСТ API

### ✅ Checklist: Общие проверки API
- [ ] Собрать список всех API endpoints из:
  - [ ] Burp history
  - [ ] Документация API (если есть)
  - [ ] Исходный код

### ✅ Checklist: Для каждого endpoint
- [ ] Authentication: нужен ли токен, можно ли без него
- [ ] Authorization: токен низкой роли vs admin-операции
- [ ] IDOR: смена ID в path/query/body
- [ ] HTTP Method bypass (PUT вместо POST, GET вместо POST)
- [ ] Content-Type manipulation
- [ ] Rate limiting bypass:
  - [ ] X-Forwarded-For
  - [ ] X-Real-IP
  - [ ] Параллельные запросы

### ✅ Checklist: Специфичные проверки
- [ ] `/api/management/v1/useradm/` - User management
- [ ] `/api/management/v2/devauth/` - Device auth
- [ ] `/api/management/v1/deployments/` - Deployments
- [ ] `/api/management/v1/inventory/` - Device inventory
- [ ] API versioning issues (v1 vs v2)

### 📝 API Endpoints Table
| Endpoint | Method | Auth Required | Authorization Check | IDOR Test | Status |
|----------|--------|---------------|---------------------|-----------|--------|
| | | | | | |

---

## 9️⃣ ИСХОДНЫЙ КОД (SourceCode)

### ✅ Checklist: Клонировать репозитории
- [ ] Mender Server: `git clone https://github.com/mendersoftware/mender-server`
- [ ] Mender Client: `git clone https://github.com/mendersoftware/mender-client`
- [ ] CFEngine Community: (найти правильный репозиторий)

### ✅ Checklist: Code Review приоритеты
#### 1. Authorization middleware
- [ ] Проверка org/tenant из сессии vs из параметров
- [ ] Отсутствие проверок прав
- [ ] Hardcoded bypass tokens

#### 2. REST API handlers
- [ ] Контроллеры устройств
- [ ] Контроллеры deployments
- [ ] Контроллеры пользователей/ролей
- [ ] Контроллеры организаций

#### 3. Database queries
- [ ] SQL injection точки
- [ ] NoSQL injection
- [ ] Отсутствие параметризованных запросов

#### 4. Artifact processing
- [ ] Проверка подписи артефактов
- [ ] Path traversal при распаковке
- [ ] Command injection в metadata

#### 5. Secrets management
- [ ] Hardcoded API keys
- [ ] Hardcoded database credentials
- [ ] Secrets в конфигах / env vars

### 📝 Code Analysis Notes
```
File: 
Line: 
Issue: 
Exploitable: Yes/No
PoC on live system: 
```

---

## 🔟 EXECUTABLE (АГЕНТ/CLI)

### ✅ Checklist: Получить и проанализировать
- [ ] Скачать Mender client
- [ ] Скачать CFEngine agent (если in-scope)
- [ ] Установить в изолированном окружении

### ✅ Checklist: Безопасность клиента
#### 1. Коммуникация с сервером
- [ ] TLS verification
- [ ] Certificate pinning
- [ ] MITM возможности

#### 2. Хранение credentials
- [ ] Где хранятся device keys
- [ ] Permissions на файлы с ключами
- [ ] Шифрование ключей

#### 3. Privilege escalation
- [ ] Небезопасные флаги командной строки
- [ ] Environment variables для RCE
- [ ] Sudo/suid issues
- [ ] File write в privileged locations

#### 4. Artifact processing на клиенте
- [ ] Bypass signature check
- [ ] Path traversal при установке
- [ ] Command execution через update scripts

### 📝 Client Security Issues
```
Component: 
Issue: 
Impact: Local RCE / Privilege Escalation / ...
PoC: 
```

---

## 1️⃣1️⃣ ФИКСАЦИЯ РЕЗУЛЬТАТОВ И ПОДГОТОВКА РЕПОРТА

### Структура отчета для HackerOne:
```markdown
## Summary
[Краткое описание уязвимости в 1-2 предложениях]

## Asset
- Type: Web Application / API / Source Code / Executable
- URL/Location: [точный in-scope asset]

## Weakness
- CWE: [CWE номер если известен]
- Category: [IDOR / XSS / RCE / ...]

## Severity Assessment
- CVSS: [calculated score]
- Impact: [Critical/High/Medium/Low]

## Steps To Reproduce
1. [Точные шаги]
2. [С примерами запросов/команд]
3. [С скриншотами при необходимости]

## Impact
[Детальное описание в терминах бизнеса Northern.tech:
- Cross-tenant data access
- Device takeover
- RCE on server/device
- Account takeover
- Data leak]

## Proof of Concept
[Запросы curl, скриншоты, видео]

## Suggested Fix
[Опционально, но приветствуется]
```

### ✅ Checklist перед отправкой
- [ ] Asset точно in-scope
- [ ] Уязвимость воспроизводима на текущий момент
- [ ] Не попадает в Scope Exclusions
- [ ] Есть реальный security impact
- [ ] Приложен PoC
- [ ] Отчет детальный и понятный
- [ ] Проверена уникальность (нет дупликатов)

---

## 1️⃣2️⃣ ПРИОРИТЕТЫ ПОИСКА

### 🔴 КРИТИЧЕСКИЙ ПРИОРИТЕТ (Critical/High bounty)
1. **Cross-tenant/Cross-org IDOR** в любых операциях
2. **RCE** на сервере или устройстве
3. **Device takeover** чужих устройств
4. **Authentication bypass** / **Account takeover**
5. **Bypass signature verification** для артефактов
6. **Privilege escalation** (user → admin)

### 🟡 СРЕДНИЙ ПРИОРИТЕТ (Medium/High bounty)
1. **XSS в admin-панели** с реальным impact (например, кража admin token)
2. **CSRF** на критичные операции
3. **API keys/secrets leak** позволяющие доступ к внутренним сервисам
4. **Mass assignment** для повышения привилегий

### 🟢 НИЗКИЙ ПРИОРИТЕТ (Low/Medium bounty)
1. **Информационные утечки** (version disclosure, path disclosure)
2. **XSS** в некритичных местах
3. **Missing security headers** (при условии реального impact)

### ❌ НЕ ТРАТИТЬ ВРЕМЯ (Out of scope)
- Username enumeration
- Missing rate limits (они есть!)
- Subscription bypass
- UI/API feature parity
- Low-privilege users seeing extra API info
- Email verification not enforced

---

## 📊 ПРОГРЕСС ТЕСТИРОВАНИЯ

| Блок | Статус | Критичных | Высоких | Средних | Низких | Заметки |
|------|--------|-----------|---------|---------|--------|---------|
| 0. Scope | ⬜ | - | - | - | - | |
| 1. Архитектура | ⬜ | - | - | - | - | |
| 2. Стенд | ⬜ | - | - | - | - | |
| 3. Разведка | ⬜ | - | - | - | - | |
| 4. Аутентификация | ⬜ | - | - | - | - | |
| 5. Авторизация | ⬜ | - | - | - | - | |
| 6. Бизнес-логика | ⬜ | - | - | - | - | |
| 7. XSS/CSRF | ⬜ | - | - | - | - | |
| 8. API | ⬜ | - | - | - | - | |
| 9. Source Code | ⬜ | - | - | - | - | |
| 10. Executable | ⬜ | - | - | - | - | |

**Легенда**: ⬜ Не начато | 🟡 В процессе | ✅ Завершено

---

## 🔗 ПОЛЕЗНЫЕ ССЫЛКИ

### HackerOne
- Program page: [вставить ссылку]
- Submit report: [вставить ссылку]

### Northern.tech Resources
- Mender docs: https://docs.mender.io/
- CFEngine docs: https://docs.cfengine.com/
- Mender Blog (CVEs): https://mender.io/blog/tag/cve
- CFEngine CVEs: https://cfengine.com/tags/cve/

### Testing Environment
- Staging: https://staging.hosted.mender.io
- Account 1: [email]
- Account 2: [email]

### GitHub Repositories
- Mender Server: https://github.com/mendersoftware/mender-server
- Mender Client: https://github.com/mendersoftware/mender-client
- CFEngine: [URL]

---

**Создан**: [дата]  
**Обновлен**: [дата]  
**Версия**: 1.0
