# 📋 Quick Testing Checklist

Краткая версия для быстрого доступа. Полные детали в TestPlan.md.

## 🔴 CRITICAL PRIORITY (тестировать первым)

### Cross-Tenant IDOR (Account A → Account B)
```bash
# Используй 2 аккаунта и проверь:
```

- [ ] **Devices**: GET/PUT/DELETE `/api/management/v2/devauth/devices/{victim_device_id}`
- [ ] **Deployments**: GET/PUT/DELETE `/api/management/v1/deployments/deployments/{victim_deployment_id}`
- [ ] **Users**: GET/PUT/DELETE `/api/management/v1/useradm/users/{victim_user_id}`
- [ ] **Artifacts**: GET/DELETE `/api/management/v1/deployments/artifacts/{victim_artifact_id}`
- [ ] **Organization settings**: GET/PUT `/api/management/v1/...` (найти endpoint для org)

### Device Takeover
- [ ] Регистрация устройства в чужую org (подмена org_id/tenant_id)
- [ ] Перемещение устройства между org
- [ ] Изменение device authentication status чужого устройства

### Deployment Takeover
- [ ] Создание deployment на чужие устройства
- [ ] Изменение активного deployment другой org
- [ ] Доступ к артефактам другой org

### RCE via Artifacts
- [ ] Upload malicious artifact
- [ ] Bypass signature verification
- [ ] Path traversal в artifact
- [ ] Command injection через artifact metadata

## 🟠 HIGH PRIORITY

### Privilege Escalation
- [ ] Mass assignment: добавить `role`, `is_admin` при создании user
- [ ] Mass assignment: изменить `org_id`, `tenant_id` в запросах
- [ ] User → Admin через PUT `/users/{id}` с `roles: ["RBAC_ROLE_PERMIT_ALL"]`
- [ ] Device token для management API операций

### Authentication Issues
- [ ] Session не инвалидируется после logout
- [ ] Session не инвалидируется после смены пароля
- [ ] JWT без проверки expiration
- [ ] JWT weak algorithm (alg: none, HS256 → RS256)

### Business Logic
- [ ] Создать deployment без прав
- [ ] Abort чужого deployment
- [ ] Accept/Reject чужих pending devices
- [ ] Изменить чужие API keys

## 🟡 MEDIUM PRIORITY

### XSS (проверить все input поля)
```
Test в: device names, deployment descriptions, group names, user emails
```

- [ ] Device name: `TEST<script>alert(1)</script>`
- [ ] Deployment description: `<img src=x onerror=alert(1)>`
- [ ] Group name: `<svg onload=alert(1)>`
- [ ] User profile fields
- [ ] Artifact metadata/description

### CSRF
- [ ] Create user (есть ли CSRF token?)
- [ ] Change user role
- [ ] Start deployment
- [ ] Modify organization settings
- [ ] Delete device
- [ ] Generate API key

### API Issues
- [ ] Rate limiting bypass (X-Forwarded-For, параллельные запросы)
- [ ] Method tampering (GET → POST, PUT → DELETE)
- [ ] Content-Type manipulation
- [ ] API versioning bypass (v1 vs v2)

### Information Disclosure
- [ ] Error messages revealing internal paths
- [ ] Stack traces in responses
- [ ] Sensitive data in logs
- [ ] API keys в responses
- [ ] Internal IPs в responses

## 🟢 LOW PRIORITY

### Security Headers
- [ ] Missing HSTS
- [ ] Missing CSP
- [ ] Missing X-Frame-Options
- [ ] Missing X-Content-Type-Options

### Informational
- [ ] Version disclosure
- [ ] Technology stack disclosure
- [ ] Verbose error messages

## ❌ DON'T WASTE TIME (Out of Scope)

- ❌ Username/email enumeration
- ❌ Missing rate limits (они есть, просто высокие!)
- ❌ Low-privilege users видят extra API info (`/iot-manager/integrations`, `/useradm/roles`)
- ❌ All users can add pending devices
- ❌ Subscription bypass
- ❌ Email verification not enforced
- ❌ UI/API feature parity

## 🛠 Quick Commands

### IDOR Test
```bash
python3 scripts/test_idor.py
```

### Get API Token
```bash
curl -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: username" \
  -d '{"email":"email@example.com","password":"password"}'
```

### Test IDOR Manually
```bash
# With Account A token, try to access Account B resources:
export TOKEN_A="<token_a>"
export TOKEN_B="<token_b>"
export VICTIM_DEVICE_ID="<device_id_from_account_b>"

curl -X GET https://staging.hosted.mender.io/api/management/v2/devauth/devices/$VICTIM_DEVICE_ID \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: username"

# If status 200 → VULNERABLE!
# If status 403/404 → Protected
```

### Parse Burp Requests
```bash
# 1. In Burp: Select requests → Right-click → Copy
# 2. Paste into file: burp_export.txt
# 3. Parse:
python3 scripts/burp_request_parser.py burp_export.txt
```

### XSS Test
```bash
# Copy payloads
cat scripts/xss_payloads.txt

# Test in UI fields or API:
curl -X POST https://staging.hosted.mender.io/api/management/v2/devauth/devices \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: username" \
  -d '{"name":"TEST<script>alert(1)</script>"}'
```

## 📝 Quick Documentation

### Found vulnerability?
```bash
# 1. Open Findings.md
# 2. Add to appropriate section (Critical/High/Medium/Low)
# 3. Fill template:
#    - Description
#    - Impact  
#    - Steps to Reproduce
#    - PoC (curl commands, screenshots)

# 4. Update TestPlan.md progress
# 5. Update ProgressTracker.csv
```

### Session notes
```bash
# Copy template
cp notes/session_template.md notes/session_$(date +%Y%m%d).md

# Edit with your findings
vim notes/session_$(date +%Y%m%d).md
```

## 🎯 Daily Goals

Хороший день тестирования:
- [ ] Протестировать 1 major блок из TestPlan.md
- [ ] Проверить минимум 10 endpoints на IDOR
- [ ] Найти и задокументировать минимум 1 interesting behavior
- [ ] Обновить документацию (Findings.md, ProgressTracker.csv)

## 🚀 Pro Tips

1. **Всегда начинай с IDOR** - самый высокий impact, простой тест
2. **Используй 2 браузера** - один для Account A, один для Account B
3. **Burp Repeater = твой друг** - быстро модифицировать и отправлять запросы
4. **Документируй сразу** - не откладывай на потом
5. **Читай source code** - многие уязвимости видны в коде
6. **Следи за Burp HTTP History** - новые endpoints появляются при клике в UI

## ⚡ Speed Run (1 hour)

Если времени мало, тест приоритетное:

```
1. [10 min] Создать 2 аккаунта
2. [10 min] Получить токены и IDs ресурсов
3. [30 min] Запустить test_idor.py на:
   - Devices
   - Deployments  
   - Users
4. [10 min] Если найдено - задокументировать в Findings.md
```

## 📞 Need Help?

- Детали в `TestPlan.md`
- Быстрый старт в `QUICKSTART.md`
- Общая информация в `README.md`
- Scope exclusions в `Introduction.txt`

---

**Print this and keep nearby while testing!** 📌
