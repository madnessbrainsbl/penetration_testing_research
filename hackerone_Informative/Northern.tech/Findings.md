# 📋 Findings Log - Northern.tech

## Метаданные
- **Researcher**: [Your H1 username]
- **Program**: Northern.tech
- **Start Date**: [дата начала]
- **Last Updated**: [дата]

---

## 🎯 Статистика

| Severity | Submitted | Triaged | Resolved | Bounty |
|----------|-----------|---------|----------|--------|
| Critical | 0 | 0 | 0 | $0 |
| High | 0 | 0 | 0 | $0 |
| Medium | 0 | 0 | 0 | $0 |
| Low | 0 | 0 | 0 | $0 |
| **Total** | **0** | **0** | **0** | **$0** |

---

## 🔴 CRITICAL FINDINGS

### CRIT-001: [Название уязвимости]
**Status**: 🟡 Draft / 📤 Submitted / ✅ Triaged / 💰 Bounty / ❌ Closed  
**Submitted**: [дата]  
**Asset**: [URL/component]  
**Category**: [IDOR/RCE/Auth Bypass/etc]

#### Description
[Краткое описание проблемы]

#### Impact
- [ ] Cross-tenant data access
- [ ] Device takeover
- [ ] RCE
- [ ] Authentication bypass
- [ ] Other: [specify]

#### Steps to Reproduce
```
1. 
2. 
3. 
```

#### Proof of Concept
```bash
# Request
curl -X POST https://staging.hosted.mender.io/api/... \
  -H "Authorization: Bearer TOKEN" \
  -H "X-HackerOne-Research: username" \
  -d '{"org_id": "victim_org"}'

# Response
{
  "devices": [...]
}
```

#### Screenshots
- [Link to screenshot 1]
- [Link to screenshot 2]

#### HackerOne Report
- Report ID: #[number]
- URL: [link]
- Current Status: [status]
- Bounty: $[amount]

#### Notes
```
[Additional notes, observations, fix suggestions]
```

---

## 🟠 HIGH FINDINGS

### HIGH-001: [Название уязвимости]
**Status**: 🟡 Draft  
**Submitted**: -  
**Asset**: [URL/component]  
**Category**: [category]

#### Description


#### Impact


#### Steps to Reproduce


#### Proof of Concept


#### HackerOne Report


#### Notes


---

## 🟡 MEDIUM FINDINGS

### MED-001: [Название уязвимости]
**Status**: 🟡 Draft  
**Submitted**: -  
**Asset**: [URL/component]  
**Category**: [category]

#### Description


#### Impact


#### Steps to Reproduce


#### Proof of Concept


#### HackerOne Report


#### Notes


---

## 🟢 LOW FINDINGS

### LOW-001: [Название уязвимости]
**Status**: 🟡 Draft  
**Submitted**: -  
**Asset**: [URL/component]  
**Category**: [category]

#### Description


#### Impact


#### Steps to Reproduce


#### Proof of Concept


#### HackerOne Report


#### Notes


---

## 📝 INFORMATIONAL / NOT EXPLOITABLE

### INFO-001: [Название наблюдения]
**Asset**: [URL/component]

#### Description


#### Why Not Exploitable


---

## ❌ OUT OF SCOPE / FALSE POSITIVES

### OOS-001: [Название]
**Reason**: [Scope exclusion / False positive / Duplicate]

#### Description


#### Why Out of Scope
- [ ] Listed in Scope Exclusions
- [ ] No real security impact
- [ ] Working as intended per program
- [ ] Duplicate of #[report]
- [ ] Other: [specify]

---

## 🧪 TESTING NOTES

### Interesting Observations
```
- 
- 
```

### Potential Areas to Explore Further
```
- 
- 
```

### Questions for Program Team
```
- 
- 
```

### Blocked/Need Help
```
- 
- 
```

---

## 📊 COVERAGE MATRIX

| Component | Tested | Findings | Notes |
|-----------|--------|----------|-------|
| Authentication | ⬜ | 0 | |
| User Management | ⬜ | 0 | |
| Organization Management | ⬜ | 0 | |
| Device Management | ⬜ | 0 | |
| Device Groups | ⬜ | 0 | |
| Artifacts/Releases | ⬜ | 0 | |
| Deployments | ⬜ | 0 | |
| API Keys | ⬜ | 0 | |
| Integrations | ⬜ | 0 | |
| Audit Logs | ⬜ | 0 | |

---

## 🔄 CHANGELOG

### [Date] - Session N
- Started testing: [component]
- Found: [brief summary]
- Submitted: [report IDs]

### [Date] - Session 2
- 

### [Date] - Session 1
- Initial setup
- Created test accounts
- Mapped application

---

**Last Review**: [date]  
**Next Actions**: [what to test next]
