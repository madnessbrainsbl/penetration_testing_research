# Databricks API Testing Results

**Date**: 2025-12-05
**Workspace**: `dbc-4b448b2e-59b6.cloud.databricks.com`
**Org-ID**: `3047257800510966`

---

## 🔐 Authentication Info

- **User**: `tanyia45@doncong.com`
- **User ID**: `71067049637275`
- **Role**: **ADMIN** (workspace admin)
- **Entitlements**: `allow-cluster-create`, `allow-instance-pool-create`
- **Groups**: `users`, `admins`, `account users`

---

## 🗺️ Infrastructure Discovered

### AWS Resources
```
S3 Bucket: s3://dbstorage-prod-uxpk8/uc/7a87b952-5720-4ccc-a12d-96af43371ad4/8510a0a1-dcbd-483f-8dfd-3ec964685259
IAM Role: arn:aws:iam::654654154626:role/dbrole-prod-sbfd2
Unity Catalog Role: arn:aws:iam::414351767826:role/unity-catalog-prod-UCMasterRole-14S5ZJVKOTYTL
External ID: 7a87b952-5720-4ccc-a12d-96af43371ad4
AWS Accounts: 654654154626, 414351767826
```

### Unity Catalog
```
Metastore: metastore_aws_us_east_2
Metastore ID: 8510a0a1-dcbd-483f-8dfd-3ec964685259
Region: us-east-2
Cloud: AWS
Global ID: aws:us-east-2:8510a0a1-dcbd-483f-8dfd-3ec964685259
```

### SQL Warehouse
```
ID: c38a578e1ced2494
Name: Serverless Starter Warehouse
JDBC: jdbc:spark://dbc-4b448b2e-59b6.cloud.databricks.com:443/default
```

---

## 📊 API Endpoints Tested

### Workspace Objects
| Endpoint | Status | Notes |
|----------|--------|-------|
| `/api/2.0/workspace/list` | ✅ | Lists /Users, /Shared, /Repos |
| `/api/2.0/clusters/list` | ✅ | Empty (no clusters) |
| `/api/2.0/jobs/list` | ✅ | Empty (no jobs) |
| `/api/2.0/secrets/scopes/list` | ✅ | Empty (no secrets) |
| `/api/2.0/dbfs/list` | ✅ | /Volumes, /Workspace, /databricks-datasets |
| `/api/2.0/token/list` | ✅ | Shows own tokens |
| `/api/2.0/repos` | ✅ | Empty |
| `/api/2.0/pipelines` | ✅ | Empty |
| `/api/2.0/git-credentials` | ✅ | Empty |

### SCIM/Users
| Endpoint | Status | Notes |
|----------|--------|-------|
| `/api/2.0/preview/scim/v2/Me` | ✅ | Own user info |
| `/api/2.0/preview/scim/v2/Users` | ✅ | All workspace users |
| `/api/2.0/preview/scim/v2/Groups` | ✅ | All groups with members |

### Unity Catalog
| Endpoint | Status | Notes |
|----------|--------|-------|
| `/api/2.1/unity-catalog/catalogs` | ✅ | samples, system, workspace |
| `/api/2.1/unity-catalog/metastores` | ✅ | Metastore info |
| `/api/2.1/unity-catalog/external-locations` | ✅ | S3 location exposed |
| `/api/2.1/unity-catalog/storage-credentials` | ✅ | **AWS IAM ARN exposed** |
| `/api/2.1/unity-catalog/schemas` | ✅ | System schemas |
| `/api/2.1/unity-catalog/tables` | ✅ | System tables |

### SQL Statements
| Endpoint | Status | Notes |
|----------|--------|-------|
| `/api/2.0/sql/statements` | ✅ | Can execute SQL |
| `system.billing.*` | ✅ | Empty (new workspace) |
| `system.access.audit` | ✅ | Empty (new workspace) |

---

## 🧪 Security Tests

### IDOR Testing
| Test | Result |
|------|--------|
| Access other user IDs | ❌ 404 Not Found |
| Access other workspace IDs | ❌ Invalid token |
| Access other metastore IDs | ❌ Resource not found |
| Sequential directory IDs | ❌ 404 Not Found |

### Cross-Tenant
| Test | Result |
|------|--------|
| Token on community.cloud.databricks.com | ❌ Invalid token |
| Token on other workspaces | ❌ Invalid token |

### Permission Boundaries
| Resource | Access Level |
|----------|--------------|
| /Volumes (DBFS) | ❌ PERMISSION_DENIED |
| /Workspace (DBFS) | ❌ PERMISSION_DENIED |
| Other user directories | ❌ Only own directory visible |

---

## 📋 Information Disclosure Findings

### 1. AWS IAM Role ARN Exposure (LOW/MEDIUM)
**Endpoint**: `/api/2.1/unity-catalog/storage-credentials`
```json
{
  "role_arn": "arn:aws:iam::654654154626:role/dbrole-prod-sbfd2",
  "unity_catalog_iam_arn": "arn:aws:iam::414351767826:role/unity-catalog-prod-UCMasterRole-14S5ZJVKOTYTL",
  "external_id": "7a87b952-5720-4ccc-a12d-96af43371ad4"
}
```
**Impact**: Exposes AWS account IDs and IAM role names. Could be used for:
- AWS account enumeration
- Targeted phishing
- Role confusion attacks if misconfigured

### 2. S3 Bucket Path Disclosure (LOW)
**Location**: Storage credentials and external locations
```
s3://dbstorage-prod-uxpk8/uc/7a87b952-5720-4ccc-a12d-96af43371ad4/8510a0a1-dcbd-483f-8dfd-3ec964685259
```

### 3. Internal IDs Exposure (INFORMATIVE)
- Metastore IDs
- User IDs
- Group IDs
- Catalog IDs
- Schema IDs

---

## ❌ Not Vulnerable

- **IDOR**: User/object ID enumeration blocked
- **Cross-tenant**: Token isolation works correctly
- **Permission escalation**: Could not self-assign higher permissions
- **DBFS traversal**: Blocked at /Volumes and /Workspace
- **SQL injection**: Parameterized queries

---

## 📝 Conclusion

This is a **fresh test workspace** with minimal data. The key finding is the **AWS IAM Role ARN exposure** through the storage-credentials API, which reveals:
- AWS Account IDs
- IAM Role names
- External IDs

This is likely "expected behavior" for admin users, but worth documenting.

**Recommendation**: Continue testing with second account for true IDOR verification.

---

---

## 🔬 IDOR Test Setup (In Progress)

### Created Resources (User 1 - Admin)
```
Storage Credential: test-cred-idor (ISOLATED mode)
Secret Scope: test-secret-scope
Secret Key: api-key
Cluster Policy: test-policy-injection (serverless profile)
User 2: test-user2@doncong.com (ID: 75676850361637)
```

### Next Steps for IDOR Testing
1. Get User 2 token (need them to login and generate PAT)
2. Test if User 2 can:
   - View storage credentials (`/api/2.1/unity-catalog/storage-credentials`)
   - Read secrets (`/api/2.0/secrets/list`)
   - Access ISOLATED resources
   - Modify resources owned by User 1

### Vectors Still To Test
- [ ] Service Principal Token Leak via SQL
- [ ] Workspace Files symlink escape
- [ ] Git Credential IDOR (need git credentials added)
- [ ] Model Registry UDF PrivEsc
- [ ] Delta Live Tables Pipeline IDOR

---

---

## 🛡️ Cross-Tenant Security Testing

### Setup
- **Workspace 1**: `dbc-4b448b2e-59b6.cloud.databricks.com` (Account: `7a87b952-5720-4ccc-a12d-96af43371ad4`)
- **Workspace 2**: `dbc-8da6da2e-9b9c.cloud.databricks.com` (Account: `8be5da54-165d-4f29-8c39-93533ca5af90`)

### Resources Created for Testing
**Workspace 1:**
- Storage Credential: `test-cred-idor` (ID: `295f4101-1718-4115-a90e-4042eb2a5b7d`)
- Secret Scope: `test-secret-scope` with key `api-key`
- Git Credential: `293720980815113`
- Cluster Policy: `test-policy-injection`

**Workspace 2:**
- Storage Credential: `ws2-secret-cred` (ID: `f401c7e7-af6c-4866-9386-968354efa4c8`)
- Secret Scope: `ws2-secret-scope` with key `super-secret-key`

### Cross-Tenant Test Results
| Test | WS1 → WS2 | WS2 → WS1 |
|------|----------|----------|
| Storage Credential by Name | ❌ NOT EXIST | ❌ NOT EXIST |
| Storage Credential by ID | ❌ NOT EXIST | ❌ NOT EXIST |
| Secret Scope Access | ❌ NOT EXIST | ❌ NOT EXIST |
| Metastore Access | ❌ NOT EXIST | ❌ NOT EXIST |
| User ID Lookup | ❌ NOT FOUND | ❌ NOT FOUND |
| Token with wrong workspace | ❌ 403 Invalid Org | ❌ 403 Invalid Org |

### ✅ Conclusion: Cross-Tenant Isolation WORKS

Databricks properly isolates:
- Storage credentials
- Secrets
- Metastores
- User IDs
- Tokens are workspace-bound

---

## ⚠️ Same-Workspace IDOR Testing Status

**BLOCKED:** Cannot complete same-workspace IDOR test because:
1. Second user (`gba8320255061457@mosquito.pw`) is in different Databricks Account
2. Cannot login to first workspace - accounts are isolated
3. Need second user to create PAT in first workspace

**To complete this test, need:**
- New Databricks account with fresh email
- Add to first workspace
- Generate PAT
- Test IDOR between users

---

*Testing performed: 2025-12-05*

