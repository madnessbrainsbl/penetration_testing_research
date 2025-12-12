#!/bin/bash

TOKEN="REDACTED_DATABRICKS_TOKEN"
WORKSPACE="https://dbc-54d21f62-0426.cloud.databricks.com"
ORG_ID="716445344710955"

echo "=== Testing New Workspace ==="
echo "Workspace: $WORKSPACE"
echo "Org ID: $ORG_ID"
echo ""

# Test authentication
echo "[1] Testing Authentication..."
curl -s "$WORKSPACE/api/2.0/preview/scim/v2/Me" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.userName // .error_code' | head -5

echo ""
echo "[2] Getting SQL Warehouses..."
curl -s "$WORKSPACE/api/2.0/sql/warehouses" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.warehouses[0].id // "No warehouses"'

echo ""
echo "[3] Getting Unity Catalog info..."
curl -s "$WORKSPACE/api/2.1/unity-catalog/catalogs" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.catalogs[].name' 2>/dev/null || echo "No catalogs or error"

echo ""
echo "=== Setup Complete ==="

