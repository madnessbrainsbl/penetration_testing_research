import time
import hmac
import hashlib
import urllib.parse

api_key = "22JSr5zWpW0eReC6rE"
api_secret = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
timestamp = str(int(time.time() * 1000))
recv_window = "5000"
params = "accountType=UNIFIED"

payload = f"{timestamp}{api_key}{recv_window}{params}"
signature = hmac.new(bytes(api_secret, "utf-8"), bytes(payload, "utf-8"), hashlib.sha256).hexdigest()

print(f"curl -v -H 'X-BAPI-API-KEY: {api_key}' -H 'X-BAPI-SIGN: {signature}' -H 'X-BAPI-SIGN-TYPE: 2' -H 'X-BAPI-TIMESTAMP: {timestamp}' -H 'X-BAPI-RECV-WINDOW: {recv_window}' 'https://api-testnet.bybit.com/v5/account/wallet-balance?{params}'")
