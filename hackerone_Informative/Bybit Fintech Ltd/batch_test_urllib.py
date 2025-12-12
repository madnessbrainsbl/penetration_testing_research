#!/usr/bin/env python3
import urllib.request
import ssl
import time
import hmac
import hashlib
import json

print("START", flush=True)

API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api.bybit.com"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

endpoint = "/v5/order/amend-batch"
payload_dict = {
    "category": "linear",
    "request": [
        {"symbol": "BTCUSDT", "orderId": "fake-1", "qty": "0.001"},
        {"symbol": "BTCUSDT", "orderId": "fake-2", "qty": "0.001"}
    ]
}

payload = json.dumps(payload_dict)
timestamp = str(int(time.time() * 1000) + 29000)  # +29sec offset
recv_window = "5000"

sign_payload = f"{timestamp}{API_KEY}{recv_window}{payload}"
signature = hmac.new(bytes(API_SECRET, "utf-8"), bytes(sign_payload, "utf-8"), hashlib.sha256).hexdigest()

print(f"Timestamp: {timestamp}", flush=True)
print(f"Signature: {signature[:20]}...", flush=True)

req = urllib.request.Request(BASE_URL + endpoint, data=payload.encode(), method='POST')
req.add_header("X-BAPI-API-KEY", API_KEY)
req.add_header("X-BAPI-SIGN", signature)
req.add_header("X-BAPI-SIGN-TYPE", "2")
req.add_header("X-BAPI-TIMESTAMP", timestamp)
req.add_header("X-BAPI-RECV-WINDOW", recv_window)
req.add_header("Content-Type", "application/json")

print("Sending request...", flush=True)

try:
    response = urllib.request.urlopen(req, context=ctx, timeout=5)
    data = response.read().decode()
    print(f"Response: {data}", flush=True)
except Exception as e:
    print(f"Error: {e}", flush=True)

print("DONE", flush=True)
