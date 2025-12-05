import json
import requests
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Configuration
TENANT_TOKEN = "VZQnuRdl-2sjUgaRehS_pwmJXAzbsdM-vn3kEresr2k"
HOST = "https://staging.hosted.mender.io"
MAC_ADDRESS = "de:ad:be:ef:00:01"

# 1. Generate RSA Keys
print("[*] Generating RSA keys...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

pubkey_str = pem_public.decode('utf-8')
print("[+] Keys generated.")

# 2. Prepare Auth Request Body
id_data = json.dumps({"mac": MAC_ADDRESS})
auth_body = {
    "id_data": id_data,
    "pubkey": pubkey_str,
    "tenant_token": TENANT_TOKEN
}
body_json = json.dumps(auth_body)
print(f"[*] Auth Body: {body_json[:100]}...")

# 3. Sign the Body
print("[*] Signing request...")
signature = private_key.sign(
    body_json.encode('utf-8'),
    padding.PKCS1v15(),
    hashes.SHA256()
)
signature_b64 = base64.b64encode(signature).decode('utf-8')

# 4. Send Request
print("[*] Sending auth request...")
headers = {
    "Content-Type": "application/json",
    "X-Men-Signature": signature_b64
}

url = f"{HOST}/api/devices/v1/authentication/auth_requests"
try:
    r = requests.post(url, headers=headers, data=body_json)
    print(f"[*] Status Code: {r.status_code}")
    print(f"[*] Response: {r.text}")
    
    if r.status_code == 401:
        print("[-] 401 Unauthorized. This is expected for first request (pending approval).")
    elif r.status_code == 200:
        print("[+] 200 OK! We got a token!")
    else:
        print(f"[-] Unexpected status: {r.status_code}")
except Exception as e:
    print(f"[-] Error: {e}")

