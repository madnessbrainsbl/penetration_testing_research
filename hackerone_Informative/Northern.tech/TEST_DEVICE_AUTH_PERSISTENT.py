import json
import requests
import base64
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Configuration
TENANT_TOKEN = "VZQnuRdl-2sjUgaRehS_pwmJXAzbsdM-vn3kEresr2k"
HOST = "https://staging.hosted.mender.io"
MAC_ADDRESS = "de:ad:be:ef:00:02" # New device
KEY_FILE = "device_private.pem"

# 1. Load or Generate RSA Keys
if os.path.exists(KEY_FILE):
    print("[*] Loading existing private key...")
    with open(KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
else:
    print("[*] Generating NEW RSA keys...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Save key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(KEY_FILE, "wb") as f:
        f.write(pem)

public_key = private_key.public_key()
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pubkey_str = pem_public.decode('utf-8')

# 2. Prepare Auth Request Body
id_data = json.dumps({"mac": MAC_ADDRESS})
auth_body = {
    "id_data": id_data,
    "pubkey": pubkey_str,
    "tenant_token": TENANT_TOKEN
}
body_json = json.dumps(auth_body)

# 3. Sign the Body
signature = private_key.sign(
    body_json.encode('utf-8'),
    padding.PKCS1v15(),
    hashes.SHA256()
)
signature_b64 = base64.b64encode(signature).decode('utf-8')

# 4. Send Request
headers = {
    "Content-Type": "application/json",
    "X-Men-Signature": signature_b64
}

url = f"{HOST}/api/devices/v1/authentication/auth_requests"
try:
    r = requests.post(url, headers=headers, data=body_json)
    print(f"[*] Status Code: {r.status_code}")
    print(f"[*] Response: {r.text}")
except Exception as e:
    print(f"[-] Error: {e}")
