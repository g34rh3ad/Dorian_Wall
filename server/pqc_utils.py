
import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"
TOKEN_TTL_SECONDS = 600


def simulated_qrng_bytes(n: int) -> bytes:

    return os.urandom(n)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha384).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha384).digest()
        out += t
        counter += 1
    return out[:length]


def derive_session_key(kem_shared_secret: bytes, qrng_bytes: bytes, context: bytes) -> bytes:

    prk = hkdf_extract(salt=qrng_bytes, ikm=kem_shared_secret)
    return hkdf_expand(prk, info=b"quantum-auth-poc|session-key|" + context, length=32)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def unb64(data: str) -> bytes:

    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def token_fingerprint(token: str) -> str:

    return hashlib.sha256(token.encode()).hexdigest()


class TokenAuthority:


    def __init__(self, record=None, lookup=None, ttl_seconds: int = TOKEN_TTL_SECONDS):
        self._sig = oqs.Signature(SIG_ALG)
        self.public_key = self._sig.generate_keypair()
        self._record = record
        self._lookup = lookup
        self._ttl_seconds = ttl_seconds

    def issue_token(self, subject: str, scope: list[str]) -> str:
        now = int(time.time())
        exp = now + self._ttl_seconds
        payload = {
            "sub": subject,
            "scope": scope,
            "iat": now,
            "exp": exp,
            "jti": base64.urlsafe_b64encode(os.urandom(12)).decode(),
            "alg": SIG_ALG,
        }
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        signature = self._sig.sign(payload_bytes)
        token = f"{b64(payload_bytes)}.{b64(signature)}"

        if self._record:
            self._record(token_fingerprint(token), subject, json.dumps(scope), now, exp)
        return token

    def verify_token(self, token: str) -> dict:
        try:
            payload_b64, sig_b64 = token.split(".")
        except ValueError:
            raise ValueError("malformed token")
        payload_bytes = unb64(payload_b64)
        signature = unb64(sig_b64)

        verifier = oqs.Signature(SIG_ALG)
        if not verifier.verify(payload_bytes, signature, self.public_key):
            raise ValueError("bad ML-DSA signature")

        payload = json.loads(payload_bytes)
        if payload["exp"] < time.time():
            raise ValueError("token expired")

        if self._lookup:
            row = self._lookup(token_fingerprint(token))
            if row is None:
                raise ValueError("session not found")
            if row["revoked"]:
                raise ValueError("session revoked")

        return payload


class FileVault:


    def __init__(self, kms):


        self._kms = kms
        self._kms.ping()

    def _data_key(self, file_id: str) -> bytes:
        return self._kms.derive_key(f"file-key|{file_id}")

    def encrypt(self, file_id: str, plaintext: bytes) -> bytes:
        key = self._data_key(file_id)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=file_id.encode())
        return nonce + ciphertext

    def decrypt(self, file_id: str, blob: bytes) -> bytes:
        key = self._data_key(file_id)
        nonce, ciphertext = blob[:12], blob[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data=file_id.encode())
