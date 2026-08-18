
import base64
import hashlib
import hmac
import os

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEM_ALG = "ML-KEM-768"
KEY_WRAP_INFO = b"quantum-auth-drive|file-key-wrap|v1"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _hkdf_sha256(shared_secret: bytes) -> bytes:

    prk = hmac.new(b"\x00" * 32, shared_secret, hashlib.sha256).digest()
    return hmac.new(prk, KEY_WRAP_INFO + b"\x01", hashlib.sha256).digest()


def new_file_key() -> bytes:
    return os.urandom(32)


def wrap_file_key_for(recipient_kem_public_key: bytes, file_key: bytes):

    kem = oqs.KeyEncapsulation(KEM_ALG)
    kem_ct, shared = kem.encap_secret(recipient_kem_public_key)
    aes_key = _hkdf_sha256(shared)
    nonce = os.urandom(12)
    sealed = AESGCM(aes_key).encrypt(nonce, file_key, None)
    return kem_ct, nonce + sealed


def unwrap_file_key(kem_obj, kem_ciphertext: bytes, wrapped_key: bytes) -> bytes:

    shared = kem_obj.decap_secret(kem_ciphertext)
    aes_key = _hkdf_sha256(shared)
    nonce, sealed = wrapped_key[:12], wrapped_key[12:]
    return AESGCM(aes_key).decrypt(nonce, sealed, None)


def encrypt_file(file_key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(file_key).encrypt(nonce, plaintext, None)


def decrypt_file(file_key: bytes, blob: bytes) -> bytes:
    return AESGCM(file_key).decrypt(blob[:12], blob[12:], None)
