
import base64
import re
import unicodedata
from pathlib import Path


ACCOUNT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

MAX_FILENAME_LENGTH = 200
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_CIPHERTEXT_BYTES = 1088

WRAPPED_KEY_BYTES = 60


class ValidationError(ValueError):
    pass


def validate_account_id(account_id: str) -> str:
    account_id = (account_id or "").strip()
    if not ACCOUNT_ID_RE.match(account_id):
        raise ValidationError(
            "Account id must be 1-64 characters, start with a letter or digit, "
            "and contain only letters, digits, underscore, dot or hyphen."
        )


    if account_id in (".", "..") or "/" in account_id or "\\" in account_id:
        raise ValidationError("Invalid account id.")
    return account_id


def sanitize_filename(filename: str | None) -> str:

    name = (filename or "").strip()


    name = name.replace("\\", "/").split("/")[-1]


    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C")


    name = re.sub(r'[<>:"|?*\x7f]', "", name)

    name = name.strip(". ")
    if not name:
        name = "untitled"
    return name[:MAX_FILENAME_LENGTH]


def decode_public_key(sig_public_key_b64: str) -> bytes:

    if not isinstance(sig_public_key_b64, str) or not sig_public_key_b64:
        raise ValidationError("Missing public key.")

    if len(sig_public_key_b64) > 4096:
        raise ValidationError("Public key is too large.")
    try:
        padded = sig_public_key_b64 + "=" * (-len(sig_public_key_b64) % 4)
        raw = base64.urlsafe_b64decode(padded.encode())
    except Exception:
        raise ValidationError("Public key is not valid base64.")
    if len(raw) != ML_DSA_65_PUBLIC_KEY_BYTES:
        raise ValidationError(
            f"Public key must be {ML_DSA_65_PUBLIC_KEY_BYTES} bytes for ML-DSA-65 "
            f"(got {len(raw)})."
        )
    return raw


def _decode_fixed(value: str, expected: int, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"Missing {label}.")
    if len(value) > 8192:
        raise ValidationError(f"{label} is too large.")
    try:
        padded = value + "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(padded.encode())
    except Exception:
        raise ValidationError(f"{label} is not valid base64.")
    if len(raw) != expected:
        raise ValidationError(f"{label} must be {expected} bytes (got {len(raw)}).")
    return raw


def decode_kem_public_key(value: str) -> bytes:
    return _decode_fixed(value, ML_KEM_768_PUBLIC_KEY_BYTES, "ML-KEM-768 public key")


def decode_kem_ciphertext(value: str) -> bytes:
    return _decode_fixed(value, ML_KEM_768_CIPHERTEXT_BYTES, "ML-KEM-768 ciphertext")


def decode_wrapped_key(value: str) -> bytes:
    return _decode_fixed(value, WRAPPED_KEY_BYTES, "wrapped file key")


def safe_account_dir(storage_root: Path, account_id: str) -> Path:

    root = storage_root.resolve()
    candidate = (root / account_id).resolve()
    if candidate != root and not candidate.is_relative_to(root):
        raise ValidationError("Invalid account id.")
    return candidate
