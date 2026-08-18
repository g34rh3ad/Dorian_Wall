
from argon2 import PasswordHasher

MIN_LENGTH = 10
MAX_LENGTH = 128


_COMMON = {
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "qwertyuiop", "letmein123", "changeme", "admin1234",
    "iloveyou1", "welcome123", "abc12345", "passw0rd", "quantum123",
}

_ph = PasswordHasher()


class PasswordPolicyError(ValueError):
    pass


def validate(password: str, account_id: str = "") -> None:
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_LENGTH} characters.")
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {MAX_LENGTH} characters.")
    if password.lower() in _COMMON:
        raise PasswordPolicyError("That password is too common. Choose something less predictable.")
    if account_id and account_id.lower() in password.lower():
        raise PasswordPolicyError("Password must not contain your account id.")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        _ph.verify(stored_hash, password)
        return True
    except Exception:


        return False


def needs_rehash(stored_hash: str) -> bool:

    try:
        return _ph.check_needs_rehash(stored_hash)
    except Exception:
        return False


MAX_FAILED = 5
LOCKOUT_SECONDS = 300
