import base64
import secrets
import time
import uuid

import oqs
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

import db
import passwords
import session_store
import validation
from config import settings
from deps import require_token
from logging_config import log_security_event
from pqc_utils import KEM_ALG, SIG_ALG, derive_session_key, simulated_qrng_bytes, token_fingerprint, unb64
from security import client_ip

router = APIRouter(tags=["auth"])


class RegisterRequest(BaseModel):
    account_id: str
    password: str
    sig_public_key_b64: str
    kem_public_key_b64: str


class SessionInitRequest(BaseModel):
    account_id: str
    kem_public_key_b64: str


class SessionAuthRequest(BaseModel):
    session_id: str
    password: str
    signature_b64: str


@router.post("/register")
def register(req: RegisterRequest, request: Request):
    try:
        account_id = validation.validate_account_id(req.account_id)
        sig_public_key = validation.decode_public_key(req.sig_public_key_b64)
        kem_public_key = validation.decode_kem_public_key(req.kem_public_key_b64)
    except validation.ValidationError as e:
        raise HTTPException(400, str(e))

    ip = client_ip(request)
    if not request.app.state.register_limiter.check(ip):
        raise HTTPException(429, "too many registration attempts", headers={
            "Retry-After": str(request.app.state.register_limiter.retry_after(ip))
        })

    if db.account_exists(account_id):
        log_security_event("register_conflict", account_id=account_id, ip=ip)
        raise HTTPException(409, f"account '{account_id}' already exists")

    try:
        passwords.validate(req.password, account_id)
    except passwords.PasswordPolicyError as e:
        raise HTTPException(400, str(e))

    db.create_account(
        account_id,
        passwords.hash_password(req.password),
        sig_public_key,
        SIG_ALG,
        kem_public_key,
    )
    log_security_event("register_success", account_id=account_id, ip=ip)
    return {"status": "registered", "account_id": account_id, "sig_alg": SIG_ALG}


@router.post("/session/init")
def session_init(req: SessionInitRequest, request: Request):
    ip = client_ip(request)
    if not request.app.state.init_limiter.check(ip):
        raise HTTPException(429, "too many handshake attempts", headers={
            "Retry-After": str(request.app.state.init_limiter.retry_after(ip))
        })

    kem = oqs.KeyEncapsulation(KEM_ALG)
    ciphertext, shared_secret = kem.encap_secret(unb64(req.kem_public_key_b64))

    session_id = str(uuid.uuid4())
    challenge = secrets.token_bytes(32)
    # TTL enforced by Redis itself (SETEX) -- no periodic sweep needed, and
    # the state is visible to every app replica, not pinned to whichever
    # one handled this request.
    session_store.put(session_id, req.account_id, shared_secret, challenge, settings.handshake_ttl_seconds)

    return {
        "session_id": session_id,
        "kem_alg": KEM_ALG,
        "ciphertext_b64": base64.urlsafe_b64encode(ciphertext).decode(),
        "challenge_b64": base64.urlsafe_b64encode(challenge).decode(),
    }


@router.post("/session/auth")
def session_auth(req: SessionAuthRequest, request: Request):
    ip = client_ip(request)
    if not request.app.state.login_limiter.check(ip):
        raise HTTPException(429, "too many login attempts", headers={
            "Retry-After": str(request.app.state.login_limiter.retry_after(ip))
        })

    session = session_store.pop(req.session_id)
    if session is None:
        # Covers both "never existed" and "Redis TTL already expired it" --
        # from the caller's point of view those are indistinguishable and
        # don't need to be.
        raise HTTPException(404, "unknown or expired session")

    account_id = session["account_id"]
    account = db.get_account(account_id)
    now = int(time.time())

    if account and account["locked_until"] > now:
        log_security_event("login_locked_out", account_id=account_id, ip=ip)
        raise HTTPException(
            429,
            f"too many failed attempts -- locked for {account['locked_until'] - now}s",
        )

    password_ok = bool(account) and passwords.verify_password(account["password_hash"], req.password)

    signature_ok = False
    if account:
        verifier = oqs.Signature(SIG_ALG)
        try:
            signature_ok = verifier.verify(
                session["challenge"], unb64(req.signature_b64), bytes(account["sig_public_key"])
            )
        except Exception:
            signature_ok = False

    if not (password_ok and signature_ok):
        if account:
            db.record_failed_login(account_id, passwords.MAX_FAILED, passwords.LOCKOUT_SECONDS)
        log_security_event("login_failed", account_id=account_id, ip=ip,
                           password_ok=password_ok, signature_ok=signature_ok)
        raise HTTPException(401, "invalid credentials")

    db.clear_failed_logins(account_id)

    if passwords.needs_rehash(account["password_hash"]):
        db.update_password_hash(account_id, passwords.hash_password(req.password))

    qrng = simulated_qrng_bytes(32)
    session_key = derive_session_key(
        kem_shared_secret=session["shared_secret"],
        qrng_bytes=qrng,
        context=account_id.encode(),
    )
    session_key_fingerprint = session_key.hex()[:16]

    scope = ["drive:read", "drive:write"]
    if account["is_admin"]:
        scope.append("admin")

    token = request.app.state.token_authority.issue_token(subject=account_id, scope=scope)
    log_security_event("login_success", account_id=account_id, ip=ip, scope=scope)
    return {
        "token": token,
        "account_id": account_id,
        "scope": scope,
        "session_key_fingerprint": session_key_fingerprint,
    }


@router.post("/session/logout")
def logout(request: Request, authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.removeprefix("Bearer ")
    revoked = db.revoke_session(token_fingerprint(token))
    if revoked:
        log_security_event("logout", ip=client_ip(request))
    return {"status": "revoked" if revoked else "already inactive"}
