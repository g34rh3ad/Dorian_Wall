import base64
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import db
import session_store
from config import settings
from kms_client import KMSClient, KMSUnavailable
from logging_config import RequestIDMiddleware, setup_logging
from pqc_utils import KEM_ALG, SIG_ALG, FileVault, TokenAuthority
from routers import admin, auth, drive
from security import RateLimiter, SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Called after uvicorn's own logging.config.dictConfig(), which would
    # otherwise clobber this -- setting it up here instead of at import
    # time makes it the one that wins.
    setup_logging(settings.log_level, settings.log_json)

    db.init_db()
    db.purge_expired_sessions()

    app.state.token_authority = TokenAuthority(
        record=db.insert_session,
        lookup=db.get_session,
        ttl_seconds=settings.token_ttl_seconds,
    )

    try:
        app.state.file_vault = FileVault(KMSClient())
    except KMSUnavailable as e:
        raise SystemExit(f"cannot start: {e}")

    # Fail closed, same as the KMS check above: a silent fallback to
    # per-process state would quietly break multi-replica handshakes
    # instead of refusing to start.
    if not session_store.ping():
        raise SystemExit(f"cannot start: Redis unreachable at {settings.redis_url}")

    app.state.init_limiter = RateLimiter(limit=settings.rate_limit_init_per_min, window_seconds=60)
    app.state.register_limiter = RateLimiter(limit=settings.rate_limit_register_per_min, window_seconds=60)
    app.state.login_limiter = RateLimiter(limit=settings.rate_limit_login_per_min, window_seconds=60)

    settings.storage_dir.mkdir(exist_ok=True)

    yield


app = FastAPI(
    title="Quantum-Auth Drive POC",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)

app.include_router(auth.router)
app.include_router(drive.router)
app.include_router(admin.router)

app.mount("/ui", StaticFiles(directory=str(settings.static_dir), html=True), name="ui")


@app.get("/")
def root():
    return {
        "service": "quantum-auth-drive-poc",
        "kem_alg": KEM_ALG,
        "sig_alg": SIG_ALG,
        "server_sig_public_key_b64": base64.urlsafe_b64encode(app.state.token_authority.public_key).decode(),
    }
