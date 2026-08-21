import base64
import json
import time

import redis

from config import settings

_redis = redis.from_url(settings.redis_url, decode_responses=True)


def _key(session_id: str) -> str:
    return f"pending_session:{session_id}"


def ping() -> bool:
    return bool(_redis.ping())


def put(session_id: str, account_id: str, shared_secret: bytes, challenge: bytes, ttl_seconds: int):
    """Stores handshake state with a Redis TTL, so expiry is enforced by
    Redis itself rather than a periodic sweep of an in-process dict. This
    is also what makes the handshake state visible to every app replica,
    not just the one that happened to receive /session/init -- a load
    balancer can route /session/auth to a different replica and it still
    works."""
    payload = json.dumps({
        "account_id": account_id,
        "shared_secret": base64.b64encode(shared_secret).decode(),
        "challenge": base64.b64encode(challenge).decode(),
        "created": time.time(),
    })
    _redis.setex(_key(session_id), ttl_seconds, payload)


def pop(session_id: str) -> dict | None:
    """Atomic get-then-delete so a session can only be completed once,
    even if two /session/auth requests for the same session_id land on
    different replicas at nearly the same time."""
    key = _key(session_id)
    pipe = _redis.pipeline()
    pipe.get(key)
    pipe.delete(key)
    raw, _ = pipe.execute()
    if raw is None:
        return None
    data = json.loads(raw)
    data["shared_secret"] = base64.b64decode(data["shared_secret"])
    data["challenge"] = base64.b64decode(data["challenge"])
    return data
