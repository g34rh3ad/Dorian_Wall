from fastapi import HTTPException, Request

from pqc_utils import TokenAuthority


def require_token(request: Request, authorization: str | None, scope: str) -> dict:
    token_authority: TokenAuthority = request.app.state.token_authority
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.removeprefix("Bearer ")
    try:
        payload = token_authority.verify_token(token)
    except ValueError as e:
        raise HTTPException(401, f"invalid token: {e}")
    if scope not in payload["scope"]:
        raise HTTPException(403, f"token missing {scope} scope")
    return payload
