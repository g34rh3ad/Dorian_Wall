from fastapi import APIRouter, Header, HTTPException, Request

import db
from deps import require_token
from logging_config import log_security_event
from routers.drive import purge_file
from security import client_ip

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/accounts")
def admin_list_accounts(request: Request, authorization: str = Header(None)):
    require_token(request, authorization, "admin")
    return {"accounts": db.list_accounts()}


@router.get("/stats")
def admin_stats(request: Request, authorization: str = Header(None)):
    require_token(request, authorization, "admin")
    return db.global_stats()


@router.get("/files")
def admin_list_files(request: Request, authorization: str = Header(None)):
    require_token(request, authorization, "admin")
    return {"files": db.list_all_files()}


@router.delete("/files/{file_id}")
def admin_delete_file(file_id: str, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "admin")
    meta = db.get_file(file_id)
    if meta is None:
        raise HTTPException(404, "file not found")

    purge_file(meta)
    log_security_event("admin_file_deleted", admin_id=payload["sub"], file_id=file_id,
                       owner=meta["owner"], ip=client_ip(request))
    return {"status": "deleted", "file_id": file_id}
