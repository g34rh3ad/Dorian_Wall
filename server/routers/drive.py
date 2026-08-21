import base64
import re
import time
import uuid
from urllib.parse import quote

from fastapi import APIRouter, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

import db
import validation
from config import settings
from deps import require_token
from logging_config import log_security_event
from pqc_utils import KEM_ALG
from security import client_ip

router = APIRouter(tags=["drive"])


class ShareRequest(BaseModel):
    account_id: str
    kem_ciphertext_b64: str
    wrapped_key_b64: str


def content_disposition(filename: str) -> str:
    ascii_fallback = re.sub(r'[^A-Za-z0-9._-]', "_", filename) or "download"
    encoded = quote(filename, safe="")
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded}"


def purge_file(meta: dict):
    try:
        owner_dir = validation.safe_account_dir(settings.storage_dir, meta["owner"])
        (owner_dir / f"{meta['file_id']}.enc").unlink(missing_ok=True)
    except validation.ValidationError:
        pass
    db.delete_file(meta["file_id"])


@router.post("/drive/upload")
async def upload_file(
    request: Request,
    file: UploadFile,
    kem_ciphertext_b64: str = Form(...),
    wrapped_key_b64: str = Form(...),
    filename: str = Form(...),
    content_type: str = Form("application/octet-stream"),
    folder_id: str | None = Form(None),
    authorization: str = Header(None),
):
    payload = require_token(request, authorization, "drive:write")
    account_id = payload["sub"]

    try:
        kem_ct = validation.decode_kem_ciphertext(kem_ciphertext_b64)
        wrapped = validation.decode_wrapped_key(wrapped_key_b64)
    except validation.ValidationError as e:
        raise HTTPException(400, str(e))

    if folder_id is not None:
        folder = db.get_folder(folder_id)
        if folder is None or folder["owner"] != account_id:
            raise HTTPException(404, "folder not found")

    contents = await file.read()
    if len(contents) > settings.max_upload_bytes:
        raise HTTPException(413, f"file exceeds {settings.max_upload_mb}MB POC limit")

    file_id = str(uuid.uuid4())
    encrypted = request.app.state.file_vault.encrypt(file_id, contents)

    account_dir = validation.safe_account_dir(settings.storage_dir, account_id)
    account_dir.mkdir(parents=True, exist_ok=True)
    (account_dir / f"{file_id}.enc").write_bytes(encrypted)

    clean_name = validation.sanitize_filename(filename)
    # A same-name upload into the same folder is a new VERSION of the
    # existing file (its own file_id, own blob, own E2E key grant --
    # sharing the encryption key across versions would let a later
    # version silently decrypt with an old grant), not an overwrite.
    existing = db.find_latest_version_in_folder(account_id, folder_id, clean_name)
    group_id = existing["group_id"] if existing else file_id
    version = (existing["version"] + 1) if existing else 1

    meta = {
        "file_id": file_id,
        "owner": account_id,
        "filename": clean_name,
        "content_type": content_type or "application/octet-stream",
        "size": len(contents),
        "created": int(time.time()),
        "folder_id": folder_id,
        "group_id": group_id,
        "version": version,
    }
    db.insert_file(meta)
    db.put_file_key(file_id, account_id, kem_ct, wrapped)
    log_security_event("file_uploaded", account_id=account_id, file_id=file_id,
                       size=len(contents), version=version, ip=client_ip(request))
    return meta


@router.get("/drive/files")
def list_files(request: Request, folder_id: str | None = None, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:read")
    account_id = payload["sub"]
    files = db.list_files_for(account_id, folder_id)
    counts = db.share_counts_for(account_id)
    for f in files:
        f["shared_with_count"] = counts.get(f["file_id"], 0)
    folders = db.list_folders_for(account_id, folder_id)
    return {"account_id": account_id, "files": files, "folders": folders}


@router.get("/drive/files/{file_id}/versions")
def list_versions(file_id: str, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:read")
    account_id = payload["sub"]
    meta = db.get_file(file_id)
    if meta is None:
        raise HTTPException(404, "file not found")
    if meta["owner"] != account_id and not db.has_share(file_id, account_id):
        raise HTTPException(403, "not your file")
    return {"group_id": meta["group_id"], "versions": db.list_versions_for(meta["group_id"])}


class FolderRequest(BaseModel):
    name: str
    parent_id: str | None = None


@router.post("/drive/folders")
def create_folder(req: FolderRequest, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:write")
    account_id = payload["sub"]

    name = req.name.strip()
    if not name or len(name) > 200:
        raise HTTPException(400, "folder name must be 1-200 characters")

    if req.parent_id is not None:
        parent = db.get_folder(req.parent_id)
        if parent is None or parent["owner"] != account_id:
            raise HTTPException(404, "parent folder not found")

    folder_id = str(uuid.uuid4())
    db.create_folder(folder_id, account_id, name, req.parent_id)
    return {"folder_id": folder_id, "name": name, "parent_id": req.parent_id}


@router.delete("/drive/folders/{folder_id}")
def delete_folder(folder_id: str, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:write")
    account_id = payload["sub"]

    folder = db.get_folder(folder_id)
    if folder is None:
        raise HTTPException(404, "folder not found")
    if folder["owner"] != account_id:
        raise HTTPException(403, "only the owner can delete this folder")
    if not db.folder_is_empty(folder_id):
        raise HTTPException(409, "folder is not empty")

    db.delete_folder(folder_id)
    return {"status": "deleted", "folder_id": folder_id}


@router.delete("/drive/files/{file_id}")
def delete_own_file(file_id: str, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:write")
    account_id = payload["sub"]

    meta = db.get_file(file_id)
    if meta is None:
        raise HTTPException(404, "file not found")
    if meta["owner"] != account_id:
        raise HTTPException(403, "only the owner can delete this file")

    purge_file(meta)
    log_security_event("file_deleted", account_id=account_id, file_id=file_id, ip=client_ip(request))
    return {"status": "deleted", "file_id": file_id}


@router.get("/accounts/{account_id}/kem-key")
def get_kem_key(account_id: str, request: Request, authorization: str = Header(None)):
    require_token(request, authorization, "drive:read")
    key = db.get_kem_public_key(account_id)
    if key is None:
        raise HTTPException(404, "account not found")
    return {
        "account_id": account_id,
        "kem_alg": KEM_ALG,
        "kem_public_key_b64": base64.urlsafe_b64encode(key).decode(),
    }


@router.get("/drive/files/{file_id}/key")
def get_file_key(file_id: str, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:read")
    account_id = payload["sub"]

    grant = db.get_file_key(file_id, account_id)
    if grant is None:
        raise HTTPException(404, "no key grant for this account")
    return {
        "file_id": file_id,
        "kem_ciphertext_b64": base64.urlsafe_b64encode(bytes(grant["kem_ciphertext"])).decode(),
        "wrapped_key_b64": base64.urlsafe_b64encode(bytes(grant["wrapped_key"])).decode(),
    }


@router.get("/drive/shared")
def list_shared_with_me(request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:read")
    account_id = payload["sub"]
    return {"account_id": account_id, "files": db.list_shared_with(account_id)}


@router.post("/drive/files/{file_id}/share")
def share_file(file_id: str, req: ShareRequest, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:write")
    account_id = payload["sub"]

    meta = db.get_file(file_id)
    if meta is None:
        raise HTTPException(404, "file not found")
    if meta["owner"] != account_id:
        raise HTTPException(403, "only the owner can share this file")
    if req.account_id == account_id:
        raise HTTPException(400, "cannot share a file with yourself")
    if not db.account_exists(req.account_id):
        raise HTTPException(404, f"account '{req.account_id}' not found")

    try:
        kem_ct = validation.decode_kem_ciphertext(req.kem_ciphertext_b64)
        wrapped = validation.decode_wrapped_key(req.wrapped_key_b64)
    except validation.ValidationError as e:
        raise HTTPException(400, str(e))

    db.add_share(file_id, shared_with=req.account_id, shared_by=account_id)
    db.put_file_key(file_id, req.account_id, kem_ct, wrapped)
    log_security_event("file_shared", account_id=account_id, file_id=file_id,
                       shared_with=req.account_id, ip=client_ip(request))
    return {"status": "shared", "file_id": file_id, "shared_with": req.account_id}


@router.get("/drive/files/{file_id}/shares")
def list_file_shares(file_id: str, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:read")
    account_id = payload["sub"]

    meta = db.get_file(file_id)
    if meta is None:
        raise HTTPException(404, "file not found")
    if meta["owner"] != account_id:
        raise HTTPException(403, "only the owner can see this file's shares")

    return {"file_id": file_id, "shares": db.list_shares_for_file(file_id)}


@router.delete("/drive/files/{file_id}/share/{shared_with}")
def revoke_share(file_id: str, shared_with: str, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:write")
    account_id = payload["sub"]

    meta = db.get_file(file_id)
    if meta is None:
        raise HTTPException(404, "file not found")
    if meta["owner"] != account_id:
        raise HTTPException(403, "only the owner can revoke shares on this file")

    if not db.remove_share(file_id, shared_with):
        raise HTTPException(404, "no such share")

    db.delete_file_key(file_id, shared_with)
    log_security_event("share_revoked", account_id=account_id, file_id=file_id,
                       shared_with=shared_with, ip=client_ip(request))
    return {"status": "revoked", "file_id": file_id, "shared_with": shared_with}


@router.get("/drive/files/{file_id}")
def download_file(file_id: str, request: Request, authorization: str = Header(None)):
    payload = require_token(request, authorization, "drive:read")
    account_id = payload["sub"]

    meta = db.get_file(file_id)
    if meta is None:
        raise HTTPException(404, "file not found")

    if meta["owner"] != account_id and not db.has_share(file_id, account_id):
        raise HTTPException(403, "not your file")

    try:
        owner_dir = validation.safe_account_dir(settings.storage_dir, meta["owner"])
    except validation.ValidationError:
        raise HTTPException(404, "file not found")
    blob_path = owner_dir / f"{file_id}.enc"
    if not blob_path.is_file():
        raise HTTPException(404, "file not found")
    encrypted = blob_path.read_bytes()
    plaintext = request.app.state.file_vault.decrypt(file_id, encrypted)

    return Response(
        content=plaintext,
        media_type=meta["content_type"],
        headers={"Content-Disposition": content_disposition(meta["filename"])},
    )
