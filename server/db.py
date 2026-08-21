import time

from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool

from config import settings

engine = create_engine(settings.database_url, poolclass=QueuePool, pool_size=10, max_overflow=20, pool_pre_ping=True)


def init_db():
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS accounts (
                account_id      TEXT PRIMARY KEY,
                password_hash   TEXT NOT NULL,
                sig_public_key  BYTEA NOT NULL,
                sig_alg         TEXT NOT NULL,
                enrolled_at     BIGINT NOT NULL,
                is_admin        BOOLEAN NOT NULL DEFAULT FALSE,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    BIGINT NOT NULL DEFAULT 0,
                kem_public_key  BYTEA
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash   TEXT PRIMARY KEY,
                account_id   TEXT NOT NULL REFERENCES accounts(account_id),
                scope        TEXT NOT NULL,
                issued_at    BIGINT NOT NULL,
                expires_at   BIGINT NOT NULL,
                revoked      BOOLEAN NOT NULL DEFAULT FALSE
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_sessions_acct ON sessions(account_id)"))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS folders (
                folder_id  TEXT PRIMARY KEY,
                owner      TEXT NOT NULL REFERENCES accounts(account_id),
                name       TEXT NOT NULL,
                parent_id  TEXT REFERENCES folders(folder_id) ON DELETE CASCADE,
                created    BIGINT NOT NULL
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_folders_owner ON folders(owner)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id)"))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS files (
                file_id       TEXT PRIMARY KEY,
                owner         TEXT NOT NULL REFERENCES accounts(account_id),
                filename      TEXT NOT NULL,
                content_type  TEXT NOT NULL,
                size          BIGINT NOT NULL,
                created       BIGINT NOT NULL,
                folder_id     TEXT REFERENCES folders(folder_id) ON DELETE SET NULL,
                group_id      TEXT NOT NULL,
                version       INTEGER NOT NULL DEFAULT 1
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_files_group ON files(group_id)"))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS shares (
                file_id      TEXT NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
                shared_with  TEXT NOT NULL REFERENCES accounts(account_id),
                shared_by    TEXT NOT NULL,
                created      BIGINT NOT NULL,
                PRIMARY KEY (file_id, shared_with)
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_shares_with ON shares(shared_with)"))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS file_keys (
                file_id        TEXT NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
                account_id     TEXT NOT NULL REFERENCES accounts(account_id),
                kem_ciphertext BYTEA NOT NULL,
                wrapped_key    BYTEA NOT NULL,
                created        BIGINT NOT NULL,
                PRIMARY KEY (file_id, account_id)
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_file_keys_acct ON file_keys(account_id)"))


def create_account(account_id: str, password_hash: str, sig_public_key: bytes,
                   sig_alg: str, kem_public_key: bytes):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO accounts
                (account_id, password_hash, sig_public_key, sig_alg, enrolled_at, kem_public_key)
            VALUES (:account_id, :password_hash, :sig_public_key, :sig_alg, :enrolled_at, :kem_public_key)
        """), {
            "account_id": account_id, "password_hash": password_hash,
            "sig_public_key": sig_public_key, "sig_alg": sig_alg,
            "enrolled_at": int(time.time()), "kem_public_key": kem_public_key,
        })


def get_kem_public_key(account_id: str) -> bytes | None:
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT kem_public_key FROM accounts WHERE account_id = :account_id"
        ), {"account_id": account_id}).mappings().fetchone()
        return bytes(row["kem_public_key"]) if row and row["kem_public_key"] else None


def put_file_key(file_id: str, account_id: str, kem_ciphertext: bytes, wrapped_key: bytes):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO file_keys (file_id, account_id, kem_ciphertext, wrapped_key, created)
            VALUES (:file_id, :account_id, :kem_ciphertext, :wrapped_key, :created)
            ON CONFLICT (file_id, account_id) DO UPDATE SET
                kem_ciphertext = excluded.kem_ciphertext,
                wrapped_key    = excluded.wrapped_key
        """), {
            "file_id": file_id, "account_id": account_id,
            "kem_ciphertext": kem_ciphertext, "wrapped_key": wrapped_key,
            "created": int(time.time()),
        })


def get_file_key(file_id: str, account_id: str) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT kem_ciphertext, wrapped_key FROM file_keys
            WHERE file_id = :file_id AND account_id = :account_id
        """), {"file_id": file_id, "account_id": account_id}).mappings().fetchone()
        return dict(row) if row else None


def delete_file_key(file_id: str, account_id: str) -> bool:
    with engine.begin() as conn:
        cur = conn.execute(text(
            "DELETE FROM file_keys WHERE file_id = :file_id AND account_id = :account_id"
        ), {"file_id": file_id, "account_id": account_id})
        return cur.rowcount > 0


def get_account(account_id: str) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT account_id, password_hash, sig_public_key, is_admin,
                   failed_attempts, locked_until FROM accounts WHERE account_id = :account_id
        """), {"account_id": account_id}).mappings().fetchone()
        return dict(row) if row else None


def update_password_hash(account_id: str, password_hash: str):
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE accounts SET password_hash = :password_hash WHERE account_id = :account_id"
        ), {"password_hash": password_hash, "account_id": account_id})


def record_failed_login(account_id: str, max_failed: int, lockout_seconds: int):
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE accounts
            SET failed_attempts = failed_attempts + 1,
                locked_until = CASE
                    WHEN failed_attempts + 1 >= :max_failed THEN :lock_until
                    ELSE locked_until
                END
            WHERE account_id = :account_id
        """), {
            "max_failed": max_failed,
            "lock_until": int(time.time()) + lockout_seconds,
            "account_id": account_id,
        })


def clear_failed_logins(account_id: str):
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE accounts SET failed_attempts = 0, locked_until = 0 WHERE account_id = :account_id"
        ), {"account_id": account_id})


def insert_session(token_hash: str, account_id: str, scope: str, issued_at: int, expires_at: int):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO sessions (token_hash, account_id, scope, issued_at, expires_at)
            VALUES (:token_hash, :account_id, :scope, :issued_at, :expires_at)
            ON CONFLICT (token_hash) DO UPDATE SET
                account_id = excluded.account_id, scope = excluded.scope,
                issued_at = excluded.issued_at, expires_at = excluded.expires_at,
                revoked = FALSE
        """), {
            "token_hash": token_hash, "account_id": account_id, "scope": scope,
            "issued_at": issued_at, "expires_at": expires_at,
        })


def get_session(token_hash: str) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT token_hash, account_id, scope, issued_at, expires_at, revoked
            FROM sessions WHERE token_hash = :token_hash
        """), {"token_hash": token_hash}).mappings().fetchone()
        return dict(row) if row else None


def revoke_session(token_hash: str) -> bool:
    with engine.begin() as conn:
        cur = conn.execute(text(
            "UPDATE sessions SET revoked = TRUE WHERE token_hash = :token_hash AND revoked = FALSE"
        ), {"token_hash": token_hash})
        return cur.rowcount > 0


def revoke_all_sessions(account_id: str) -> int:
    with engine.begin() as conn:
        cur = conn.execute(text(
            "UPDATE sessions SET revoked = TRUE WHERE account_id = :account_id AND revoked = FALSE"
        ), {"account_id": account_id})
        return cur.rowcount


def purge_expired_sessions() -> int:
    with engine.begin() as conn:
        cur = conn.execute(text(
            "DELETE FROM sessions WHERE expires_at < :now"
        ), {"now": int(time.time())})
        return cur.rowcount


def active_session_count() -> int:
    with engine.connect() as conn:
        return conn.execute(text(
            "SELECT COUNT(*) FROM sessions WHERE revoked = FALSE AND expires_at >= :now"
        ), {"now": int(time.time())}).scalar()


def get_account_pubkey(account_id: str) -> bytes | None:
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT sig_public_key FROM accounts WHERE account_id = :account_id"
        ), {"account_id": account_id}).mappings().fetchone()
        return bytes(row["sig_public_key"]) if row else None


def account_exists(account_id: str) -> bool:
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT 1 FROM accounts WHERE account_id = :account_id"
        ), {"account_id": account_id}).fetchone()
        return row is not None


def is_admin(account_id: str) -> bool:
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT is_admin FROM accounts WHERE account_id = :account_id"
        ), {"account_id": account_id}).mappings().fetchone()
        return bool(row and row["is_admin"])


def set_admin(account_id: str, admin: bool):
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE accounts SET is_admin = :admin WHERE account_id = :account_id"
        ), {"admin": bool(admin), "account_id": account_id})


def list_accounts() -> list[dict]:
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT a.account_id, a.enrolled_at, a.is_admin,
                   COUNT(f.file_id) AS file_count,
                   COALESCE(SUM(f.size), 0) AS total_bytes
            FROM accounts a
            LEFT JOIN files f ON f.owner = a.account_id
            GROUP BY a.account_id
            ORDER BY a.enrolled_at DESC
        """)).mappings().fetchall()
        return [dict(r) for r in rows]


def insert_file(meta: dict):
    """meta must include group_id and version. A fresh upload sets
    group_id = file_id (it is its own group of one); a new version of an
    existing file reuses the original file's group_id and increments
    version -- see find_latest_version_in_folder()."""
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO files (file_id, owner, filename, content_type, size, created, folder_id, group_id, version)
            VALUES (:file_id, :owner, :filename, :content_type, :size, :created, :folder_id, :group_id, :version)
        """), meta)


def find_latest_version_in_folder(owner: str, folder_id: str | None, filename: str) -> dict | None:
    """Looks for an existing file with the same name in the same folder,
    to decide whether an upload is a new file or a new version of one."""
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT file_id, group_id, version FROM files
            WHERE owner = :owner AND filename = :filename
              AND ((folder_id IS NULL AND CAST(:folder_id AS TEXT) IS NULL) OR folder_id = CAST(:folder_id AS TEXT))
            ORDER BY version DESC LIMIT 1
        """), {"owner": owner, "filename": filename, "folder_id": folder_id}).mappings().fetchone()
        return dict(row) if row else None


def list_files_for(owner: str, folder_id: str | None = None) -> list[dict]:
    """Only the latest version of each group -- older versions are reached
    via list_versions_for(), not the main listing."""
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT f.file_id, f.owner, f.filename, f.content_type, f.size, f.created,
                   f.folder_id, f.group_id, f.version
            FROM files f
            INNER JOIN (
                SELECT group_id, MAX(version) AS max_version FROM files
                WHERE owner = :owner
                  AND ((folder_id IS NULL AND CAST(:folder_id AS TEXT) IS NULL) OR folder_id = CAST(:folder_id AS TEXT))
                GROUP BY group_id
            ) latest ON latest.group_id = f.group_id AND latest.max_version = f.version
            WHERE f.owner = :owner
              AND ((f.folder_id IS NULL AND CAST(:folder_id AS TEXT) IS NULL) OR f.folder_id = CAST(:folder_id AS TEXT))
            ORDER BY f.created DESC
        """), {"owner": owner, "folder_id": folder_id}).mappings().fetchall()
        return [dict(r) for r in rows]


def list_versions_for(group_id: str) -> list[dict]:
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT file_id, owner, filename, content_type, size, created, version
            FROM files WHERE group_id = :group_id ORDER BY version DESC
        """), {"group_id": group_id}).mappings().fetchall()
        return [dict(r) for r in rows]


def get_file(file_id: str) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT file_id, owner, filename, content_type, size, created, folder_id, group_id, version
            FROM files WHERE file_id = :file_id
        """), {"file_id": file_id}).mappings().fetchone()
        return dict(row) if row else None


def list_all_files() -> list[dict]:
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT file_id, owner, filename, content_type, size, created
            FROM files ORDER BY created DESC
        """)).mappings().fetchall()
        return [dict(r) for r in rows]


def delete_file(file_id: str):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM shares WHERE file_id = :file_id"), {"file_id": file_id})
        conn.execute(text("DELETE FROM file_keys WHERE file_id = :file_id"), {"file_id": file_id})
        conn.execute(text("DELETE FROM files WHERE file_id = :file_id"), {"file_id": file_id})


def add_share(file_id: str, shared_with: str, shared_by: str):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO shares (file_id, shared_with, shared_by, created)
            VALUES (:file_id, :shared_with, :shared_by, :created)
            ON CONFLICT (file_id, shared_with) DO NOTHING
        """), {
            "file_id": file_id, "shared_with": shared_with,
            "shared_by": shared_by, "created": int(time.time()),
        })


def remove_share(file_id: str, shared_with: str) -> bool:
    with engine.begin() as conn:
        cur = conn.execute(text(
            "DELETE FROM shares WHERE file_id = :file_id AND shared_with = :shared_with"
        ), {"file_id": file_id, "shared_with": shared_with})
        return cur.rowcount > 0


def has_share(file_id: str, account_id: str) -> bool:
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT 1 FROM shares WHERE file_id = :file_id AND shared_with = :account_id"
        ), {"file_id": file_id, "account_id": account_id}).fetchone()
        return row is not None


def list_shares_for_file(file_id: str) -> list[dict]:
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT shared_with, shared_by, created FROM shares
            WHERE file_id = :file_id ORDER BY created
        """), {"file_id": file_id}).mappings().fetchall()
        return [dict(r) for r in rows]


def list_shared_with(account_id: str) -> list[dict]:
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT f.file_id, f.owner, f.filename, f.content_type, f.size,
                   f.created, s.created AS shared_at
            FROM shares s
            JOIN files f ON f.file_id = s.file_id
            WHERE s.shared_with = :account_id
            ORDER BY s.created DESC
        """), {"account_id": account_id}).mappings().fetchall()
        return [dict(r) for r in rows]


def global_stats() -> dict:
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT
              (SELECT COUNT(*) FROM accounts)                       AS accounts,
              (SELECT COUNT(*) FROM accounts WHERE is_admin)         AS admins,
              (SELECT COUNT(*) FROM files)                          AS files,
              (SELECT COALESCE(SUM(size),0) FROM files)             AS total_bytes,
              (SELECT COUNT(*) FROM shares)                         AS shares,
              (SELECT COUNT(*) FROM sessions
                 WHERE revoked = FALSE AND expires_at >= :now)       AS active_sessions
        """), {"now": int(time.time())}).mappings().fetchone()
        return dict(row)


def share_counts_for(owner: str) -> dict[str, int]:
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT s.file_id, COUNT(*) AS n
            FROM shares s JOIN files f ON f.file_id = s.file_id
            WHERE f.owner = :owner
            GROUP BY s.file_id
        """), {"owner": owner}).mappings().fetchall()
        return {r["file_id"]: r["n"] for r in rows}


def create_folder(folder_id: str, owner: str, name: str, parent_id: str | None):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO folders (folder_id, owner, name, parent_id, created)
            VALUES (:folder_id, :owner, :name, :parent_id, :created)
        """), {"folder_id": folder_id, "owner": owner, "name": name,
               "parent_id": parent_id, "created": int(time.time())})


def get_folder(folder_id: str) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT folder_id, owner, name, parent_id, created FROM folders WHERE folder_id = :folder_id"
        ), {"folder_id": folder_id}).mappings().fetchone()
        return dict(row) if row else None


def list_folders_for(owner: str, parent_id: str | None) -> list[dict]:
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT folder_id, owner, name, parent_id, created FROM folders
            WHERE owner = :owner
              AND ((parent_id IS NULL AND CAST(:parent_id AS TEXT) IS NULL) OR parent_id = CAST(:parent_id AS TEXT))
            ORDER BY name
        """), {"owner": owner, "parent_id": parent_id}).mappings().fetchall()
        return [dict(r) for r in rows]


def folder_is_empty(folder_id: str) -> bool:
    with engine.connect() as conn:
        has_children = conn.execute(text(
            "SELECT 1 FROM folders WHERE parent_id = :folder_id LIMIT 1"
        ), {"folder_id": folder_id}).fetchone()
        has_files = conn.execute(text(
            "SELECT 1 FROM files WHERE folder_id = :folder_id LIMIT 1"
        ), {"folder_id": folder_id}).fetchone()
        return has_children is None and has_files is None


def delete_folder(folder_id: str) -> bool:
    with engine.begin() as conn:
        cur = conn.execute(text(
            "DELETE FROM folders WHERE folder_id = :folder_id"
        ), {"folder_id": folder_id})
        return cur.rowcount > 0
