
import sqlite3
import time
from pathlib import Path

from config import settings

DB_PATH = settings.db_path


def get_conn() -> sqlite3.Connection:


    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                account_id      TEXT PRIMARY KEY,
                password_hash   TEXT NOT NULL,
                sig_public_key  BLOB NOT NULL,
                sig_alg         TEXT NOT NULL,
                enrolled_at     INTEGER NOT NULL,
                is_admin        INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    INTEGER NOT NULL DEFAULT 0,
                -- Long-term ML-KEM-768 ENCRYPTION key, distinct from the
                -- ML-DSA signing key above. Public half only: the secret
                -- half never leaves the owner's browser, which is what
                -- makes end-to-end encryption possible at all.
                kem_public_key  BLOB
            )
            """
        )


        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash   TEXT PRIMARY KEY,
                account_id   TEXT NOT NULL REFERENCES accounts(account_id),
                scope        TEXT NOT NULL,
                issued_at    INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL,
                revoked      INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_acct ON sessions(account_id)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                file_id       TEXT PRIMARY KEY,
                owner         TEXT NOT NULL REFERENCES accounts(account_id),
                filename      TEXT NOT NULL,
                content_type  TEXT NOT NULL,
                size          INTEGER NOT NULL,
                created       INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shares (
                file_id      TEXT NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
                shared_with  TEXT NOT NULL REFERENCES accounts(account_id),
                shared_by    TEXT NOT NULL,
                created      INTEGER NOT NULL,
                PRIMARY KEY (file_id, shared_with)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_shares_with ON shares(shared_with)")


        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_keys (
                file_id        TEXT NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
                account_id     TEXT NOT NULL REFERENCES accounts(account_id),
                kem_ciphertext BLOB NOT NULL,  -- ML-KEM encapsulation to that account
                wrapped_key    BLOB NOT NULL,  -- file key, AES-GCM wrapped under the KEM secret
                created        INTEGER NOT NULL,
                PRIMARY KEY (file_id, account_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_file_keys_acct ON file_keys(account_id)")


def create_account(account_id: str, password_hash: str, sig_public_key: bytes,
                   sig_alg: str, kem_public_key: bytes):

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO accounts
                (account_id, password_hash, sig_public_key, sig_alg, enrolled_at, kem_public_key)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (account_id, password_hash, sig_public_key, sig_alg, int(time.time()), kem_public_key),
        )


def get_kem_public_key(account_id: str) -> bytes | None:

    with get_conn() as conn:
        row = conn.execute(
            "SELECT kem_public_key FROM accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        return bytes(row["kem_public_key"]) if row and row["kem_public_key"] else None


def put_file_key(file_id: str, account_id: str, kem_ciphertext: bytes, wrapped_key: bytes):
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO file_keys (file_id, account_id, kem_ciphertext, wrapped_key, created)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(file_id, account_id) DO UPDATE SET
                kem_ciphertext = excluded.kem_ciphertext,
                wrapped_key    = excluded.wrapped_key
            """,
            (file_id, account_id, kem_ciphertext, wrapped_key, int(time.time())),
        )


def get_file_key(file_id: str, account_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT kem_ciphertext, wrapped_key FROM file_keys "
            "WHERE file_id = ? AND account_id = ?",
            (file_id, account_id),
        ).fetchone()
        return dict(row) if row else None


def delete_file_key(file_id: str, account_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM file_keys WHERE file_id = ? AND account_id = ?",
            (file_id, account_id),
        )
        return cur.rowcount > 0


def get_account(account_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT account_id, password_hash, sig_public_key, is_admin, "
            "failed_attempts, locked_until FROM accounts WHERE account_id = ?",
            (account_id,),
        ).fetchone()
        return dict(row) if row else None


def update_password_hash(account_id: str, password_hash: str):
    with get_conn() as conn:
        conn.execute(
            "UPDATE accounts SET password_hash = ? WHERE account_id = ?",
            (password_hash, account_id),
        )


def record_failed_login(account_id: str, max_failed: int, lockout_seconds: int):
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE accounts
            SET failed_attempts = failed_attempts + 1,
                locked_until = CASE
                    WHEN failed_attempts + 1 >= ? THEN ?
                    ELSE locked_until
                END
            WHERE account_id = ?
            """,
            (max_failed, int(time.time()) + lockout_seconds, account_id),
        )


def clear_failed_logins(account_id: str):
    with get_conn() as conn:
        conn.execute(
            "UPDATE accounts SET failed_attempts = 0, locked_until = 0 WHERE account_id = ?",
            (account_id,),
        )


def insert_session(token_hash: str, account_id: str, scope: str, issued_at: int, expires_at: int):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token_hash, account_id, scope, issued_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (token_hash, account_id, scope, issued_at, expires_at),
        )


def get_session(token_hash: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT token_hash, account_id, scope, issued_at, expires_at, revoked "
            "FROM sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        return dict(row) if row else None


def revoke_session(token_hash: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE sessions SET revoked = 1 WHERE token_hash = ? AND revoked = 0",
            (token_hash,),
        )
        return cur.rowcount > 0


def revoke_all_sessions(account_id: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE sessions SET revoked = 1 WHERE account_id = ? AND revoked = 0",
            (account_id,),
        )
        return cur.rowcount


def purge_expired_sessions() -> int:

    with get_conn() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
        return cur.rowcount


def active_session_count() -> int:
    with get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE revoked = 0 AND expires_at >= ?",
            (int(time.time()),),
        ).fetchone()[0]


def get_account_pubkey(account_id: str) -> bytes | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT sig_public_key FROM accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        return bytes(row["sig_public_key"]) if row else None


def account_exists(account_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        return row is not None


def is_admin(account_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT is_admin FROM accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        return bool(row and row["is_admin"])


def set_admin(account_id: str, admin: bool):

    with get_conn() as conn:
        conn.execute(
            "UPDATE accounts SET is_admin = ? WHERE account_id = ?",
            (1 if admin else 0, account_id),
        )


def list_accounts() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT a.account_id, a.enrolled_at, a.is_admin,
                   COUNT(f.file_id) AS file_count,
                   COALESCE(SUM(f.size), 0) AS total_bytes
            FROM accounts a
            LEFT JOIN files f ON f.owner = a.account_id
            GROUP BY a.account_id
            ORDER BY a.enrolled_at DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]


def insert_file(meta: dict):
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO files (file_id, owner, filename, content_type, size, created)
            VALUES (:file_id, :owner, :filename, :content_type, :size, :created)
            """,
            meta,
        )


def list_files_for(owner: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT file_id, owner, filename, content_type, size, created "
            "FROM files WHERE owner = ? ORDER BY created DESC",
            (owner,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_file(file_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT file_id, owner, filename, content_type, size, created "
            "FROM files WHERE file_id = ?",
            (file_id,),
        ).fetchone()
        return dict(row) if row else None


def list_all_files() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT file_id, owner, filename, content_type, size, created "
            "FROM files ORDER BY created DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_file(file_id: str):
    with get_conn() as conn:


        conn.execute("DELETE FROM shares WHERE file_id = ?", (file_id,))
        conn.execute("DELETE FROM file_keys WHERE file_id = ?", (file_id,))
        conn.execute("DELETE FROM files WHERE file_id = ?", (file_id,))


def add_share(file_id: str, shared_with: str, shared_by: str):
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO shares (file_id, shared_with, shared_by, created)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(file_id, shared_with) DO NOTHING
            """,
            (file_id, shared_with, shared_by, int(time.time())),
        )


def remove_share(file_id: str, shared_with: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM shares WHERE file_id = ? AND shared_with = ?",
            (file_id, shared_with),
        )
        return cur.rowcount > 0


def has_share(file_id: str, account_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM shares WHERE file_id = ? AND shared_with = ?",
            (file_id, account_id),
        ).fetchone()
        return row is not None


def list_shares_for_file(file_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT shared_with, shared_by, created FROM shares "
            "WHERE file_id = ? ORDER BY created",
            (file_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def list_shared_with(account_id: str) -> list[dict]:

    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT f.file_id, f.owner, f.filename, f.content_type, f.size,
                   f.created, s.created AS shared_at
            FROM shares s
            JOIN files f ON f.file_id = s.file_id
            WHERE s.shared_with = ?
            ORDER BY s.created DESC
            """,
            (account_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def global_stats() -> dict:
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM accounts)                  AS accounts,
              (SELECT COUNT(*) FROM accounts WHERE is_admin=1) AS admins,
              (SELECT COUNT(*) FROM files)                     AS files,
              (SELECT COALESCE(SUM(size),0) FROM files)        AS total_bytes,
              (SELECT COUNT(*) FROM shares)                    AS shares,
              (SELECT COUNT(*) FROM sessions
                 WHERE revoked = 0 AND expires_at >= strftime('%s','now')) AS active_sessions
            """
        ).fetchone()
        return dict(row)


def share_counts_for(owner: str) -> dict[str, int]:

    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT s.file_id, COUNT(*) AS n
            FROM shares s JOIN files f ON f.file_id = s.file_id
            WHERE f.owner = ?
            GROUP BY s.file_id
            """,
            (owner,),
        ).fetchall()
        return {r["file_id"]: r["n"] for r in rows}
