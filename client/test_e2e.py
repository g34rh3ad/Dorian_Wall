
import base64
import secrets
import subprocess
import sys
from pathlib import Path

import httpx
import oqs
import sqlalchemy
from sqlalchemy import text

import e2e

KEM_ALG, SIG_ALG = "ML-KEM-768", "ML-DSA-65"
BASE = "https://127.0.0.1:8443"
SERVER_DIR = Path(__file__).parent.parent / "server"
CERT = SERVER_DIR / "certs" / "cert.pem"
DATABASE_URL = "postgresql+psycopg://qad:qad_dev_pw@127.0.0.1:5432/quantum_auth"

RUN = secrets.token_hex(3)
PW = "correct-horse-battery-2026"

passed = failed = 0


def check(label, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label} {detail}")


b64, unb64 = e2e.b64, e2e.unb64


def read_storage_blob(owner: str, file_id: str) -> bytes | None:
    """Reads the raw encrypted blob directly, bypassing the API entirely --
    that's the point: we're checking what's actually on disk, not trusting
    what the server chooses to tell us. Works against a local dev server
    (host filesystem) or the distributed Docker deployment (blob lives
    inside a container's volume, fetched via `docker exec`)."""
    host_path = SERVER_DIR / "storage" / owner / f"{file_id}.enc"
    if host_path.exists():
        return host_path.read_bytes()

    import os
    env = {**os.environ, "DOCKER_HOST": os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock")}
    try:
        names = subprocess.run(
            ["docker", "ps", "--filter", "name=-app-", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10, env=env,
        ).stdout.split()
    except Exception:
        return None
    if not names:
        return None
    r = subprocess.run(
        ["docker", "exec", names[0], "cat", f"/data/storage/{owner}/{file_id}.enc"],
        capture_output=True, timeout=10, env=env,
    )
    return r.stdout if r.returncode == 0 else None


class Account:


    def __init__(self, client, account_id):
        self.c = client
        self.id = account_id
        self.sig = oqs.Signature(SIG_ALG)
        self.sig_pk = self.sig.generate_keypair()
        self.kem = oqs.KeyEncapsulation(KEM_ALG)
        self.kem_pk = self.kem.generate_keypair()
        self.headers = None

    def register(self):
        return self.c.post("/register", json={
            "account_id": self.id,
            "password": PW,
            "sig_public_key_b64": b64(self.sig_pk),
            "kem_public_key_b64": b64(self.kem_pk),
        })

    def login(self):
        ekem = oqs.KeyEncapsulation(KEM_ALG)
        epk = ekem.generate_keypair()
        init = self.c.post("/session/init", json={
            "account_id": self.id, "kem_public_key_b64": b64(epk),
        }).json()
        sig = self.sig.sign(unb64(init["challenge_b64"]))
        auth = self.c.post("/session/auth", json={
            "session_id": init["session_id"], "password": PW, "signature_b64": b64(sig),
        }).json()
        self.headers = {"Authorization": f"Bearer {auth['token']}"}
        return auth

    def upload(self, filename, plaintext):
        fk = e2e.new_file_key()
        ciphertext = e2e.encrypt_file(fk, plaintext)
        kem_ct, wrapped = e2e.wrap_file_key_for(self.kem_pk, fk)
        r = self.c.post("/drive/upload", headers=self.headers,
                        files={"file": ("blob", ciphertext, "application/octet-stream")},
                        data={
                            "filename": filename,
                            "content_type": "text/plain",
                            "kem_ciphertext_b64": b64(kem_ct),
                            "wrapped_key_b64": b64(wrapped),
                        })
        r.raise_for_status()
        return r.json()

    def download(self, file_id):
        blob = self.c.get(f"/drive/files/{file_id}", headers=self.headers)
        grant = self.c.get(f"/drive/files/{file_id}/key", headers=self.headers)
        if blob.status_code != 200 or grant.status_code != 200:
            return None
        g = grant.json()
        fk = e2e.unwrap_file_key(self.kem, unb64(g["kem_ciphertext_b64"]), unb64(g["wrapped_key_b64"]))
        return e2e.decrypt_file(fk, blob.content)

    def share(self, file_id, recipient_id):
        pk = self.c.get(f"/accounts/{recipient_id}/kem-key", headers=self.headers)
        if pk.status_code != 200:
            return pk
        recipient_pk = unb64(pk.json()["kem_public_key_b64"])
        g = self.c.get(f"/drive/files/{file_id}/key", headers=self.headers).json()
        fk = e2e.unwrap_file_key(self.kem, unb64(g["kem_ciphertext_b64"]), unb64(g["wrapped_key_b64"]))
        kem_ct, wrapped = e2e.wrap_file_key_for(recipient_pk, fk)
        return self.c.post(f"/drive/files/{file_id}/share", headers=self.headers, json={
            "account_id": recipient_id,
            "kem_ciphertext_b64": b64(kem_ct),
            "wrapped_key_b64": b64(wrapped),
        })


def main():
    c = httpx.Client(base_url=BASE, timeout=30, verify=str(CERT))
    SECRET = b"BOARD MINUTES 2026: the number is 47.\n"

    alice = Account(c, f"e2ea-{RUN}")
    bob = Account(c, f"e2eb-{RUN}")
    mallory = Account(c, f"e2em-{RUN}")
    for a in (alice, bob, mallory):
        a.register().raise_for_status()
        a.login()
    print(f"registered + logged in: {alice.id}, {bob.id}, {mallory.id}\n")

    print("round trip:")
    meta = alice.upload("minutes.txt", SECRET)
    check("upload accepted", bool(meta["file_id"]))
    check("owner can decrypt their own file", alice.download(meta["file_id"]) == SECRET)

    print("\nthe server cannot read it:")
    on_disk = read_storage_blob(alice.id, meta["file_id"])
    check("blob found on disk (local or containerized)", on_disk is not None)
    check("plaintext is NOT on disk", on_disk is not None and SECRET not in on_disk)
    check("no recognisable words on disk",
          on_disk is not None and b"BOARD" not in on_disk and b"minutes" not in on_disk)

    raw = c.get(f"/drive/files/{meta['file_id']}", headers=alice.headers).content
    check("what the server serves is ciphertext, not plaintext", SECRET not in raw)
    check("ciphertext is longer than plaintext (nonce+tag)", len(raw) > len(SECRET))

    engine = sqlalchemy.create_engine(DATABASE_URL)
    with engine.connect() as dbconn:
        row = dbconn.execute(text(
            "SELECT wrapped_key FROM file_keys WHERE file_id = :fid"
        ), {"fid": meta["file_id"]}).fetchone()
        check("the DB stores only a WRAPPED key", row is not None and len(bytes(row[0])) == 60)
        cols = [r[0] for r in dbconn.execute(text(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'accounts'"
        ))]
        check("DB has no column holding any user's KEM secret key",
              not any("secret" in col.lower() for col in cols), str(cols))
    engine.dispose()

    print("\nsharing is cryptographic:")
    check("mallory cannot fetch a key grant she has none of",
          c.get(f"/drive/files/{meta['file_id']}/key", headers=mallory.headers).status_code == 404)
    check("bob has no grant before sharing",
          c.get(f"/drive/files/{meta['file_id']}/key", headers=bob.headers).status_code == 404)

    r = alice.share(meta["file_id"], bob.id)
    check("share succeeds", r.status_code == 200, r.text)
    check("bob can now decrypt with HIS OWN key", bob.download(meta["file_id"]) == SECRET)
    check("mallory still cannot even fetch the ciphertext",
          c.get(f"/drive/files/{meta['file_id']}", headers=mallory.headers).status_code == 403)


    ga = c.get(f"/drive/files/{meta['file_id']}/key", headers=alice.headers).json()
    gb = c.get(f"/drive/files/{meta['file_id']}/key", headers=bob.headers).json()
    check("alice's and bob's grants are different ciphertexts",
          ga["kem_ciphertext_b64"] != gb["kem_ciphertext_b64"])
    check("...and different wrapped keys", ga["wrapped_key_b64"] != gb["wrapped_key_b64"])

    print("\nthe server cannot forge access:")


    try:
        e2e.unwrap_file_key(mallory.kem, unb64(gb["kem_ciphertext_b64"]), unb64(gb["wrapped_key_b64"]))
        opened = True
    except Exception:
        opened = False
    check("bob's grant cannot be opened with mallory's key", not opened)

    print("\nrevocation destroys the key grant:")
    c.delete(f"/drive/files/{meta['file_id']}/share/{bob.id}", headers=alice.headers).raise_for_status()
    check("bob's grant is gone (404)",
          c.get(f"/drive/files/{meta['file_id']}/key", headers=bob.headers).status_code == 404)
    check("bob can no longer download at all", bob.download(meta["file_id"]) is None)
    check("alice still can", alice.download(meta["file_id"]) == SECRET)

    print("\nKMS custody:")
    check("no key material left in server/",
          not list(SERVER_DIR.glob("*.bin")) and not list(SERVER_DIR.glob("*wrapping*")))

    import os
    env = {**os.environ, "DOCKER_HOST": os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock")}
    app_names = subprocess.run(
        ["docker", "ps", "--filter", "name=-app-", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=10, env=env,
    ).stdout.split()

    if app_names:
        # Distributed mode: the KMS master key must exist in the kms
        # container's own volume, and be UNREACHABLE from an app
        # replica's filesystem -- app and kms share only the unix socket
        # directory, not the key material itself.
        kms_names = subprocess.run(
            ["docker", "ps", "--filter", "name=-kms-", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10, env=env,
        ).stdout.split()
        check("kms container is running", bool(kms_names))
        if kms_names:
            r = subprocess.run(
                ["docker", "exec", kms_names[0], "test", "-f", "/data/kms/master.key"],
                env=env,
            )
            check("master key exists inside the kms container", r.returncode == 0)
        r = subprocess.run(
            ["docker", "exec", app_names[0], "sh", "-c",
             "find / -xdev -name 'master.key' 2>/dev/null"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        check("master key is NOT reachable from an app replica's filesystem",
              r.stdout.strip() == "", f"found: {r.stdout!r}")
    else:
        kms_home = Path.home() / ".local/share/quantum-auth-kms"
        check("master key lives outside the app tree", (kms_home / "master.key").exists())
        check("...and is not inside server/", SERVER_DIR not in (kms_home / "master.key").parents)

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
