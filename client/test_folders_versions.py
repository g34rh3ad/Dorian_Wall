"""
Folders and file versioning, both integrated with the E2E crypto: every
version gets its own file_id, own encrypted blob, own key grant --
sharing a key across versions would let a newer version silently decrypt
under an older grant.

Run (server + KMS + Postgres must be up): python3 test_folders_versions.py
"""
import secrets

import e2e
import httpx
import oqs
from pathlib import Path

KEM_ALG, SIG_ALG = "ML-KEM-768", "ML-DSA-65"
BASE = "https://127.0.0.1:8443"
CERT = Path(__file__).parent.parent / "server" / "certs" / "cert.pem"
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


class Account:
    def __init__(self, client, account_id):
        self.c = client
        self.id = account_id
        self.sig = oqs.Signature(SIG_ALG)
        self.sig_pk = self.sig.generate_keypair()
        self.kem = oqs.KeyEncapsulation(KEM_ALG)
        self.kem_pk = self.kem.generate_keypair()
        self.headers = None

    def register_and_login(self):
        self.c.post("/register", json={
            "account_id": self.id, "password": PW,
            "sig_public_key_b64": b64(self.sig_pk), "kem_public_key_b64": b64(self.kem_pk),
        }).raise_for_status()
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

    def upload(self, filename, plaintext, folder_id=None):
        fk = e2e.new_file_key()
        ct = e2e.encrypt_file(fk, plaintext)
        kem_ct, wrapped = e2e.wrap_file_key_for(self.kem_pk, fk)
        data = {"filename": filename, "content_type": "text/plain",
                "kem_ciphertext_b64": b64(kem_ct), "wrapped_key_b64": b64(wrapped)}
        if folder_id:
            data["folder_id"] = folder_id
        return self.c.post("/drive/upload", headers=self.headers,
                           files={"file": ("blob", ct, "application/octet-stream")}, data=data)

    def download(self, file_id):
        blob = self.c.get(f"/drive/files/{file_id}", headers=self.headers)
        grant = self.c.get(f"/drive/files/{file_id}/key", headers=self.headers)
        if blob.status_code != 200 or grant.status_code != 200:
            return None
        g = grant.json()
        fk = e2e.unwrap_file_key(self.kem, unb64(g["kem_ciphertext_b64"]), unb64(g["wrapped_key_b64"]))
        return e2e.decrypt_file(fk, blob.content)


def main():
    c = httpx.Client(base_url=BASE, timeout=20, verify=str(CERT))
    A = f"fv-{RUN}"
    alice = Account(c, A)
    alice.register_and_login()

    print("folders:")
    r = c.post("/drive/folders", headers=alice.headers, json={"name": "Projects"})
    check("create root folder", r.status_code == 200, r.text)
    root_folder = r.json()["folder_id"]

    r = c.post("/drive/folders", headers=alice.headers, json={"name": "2026", "parent_id": root_folder})
    check("create nested folder", r.status_code == 200, r.text)
    sub_folder = r.json()["folder_id"]

    r = c.post("/drive/folders", headers=alice.headers, json={"name": "Ghost", "parent_id": "no-such-folder"})
    check("create folder under nonexistent parent rejected (404)", r.status_code == 404)

    listing = c.get("/drive/files", headers=alice.headers).json()
    check("root listing shows the root folder", any(f["folder_id"] == root_folder for f in listing["folders"]))
    check("root listing does NOT show the nested folder", not any(f["folder_id"] == sub_folder for f in listing["folders"]))

    sub_listing = c.get("/drive/files", headers=alice.headers, params={"folder_id": root_folder}).json()
    check("folder listing shows its child folder", any(f["folder_id"] == sub_folder for f in sub_listing["folders"]))

    up = alice.upload("notes.txt", b"in a folder\n", folder_id=sub_folder)
    check("upload into a folder succeeds", up.status_code == 200, up.text)
    file_in_folder = up.json()["file_id"]

    root_files = c.get("/drive/files", headers=alice.headers).json()["files"]
    check("file in subfolder does NOT appear in root listing", not any(f["file_id"] == file_in_folder for f in root_files))
    deep_files = c.get("/drive/files", headers=alice.headers, params={"folder_id": sub_folder}).json()["files"]
    check("file appears in its own folder's listing", any(f["file_id"] == file_in_folder for f in deep_files))

    r = c.delete(f"/drive/folders/{root_folder}", headers=alice.headers)
    check("deleting a non-empty folder rejected (409)", r.status_code == 409)
    r = c.delete(f"/drive/folders/{sub_folder}", headers=alice.headers)
    check("deleting a folder that still has a file rejected (409)", r.status_code == 409)

    print("\nversioning:")
    up1 = alice.upload("report.txt", b"draft one\n")
    check("v1 upload", up1.status_code == 200, up1.text)
    v1 = up1.json()
    check("v1 is version 1", v1["version"] == 1)

    up2 = alice.upload("report.txt", b"draft two, revised\n")
    check("v2 upload (same name) succeeds", up2.status_code == 200, up2.text)
    v2 = up2.json()
    check("v2 is version 2", v2["version"] == 2)
    check("v1 and v2 have DIFFERENT file_ids", v1["file_id"] != v2["file_id"])
    check("v1 and v2 share the same group_id", v1["group_id"] == v2["group_id"] == v1["file_id"])

    listing = c.get("/drive/files", headers=alice.headers).json()["files"]
    matches = [f for f in listing if f["group_id"] == v1["group_id"]]
    check("main listing shows only ONE row for the group (latest version)", len(matches) == 1)
    check("...and it's v2, not v1", matches[0]["file_id"] == v2["file_id"] if matches else False)

    versions = c.get(f"/drive/files/{v2['file_id']}/versions", headers=alice.headers).json()["versions"]
    check("version history has both versions", len(versions) == 2)
    check("version history ordered newest first", versions[0]["version"] == 2 and versions[1]["version"] == 1)

    check("v1 still independently downloadable", alice.download(v1["file_id"]) == b"draft one\n")
    check("v2 downloads the newer content", alice.download(v2["file_id"]) == b"draft two, revised\n")
    check("v1 and v2 are NOT the same ciphertext on the wire (independent encryption)",
          c.get(f"/drive/files/{v1['file_id']}", headers=alice.headers).content !=
          c.get(f"/drive/files/{v2['file_id']}", headers=alice.headers).content)

    g1 = c.get(f"/drive/files/{v1['file_id']}/key", headers=alice.headers).json()
    g2 = c.get(f"/drive/files/{v2['file_id']}/key", headers=alice.headers).json()
    check("v1 and v2 have INDEPENDENT key grants (not shared)",
          g1["wrapped_key_b64"] != g2["wrapped_key_b64"])

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
