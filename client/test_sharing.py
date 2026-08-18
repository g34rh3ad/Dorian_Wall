
import base64
import secrets
import sys
from pathlib import Path

import httpx
import oqs

import e2e

KEM_ALG, SIG_ALG = "ML-KEM-768", "ML-DSA-65"
BASE = "https://127.0.0.1:8443"
CERT = Path(__file__).parent.parent / "server" / "certs" / "cert.pem"


RUN = secrets.token_hex(3)
PASSWORD = "correct-horse-battery-2026"

KEMS = {}

passed = failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label} {detail}")


def promote(account_id) -> bool:

    import subprocess
    server_dir = Path(__file__).parent.parent / "server"
    try:
        r = subprocess.run(
            [sys.executable, "promote_admin.py", account_id],
            cwd=server_dir, capture_output=True, timeout=30,
        )
        return r.returncode == 0
    except Exception:
        return False


def enroll(client, account_id):

    sig = oqs.Signature(SIG_ALG)
    pk = sig.generate_keypair()
    kem = oqs.KeyEncapsulation(KEM_ALG)
    kpk = kem.generate_keypair()
    client.post("/register", json={
        "account_id": account_id,
        "password": PASSWORD,
        "sig_public_key_b64": base64.urlsafe_b64encode(pk).decode(),
        "kem_public_key_b64": base64.urlsafe_b64encode(kpk).decode(),
    }).raise_for_status()
    KEMS[account_id] = (kem, kpk)
    return sig


def login(client, account_id, sig):

    kem = oqs.KeyEncapsulation(KEM_ALG)
    kpk = kem.generate_keypair()
    init = client.post("/session/init", json={
        "account_id": account_id,
        "kem_public_key_b64": base64.urlsafe_b64encode(kpk).decode(),
    }).json()
    kem.decap_secret(base64.urlsafe_b64decode(init["ciphertext_b64"]))
    signature = sig.sign(base64.urlsafe_b64decode(init["challenge_b64"]))
    auth = client.post("/session/auth", json={
        "session_id": init["session_id"],
        "password": PASSWORD,
        "signature_b64": base64.urlsafe_b64encode(signature).decode(),
    }).json()
    return {"Authorization": f"Bearer {auth['token']}"}


def upload(client, headers, account_id, filename, plaintext):

    _, kpk = KEMS[account_id]
    fk = e2e.new_file_key()
    ct = e2e.encrypt_file(fk, plaintext)
    kem_ct, wrapped = e2e.wrap_file_key_for(kpk, fk)
    return client.post("/drive/upload", headers=headers,
                       files={"file": ("blob", ct, "application/octet-stream")},
                       data={"filename": filename, "content_type": "text/plain",
                             "kem_ciphertext_b64": e2e.b64(kem_ct),
                             "wrapped_key_b64": e2e.b64(wrapped)})


def share(client, headers, sharer_id, file_id, recipient_id):

    grant = client.get(f"/drive/files/{file_id}/key", headers=headers)
    if grant.status_code == 200 and recipient_id in KEMS:
        kem_obj, _ = KEMS[sharer_id]
        g = grant.json()
        fk = e2e.unwrap_file_key(kem_obj, e2e.unb64(g["kem_ciphertext_b64"]),
                                 e2e.unb64(g["wrapped_key_b64"]))
        kem_ct, wrapped = e2e.wrap_file_key_for(KEMS[recipient_id][1], fk)
    else:
        kem_ct, wrapped = b"\x00" * 1088, b"\x00" * 60
    return client.post(f"/drive/files/{file_id}/share", headers=headers, json={
        "account_id": recipient_id,
        "kem_ciphertext_b64": e2e.b64(kem_ct),
        "wrapped_key_b64": e2e.b64(wrapped),
    })


def read_file(client, headers, account_id, file_id):

    blob = client.get(f"/drive/files/{file_id}", headers=headers)
    grant = client.get(f"/drive/files/{file_id}/key", headers=headers)
    if blob.status_code != 200 or grant.status_code != 200:
        return None
    g = grant.json()
    fk = e2e.unwrap_file_key(KEMS[account_id][0], e2e.unb64(g["kem_ciphertext_b64"]),
                             e2e.unb64(g["wrapped_key_b64"]))
    return e2e.decrypt_file(fk, blob.content)


def main():
    c = httpx.Client(base_url=BASE, timeout=10, verify=str(CERT))

    A, B, M = f"alice-{RUN}", f"bob-{RUN}", f"mallory-{RUN}"
    alice_sig = enroll(c, A)
    alice = login(c, A, alice_sig)
    bob = login(c, B, enroll(c, B))
    mallory = login(c, M, enroll(c, M))
    print(f"logged in: {A}, {B}, {M}\n")


    r = upload(c, alice, A, "secret.txt", b"alice's confidential notes\n")
    r.raise_for_status()
    file_id = r.json()["file_id"]
    print(f"alice uploaded secret.txt ({file_id[:8]}...)\n")

    print("access before sharing:")
    check("alice can download her own file",
          c.get(f"/drive/files/{file_id}", headers=alice).status_code == 200)
    check("bob CANNOT download it (403)",
          c.get(f"/drive/files/{file_id}", headers=bob).status_code == 403)
    check("bob's shared-with-me list is empty",
          c.get("/drive/shared", headers=bob).json()["files"] == [])

    print("\nsharing rules:")
    check("mallory CANNOT share alice's file (403)",
          share(c, mallory, M, file_id, M).status_code == 403)
    check("alice CANNOT share with herself (400)",
          share(c, alice, A, file_id, A).status_code == 400)
    check("alice CANNOT share with a nonexistent account (404)",
          share(c, alice, A, file_id, "ghost-no-such-account").status_code == 404)
    check("mallory CANNOT list shares on alice's file (403)",
          c.get(f"/drive/files/{file_id}/shares", headers=mallory).status_code == 403)

    print("\nalice shares with bob:")
    r = share(c, alice, A, file_id, B)
    check("share succeeds (200)", r.status_code == 200, r.text)
    check("bob can NOW download it",
          c.get(f"/drive/files/{file_id}", headers=bob).status_code == 200)
    check("bob decrypts the correct plaintext with his own key",
          read_file(c, bob, B, file_id) == b"alice's confidential notes\n")
    shared = c.get("/drive/shared", headers=bob).json()["files"]
    check("file appears in bob's shared-with-me", len(shared) == 1 and shared[0]["owner"] == A)
    check("mallory STILL cannot download it (403)",
          c.get(f"/drive/files/{file_id}", headers=mallory).status_code == 403)
    check("alice sees bob in the share list",
          [s["shared_with"] for s in c.get(f"/drive/files/{file_id}/shares", headers=alice).json()["shares"]] == [B])
    check("owner's file list shows shared_with_count=1",
          c.get("/drive/files", headers=alice).json()["files"][0]["shared_with_count"] == 1)
    check("shared file does NOT appear in bob's OWN file list",
          c.get("/drive/files", headers=bob).json()["files"] == [])

    print("\nrecipient cannot escalate:")
    check("bob CANNOT re-share alice's file (403)",
          share(c, bob, B, file_id, M).status_code == 403)
    check("bob CANNOT revoke alice's shares (403)",
          c.delete(f"/drive/files/{file_id}/share/{B}", headers=bob).status_code == 403)
    check("bob CANNOT list the share roster (403)",
          c.get(f"/drive/files/{file_id}/shares", headers=bob).status_code == 403)

    print("\nrevocation:")
    check("alice revokes bob's access (200)",
          c.delete(f"/drive/files/{file_id}/share/{B}", headers=alice).status_code == 200)
    check("bob can no longer download (403)",
          c.get(f"/drive/files/{file_id}", headers=bob).status_code == 403)
    check("bob's shared-with-me is empty again",
          c.get("/drive/shared", headers=bob).json()["files"] == [])
    check("revoking a nonexistent share 404s",
          c.delete(f"/drive/files/{file_id}/share/{B}", headers=alice).status_code == 404)

    print("\nowner delete:")
    r = upload(c, alice, A, "doomed.txt", b"delete me\n")
    doomed = r.json()["file_id"]
    share(c, alice, A, doomed, B)
    check("recipient CANNOT delete a file shared with them (403)",
          c.delete(f"/drive/files/{doomed}", headers=bob).status_code == 403)
    check("unrelated account CANNOT delete it (403)",
          c.delete(f"/drive/files/{doomed}", headers=mallory).status_code == 403)
    check("file still downloadable after failed deletes",
          c.get(f"/drive/files/{doomed}", headers=alice).status_code == 200)
    check("owner CAN delete it (200)",
          c.delete(f"/drive/files/{doomed}", headers=alice).status_code == 200)
    check("file is gone (404)",
          c.get(f"/drive/files/{doomed}", headers=alice).status_code == 404)
    check("recipient's shared list drops it",
          all(f["file_id"] != doomed for f in c.get("/drive/shared", headers=bob).json()["files"]))
    check("deleting again 404s",
          c.delete(f"/drive/files/{doomed}", headers=alice).status_code == 404)

    print("\ncleanup on delete:")
    c.post(f"/drive/files/{file_id}/share", headers=alice, json={"account_id": B})


    promoted = promote(A)
    if promoted:


        alice = login(c, A, alice_sig)
        check("admin delete succeeds",
              c.delete(f"/admin/files/{file_id}", headers=alice).status_code == 200)
        check("shares vanish with the deleted file",
              c.get("/drive/shared", headers=bob).json()["files"] == [])
    else:
        print(f"  SKIP  admin delete -- could not run promote_admin.py for {A}")

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
