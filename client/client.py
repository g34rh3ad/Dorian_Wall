
import base64
import sys
from pathlib import Path

import httpx
import oqs

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode())


def main():
    account_id = sys.argv[1] if len(sys.argv) > 1 else "alex"
    password = sys.argv[2] if len(sys.argv) > 2 else "demo-passphrase-2026"
    base_url = sys.argv[3] if len(sys.argv) > 3 else "https://127.0.0.1:8443"


    cert_path = Path(__file__).parent.parent / "server" / "certs" / "cert.pem"
    client = httpx.Client(base_url=base_url, timeout=10, verify=str(cert_path) if cert_path.exists() else True)

    print(f"== quantum-auth-drive-poc client :: account={account_id} ==\n")


    sig = oqs.Signature(SIG_ALG)
    sig_pubkey = sig.generate_keypair()
    print(f"[1] generated {SIG_ALG} identity keypair (pubkey {len(sig_pubkey)} bytes)")

    r = client.post("/register", json={
        "account_id": account_id,
        "password": password,
        "sig_public_key_b64": b64(sig_pubkey),
    })
    if r.status_code == 409:


        print(f"[2] account '{account_id}' already exists -- this demo generates a new "
              f"keypair each run, so pick an unused id:\n"
              f"      python3 client.py {account_id}-2 <password>")
        return 1
    r.raise_for_status()
    print(f"[2] registered: {r.json()}\n")


    kem = oqs.KeyEncapsulation(KEM_ALG)
    kem_pubkey = kem.generate_keypair()
    print(f"[3] generated ephemeral {KEM_ALG} keypair (pubkey {len(kem_pubkey)} bytes)")

    r = client.post("/session/init", json={
        "account_id": account_id,
        "kem_public_key_b64": b64(kem_pubkey),
    })
    r.raise_for_status()
    init = r.json()
    session_id = init["session_id"]
    ciphertext = unb64(init["ciphertext_b64"])
    challenge = unb64(init["challenge_b64"])
    print(f"[4] handshake init -> session={session_id[:8]}..., "
          f"ciphertext {len(ciphertext)} bytes, challenge {len(challenge)} bytes")

    shared_secret = kem.decap_secret(ciphertext)
    print(f"[5] decapsulated shared secret ({len(shared_secret)} bytes) -- "
          f"matches server's without it ever crossing the wire")

    challenge_signature = sig.sign(challenge)
    r = client.post("/session/auth", json={
        "session_id": session_id,
        "password": password,
        "signature_b64": b64(challenge_signature),
    })
    r.raise_for_status()
    auth = r.json()
    token = auth["token"]
    print(f"[6] sent password + signature; server verified BOTH factors")
    print(f"    session key fingerprint: {auth['session_key_fingerprint']}")
    print(f"    token: {token[:60]}...\n")

    headers = {"Authorization": f"Bearer {token}"}

    demo_bytes = b"hello from the quantum-auth-drive-poc CLI client\n"
    r = client.post(
        "/drive/upload",
        headers=headers,
        files={"file": ("hello.txt", demo_bytes, "text/plain")},
    )
    r.raise_for_status()
    meta = r.json()
    print(f"[7] uploaded + encrypted at rest: {meta}\n")

    r = client.get("/drive/files", headers=headers)
    r.raise_for_status()
    print(f"[8] GET /drive/files -> {r.json()}\n")

    r = client.get(f"/drive/files/{meta['file_id']}", headers=headers)
    r.raise_for_status()
    print(f"[9] downloaded + decrypted: {r.content!r}\n")

    print("[10] retrying with a corrupted token to confirm the gate holds:")
    bad_headers = {"Authorization": f"Bearer {token[:-4]}abcd"}
    r = client.get("/drive/files", headers=bad_headers)
    print(f"    -> HTTP {r.status_code}: {r.json()}")


if __name__ == "__main__":
    raise SystemExit(main())
