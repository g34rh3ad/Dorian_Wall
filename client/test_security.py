
import base64
import secrets
import subprocess
import sys
from pathlib import Path

import httpx
import oqs

import e2e

KEM_ALG, SIG_ALG = "ML-KEM-768", "ML-DSA-65"
BASE = "https://127.0.0.1:8443"
SERVER_DIR = Path(__file__).parent.parent / "server"
CERT = SERVER_DIR / "certs" / "cert.pem"

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


def b64(d):
    return base64.urlsafe_b64encode(d).decode()


def unb64(d):
    return base64.urlsafe_b64decode(d)


def register(c, acct, pw=PW, pubkey_b64=None):
    sig = oqs.Signature(SIG_ALG)
    pk = sig.generate_keypair()
    kem = oqs.KeyEncapsulation(KEM_ALG)
    kpk = kem.generate_keypair()
    r = c.post("/register", json={
        "account_id": acct,
        "password": pw,
        "sig_public_key_b64": pubkey_b64 if pubkey_b64 is not None else b64(pk),
        "kem_public_key_b64": b64(kpk),
    })
    return r, sig


def upload(c, headers, filename, plaintext):

    kem = oqs.KeyEncapsulation(KEM_ALG)
    kpk = kem.generate_keypair()
    fk = e2e.new_file_key()
    ct = e2e.encrypt_file(fk, plaintext)
    kem_ct, wrapped = e2e.wrap_file_key_for(kpk, fk)
    return c.post("/drive/upload", headers=headers,
                  files={"file": ("blob", ct, "application/octet-stream")},
                  data={"filename": filename, "content_type": "text/plain",
                        "kem_ciphertext_b64": e2e.b64(kem_ct),
                        "wrapped_key_b64": e2e.b64(wrapped)})


def login(c, acct, sig, pw=PW):
    kem = oqs.KeyEncapsulation(KEM_ALG)
    kpk = kem.generate_keypair()
    init = c.post("/session/init", json={"account_id": acct, "kem_public_key_b64": b64(kpk)}).json()
    signature = sig.sign(unb64(init["challenge_b64"]))
    auth = c.post("/session/auth", json={
        "session_id": init["session_id"], "password": pw, "signature_b64": b64(signature),
    }).json()
    return {"Authorization": f"Bearer {auth['token']}"}


def main():
    c = httpx.Client(base_url=BASE, timeout=30, verify=str(CERT))


    print("Finding 1 -- stored XSS:")
    xss_ids = [
        "<img src=x onerror=alert(1)>",
        "<script>alert(1)</script>",
        "abc<svg/onload=alert(1)>",
        'a"onmouseover="alert(1)',
    ]
    blocked = [register(c, i)[0].status_code == 400 for i in xss_ids]
    check("HTML-payload account_ids rejected at registration (400)", all(blocked), str(blocked))

    acct = f"xsstest{RUN}"
    r, sig = register(c, acct)
    check("clean account_id still accepted (200)", r.status_code == 200, r.text)
    h = login(c, acct, sig)

    payload_name = "<img src=x onerror=alert(1)>.txt"
    up = upload(c, h, payload_name, b"x")
    stored_name = up.json()["filename"]
    check("upload filename stripped of < and >",
          "<" not in stored_name and ">" not in stored_name, stored_name)
    check("upload filename stripped of quotes",
          '"' not in upload(c, h, 'a"b.txt', b"x").json()["filename"])


    print("\nFinding 2 -- path traversal:")
    for bad in ["..", ".", "../evil", "/tmp/evil", "a/../../b", "..\\evil"]:
        check(f"account_id {bad!r} rejected (400)",
              register(c, bad)[0].status_code == 400)

    before = set(SERVER_DIR.glob("*.enc"))
    check("no stray .enc blobs in server/ (traversal sandbox holds)", not before, str(before))


    print("\nFinding 5 -- Content-Disposition:")
    quote_up = upload(c, h, 'invoice"  extra.pdf', b"x")
    dl = c.get(f"/drive/files/{quote_up.json()['file_id']}", headers=h)
    cd = dl.headers.get("content-disposition", "")
    check("header has no raw quote breaking the value",
          cd.count('"') == 2, cd)
    check("header uses RFC 6266 filename* form", "filename*=UTF-8''" in cd, cd)


    print("\nFinding 6 -- docs exposure:")
    for path in ["/docs", "/redoc", "/openapi.json"]:
        check(f"{path} not served (404)", c.get(path).status_code == 404)


    print("\nFinding 7 -- security headers:")
    root = c.get("/")
    for header, expect in [
        ("content-security-policy", "script-src 'self'"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("strict-transport-security", "max-age="),
        ("referrer-policy", "no-referrer"),
    ]:
        got = root.headers.get(header, "")
        check(f"{header} present and correct", expect in got, f"got {got!r}")
    check("CSP has no unsafe-inline for scripts",
          "'unsafe-inline'" not in root.headers.get("content-security-policy", "").split("style-src")[0])


    print("\nFindings 8/9 -- register input validation:")
    r_bad_b64, _ = register(c, f"badb64{RUN}", pubkey_b64="!!!not-base64!!!")
    check("malformed base64 public key -> 400 not 500", r_bad_b64.status_code == 400, r_bad_b64.text)
    r_short, _ = register(c, f"shortkey{RUN}", pubkey_b64="AAAA")
    check("wrong-length public key rejected (400)", r_short.status_code == 400, r_short.text)


    print("\nFinding 4 -- handshake flood:")
    kpk = b64(oqs.KeyEncapsulation(KEM_ALG).generate_keypair())
    codes = []
    for _ in range(150):
        codes.append(c.post("/session/init", json={
            "account_id": f"flood{RUN}", "kem_public_key_b64": kpk,
        }).status_code)
    check("abandoned-handshake flood gets rate limited (429 seen)",
          429 in codes, f"codes={sorted(set(codes))}")

    print("\nFinding 3 -- registration rate limit:")
    codes = [register(c, f"rl{RUN}x{i}")[0].status_code for i in range(25)]
    check("registration flood gets rate limited (429 seen)",
          429 in codes, f"codes={codes}")

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
