
import base64
import secrets
from pathlib import Path

import httpx
import oqs

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


def b64(d):
    return base64.urlsafe_b64encode(d).decode()


def unb64(d):
    return base64.urlsafe_b64decode(d)


def register(c, acct, pw=PW):
    sig = oqs.Signature(SIG_ALG)
    pk = sig.generate_keypair()
    kem = oqs.KeyEncapsulation(KEM_ALG)
    kpk = kem.generate_keypair()
    r = c.post("/register", json={
        "account_id": acct, "password": pw,
        "sig_public_key_b64": b64(pk), "kem_public_key_b64": b64(kpk),
    })
    return r, sig


def attempt(c, acct, sig, pw=PW, tamper_sig=False):

    kem = oqs.KeyEncapsulation(KEM_ALG)
    kpk = kem.generate_keypair()
    init = c.post("/session/init", json={"account_id": acct, "kem_public_key_b64": b64(kpk)}).json()
    challenge = unb64(init["challenge_b64"])
    signature = sig.sign(challenge) if sig else secrets.token_bytes(3309)
    if tamper_sig:
        signature = signature[:-4] + b"\x00\x00\x00\x00"
    return c.post("/session/auth", json={
        "session_id": init["session_id"], "password": pw, "signature_b64": b64(signature),
    })


def main():
    c = httpx.Client(base_url=BASE, timeout=20, verify=str(CERT))
    A = f"authtest-{RUN}"

    print("registration policy:")
    r, _ = register(c, f"weak-{RUN}", "short")
    check("password under 10 chars rejected (400)", r.status_code == 400, r.text)
    r, _ = register(c, f"common-{RUN}", "password123")
    check("common password rejected (400)", r.status_code == 400, r.text)
    r, _ = register(c, f"selfname-{RUN}", f"selfname-{RUN}-x1")
    check("password containing account id rejected (400)", r.status_code == 400, r.text)

    r, sig = register(c, A)
    check("valid registration succeeds (200)", r.status_code == 200, r.text)
    r2, _ = register(c, A)
    check("re-registering an existing account rejected (409)", r2.status_code == 409)

    print("\nboth factors required:")
    check("correct password + correct signature -> 200", attempt(c, A, sig).status_code == 200)
    check("correct password + WRONG signature -> 401",
          attempt(c, A, sig, tamper_sig=True).status_code == 401)
    wrong_sig = oqs.Signature(SIG_ALG)
    wrong_sig.generate_keypair()
    check("correct password + OTHER device's key -> 401",
          attempt(c, A, wrong_sig).status_code == 401)
    check("WRONG password + correct signature -> 401",
          attempt(c, A, sig, pw="totally-wrong-passphrase").status_code == 401)

    print("\nno oracle leaks:")
    r_wrong_pw = attempt(c, A, sig, pw="totally-wrong-passphrase")
    r_no_acct = attempt(c, f"ghost-{RUN}", sig)
    check("wrong password and unknown account give the SAME status",
          r_wrong_pw.status_code == r_no_acct.status_code == 401)
    check("...and the SAME message",
          r_wrong_pw.json()["detail"] == r_no_acct.json()["detail"],
          f'{r_wrong_pw.json()} vs {r_no_acct.json()}')
    init = c.post("/session/init", json={
        "account_id": f"definitely-not-real-{RUN}", "kem_public_key_b64": b64(oqs.KeyEncapsulation(KEM_ALG).generate_keypair()),
    })
    check("session/init does not reveal whether an account exists (200)", init.status_code == 200)

    print("\ntoken lifecycle:")
    ok = attempt(c, A, sig)
    token = ok.json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    check("token works before logout", c.get("/drive/files", headers=h).status_code == 200)
    check("logout reports revoked", c.post("/session/logout", headers=h).json()["status"] == "revoked")
    check("token REJECTED after logout (401)", c.get("/drive/files", headers=h).status_code == 401)
    check("logging out twice is harmless",
          c.post("/session/logout", headers=h).json()["status"] == "already inactive")
    check("tampered token rejected (401)",
          c.get("/drive/files", headers={"Authorization": f"Bearer {token[:-4]}abcd"}).status_code == 401)

    print("\nbrute-force lockout:")
    L = f"lockme-{RUN}"
    _, lsig = register(c, L)
    codes = [attempt(c, L, lsig, pw=f"wrong-guess-{i}").status_code for i in range(5)]
    check("first 5 bad attempts all 401", codes == [401] * 5, str(codes))
    locked = attempt(c, L, lsig)
    check("account locked after 5 failures, even with the RIGHT password (429)",
          locked.status_code == 429, locked.text)
    check("lockout message says how long", "locked for" in locked.json()["detail"])

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
