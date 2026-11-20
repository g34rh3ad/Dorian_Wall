# The Dorian Wall

Local proof of concept for the design in *Quantum-Resistant Authentication for
Footage & Data Storage*: a Drive-like cloud storage service where sign-in and
every file operation are gated by post-quantum authentication. Real
ML-KEM-768 key exchange and ML-DSA-65 signatures via
[liboqs](https://github.com/open-quantum-safe/liboqs) (NIST FIPS 203/204) on
the server, and via [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
(pure JS, no CDN) in the browser — not a simulation of the crypto. The only
simulated piece is the QRNG entropy source
(`server/pqc_utils.py::simulated_qrng_bytes`), clearly labeled and swappable
for a hardware feed later.

Runs as a real distributed deployment (Postgres, Redis, 2+ stateless app
replicas behind nginx, a separate single-instance KMS) — see
`docker-compose.yml` and `docs/`:

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — adversary model, what's
  defended and what's explicitly not, each claim tied to a test
- [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) — ML-KEM/ML-DSA vs. classical
  crypto, measured on this project's own build, not cited from elsewhere
- [`docs/RELATED_WORK.md`](docs/RELATED_WORK.md) — positioned against
  Proton Drive/Tresorit's E2E pattern and existing PQC-TLS deployments

Drive features: nested folders, and file versioning where each version
gets its own independent E2E encryption key (`client/test_folders_versions.py`).

## Pages

| Page | What it does |
|---|---|
| `/ui/index.html` | Landing page, links to the three flows below |
| `/ui/register.html` | Creates an account: mints an ML-DSA-65 keypair, stores the secret key locally, enrolls the public key, then signs in |
| `/ui/login.html` | Signs in an existing account by reusing its local keypair — no re-enrollment, no password |
| `/ui/admin.html` | Same sign-in, but only renders the dashboard if the server grants `admin` scope |

**Registration vs. login is a real distinction here**: registering mints a new
keypair (and overwrites any existing local one for that account name, with a
confirm prompt); logging in reuses the stored keypair and will fail outright
if this browser has no identity for that account.

**Admin** is granted out-of-band with `python3 promote_admin.py <account_id>`
run on the server host — deliberately *not* an API endpoint, since letting an
account grant itself admin over the API it authenticates against would defeat
the role entirely. `session_auth` adds `admin` to the token scope at issue
time, and every `/admin/*` route re-checks that scope per request.

## What it demonstrates

1. **Enroll** — client registers a long-lived ML-DSA-65 identity public key.
2. **Handshake** — server encapsulates a shared secret against the client's
   ephemeral ML-KEM-768 public key and issues a random challenge.
3. **Auth** — client proves it holds the matching secret key by signing the
   challenge; server verifies, mixes the KEM shared secret with QRNG-sourced
   entropy via HKDF, and issues a short-lived (10 min) ML-DSA-signed session
   token scoped to `drive:read`/`drive:write`.
4. **Gated storage** — `/drive/upload`, `/drive/files`, `/drive/files/{id}`
   all re-verify the token's signature, expiry, and scope on every request;
   a corrupted token is rejected. Every file is encrypted at rest with
   AES-256-GCM before it touches disk.
5. **Sharing** — an owner can grant another account read access to a file,
   see who it's shared with, and revoke. Recipients see it under "Shared
   with me", can download it, and can do nothing else: they can't re-share,
   can't revoke, and can't enumerate the share roster. Deleting a file
   takes its shares with it.
6. **Persistence** — accounts and file metadata live in SQLite
   (`server/drive.db`); the AES wrapping key is held by the external KMS
   (see "Key custody" below), outside the app tree. Both survive a server
   restart, so previously uploaded files still list and decrypt correctly
   afterward.

## Run it

```bash
cd quantum-auth-poc
source venv/bin/activate
cd server
uvicorn main:app --host 127.0.0.1 --port 8443 --ssl-certfile certs/cert.pem --ssl-keyfile certs/key.pem
```

Then either:

- **Browser client** — open `https://127.0.0.1:8443/ui/`, enter an account
  ID, click "Sign in", then upload/download files from the Drive panel.
- **CLI client** — `cd client && python3 client.py alex` (enrolls, handshakes,
  uploads a demo file, lists it, downloads + decrypts it, then confirms a
  tampered token is rejected).

### TLS cert

`server/certs/` holds the TLS cert the server presents. Two ways to generate it:

- **`mkcert localhost 127.0.0.1 ::1`** (run from `server/certs/`) — issues a
  cert signed by a local CA that `mkcert -install` trusts system- and
  browser-wide, so there's no warning at all. Needs `mkcert` +
  `libnss3-tools` installed and `mkcert -install` run once (both need sudo).
  This is what's currently deployed.
- **`python3 gen_cert.py`** (from `server/`) — a plain self-signed cert,
  no extra tools needed, but every client has to explicitly trust it (the
  CLI client does, via `verify=<path to cert.pem>`; a browser will show a
  one-time warning to click through).

Either way, this secures the *transport* (TLS 1.3, classical ECDHE) the way
any HTTPS deployment would. It sits **underneath** the app's own ML-KEM/
ML-DSA handshake, not in place of it — the quantum-resistance argument in
the design doc rests on that application-layer handshake, which holds
regardless of what the TLS layer negotiates. A fully hybrid PQC *transport*
(X25519 + ML-KEM inside TLS itself) needs OpenSSL built with the OQS
provider and hybrid groups enabled — an infra change, not an app change,
and called out as design doc §08's phase-3 item.

## Layout

```
server/
  main.py               FastAPI app: /enroll, /session/init, /session/auth,
                         /drive/upload, /drive/files, /drive/files/{id}, and
                         /ui (serves the browser client, same origin -> no CORS)
  pqc_utils.py           ML-KEM / ML-DSA wrappers, HKDF, token issuance/
                         verification, FileVault (AES-256-GCM at rest)
  db.py                  SQLite persistence for accounts + file metadata
  promote_admin.py       grant/revoke admin on an account (operator-run, not an API)
  drive.db               created on first run (gitignored, not on GitHub)
  storage/<account>/     encrypted file blobs, one per upload (gitignored)
  gen_cert.py            generates a plain self-signed TLS cert (alternative to mkcert)
  certs/                 cert.pem + key.pem the server presents over TLS
client/
  client.py              CLI walkthrough of the full flow, prints each step
  test_sharing.py        24 assertions over the sharing rules, incl. the
                         negative cases (non-owner share, recipient re-share,
                         revocation, share cleanup on delete)
web/
  src/common.js          Shared: base64, local identity storage, the handshake
  src/register.js|.html   Registration page
  src/login.js|.html      Login + drive page
  src/admin.js|.html      Admin dashboard page
  src/index.js|.html      Landing page
  src/styles.css          Shared styles
  dist/                   esbuild output served at /ui -- rebuild with:
                            cd web
                            for p in index register login admin; do
                              npx esbuild src/$p.js --bundle --format=esm \
                                --target=es2020 --outfile=dist/$p-bundle.js
                            done
                            cp src/*.html src/styles.css dist/
requirements.txt
```

## Project structure

```
server/
  main.py           app factory: wires config, logging, routers, static UI
  config.py         pydantic-settings; all runtime config via QAD_* env vars
  routers/
    auth.py         /register, /session/init, /session/auth, /session/logout
    drive.py        /drive/*, /accounts/{id}/kem-key
    admin.py        /admin/*
  deps.py           require_token() -- shared auth dependency for routers
  logging_config.py structured JSON logs + per-request X-Request-ID
  db.py, passwords.py, validation.py, security.py, pqc_utils.py, kms_client.py
  requirements.txt  pinned dependency versions
client/             CLI walkthroughs + the 4 test suites
kms/kms_daemon.py   key-custody process, see "Key custody" below
web/src/            browser UI (vanilla JS, no framework)
Dockerfile, docker-compose.yml, docker-entrypoint.sh
```

Shared runtime objects (token authority, file vault, rate limiters, the
in-memory pending-handshake dict) live on `app.state`, set up once in
`main.py`'s lifespan hook and reached from routers via `request.app.state`
-- not module-level globals, so they're swappable in tests and there's one
place that owns their lifecycle.

## Configuration

All runtime config is environment-driven (`server/config.py`, prefix
`QAD_`) instead of constants scattered across files. Copy
`server/.env.example` to `server/.env` and adjust as needed; every setting
has a sane default matching what this POC has always run with, so an empty
`.env` is fine for local dev.

## Running without Docker

```bash
pip install -r server/requirements.txt
python3 kms/kms_daemon.py &
cd server && uvicorn main:app --host 127.0.0.1 --port 8443 \
  --ssl-certfile certs/cert.pem --ssl-keyfile certs/key.pem
```

## Running with Docker

```bash
docker compose up --build
```

One container runs both the KMS daemon and the app (simplest correct
setup for a POC; splitting them across containers would need the KMS
socket on a shared volume, a fine follow-up but not done here). Persistent
state — the database, encrypted files, the KMS master key, and the TLS
cert — lives in a named volume (`qad-data`), so `docker compose down` and
`up` again keeps everything; `docker compose down -v` wipes it.

First boot generates a self-signed cert automatically if none exists at
`/data/certs`. Visit `https://localhost:8443/ui/` (browser will warn about
the self-signed cert — same as the non-Docker path before `mkcert` was
set up locally).

**Known trade-off:** the image keeps its C build toolchain (cmake, ninja,
gcc) in the final layer because `liboqs-python` compiles the PQC library
at first import — a proper multi-stage split (build liboqs in one stage,
copy only the compiled `.so` into a slim final stage) would shrink the
image meaningfully but wasn't done here.

## Logging

Structured JSON to stdout, one line per event, `docker compose logs -f` or
`server.log` locally:

```json
{"ts": 1787045375.14, "level": "INFO", "logger": "quantum_auth.security",
 "msg": "login_success", "request_id": "e4f23b507947",
 "event": "login_success", "account_id": "abel", "ip": "127.0.0.1", "scope": [...]}
```

Every request gets an `X-Request-ID` (client-supplied or generated),
threaded through every log line emitted while handling it — grep one
request's full story with `grep <request_id> server.log`. Security-relevant
events (register, login success/fail/lockout, upload, share/revoke,
delete, admin actions) are logged explicitly via `log_security_event()`;
everything else is uvicorn's own request logging, also JSON now.

## End-to-end encryption

Files are encrypted **in the browser**, before upload. The server stores
ciphertext it cannot read.

How it works:

1. At registration the browser generates **two** keypairs — ML-DSA-65
   (identity/signing) and a long-term **ML-KEM-768** (encryption). Only the
   public halves are sent to the server. Both secret halves are sealed in
   `localStorage` under a PBKDF2-derived key (600k iterations), so a stolen
   browser profile alone doesn't open them.
2. On upload the browser generates a random 32-byte file key, encrypts the
   file with AES-256-GCM, then wraps that key to its own ML-KEM public key.
   The server receives ciphertext + an opaque key grant.
3. On download the browser fetches both, recovers the file key with its
   ML-KEM secret key, and decrypts locally.
4. **Sharing is cryptographic.** The owner's browser fetches the
   recipient's public key, reopens the file key, and re-wraps it to them.
   The server relays the grant but cannot create one — so it cannot grant
   itself, or anyone else, access to a file it stores. Revoking deletes the
   grant.

The server still envelope-encrypts the stored ciphertext a second time
(keys from the KMS below), so a raw read of `storage/` yields nothing even
to someone holding a user's keys but not the server's.

**What this means:** the operator can no longer read user files. That was
the last row of the "not secure" table — Google-Drive model to Proton-Drive
model.

**What it costs, stated plainly:**

- **Lose your password or browser storage, lose your files.** There is no
  server-side copy of your ML-KEM secret key and no recovery path. This is
  inherent to E2E, not an oversight.
- **Revocation is forward-only.** Deleting a grant stops future reads; it
  cannot un-read what a recipient already downloaded.
- **XSS on this origin still wins.** Script on the page can wait for the
  password and read the unsealed keys. Only a hardware-backed credential
  (WebAuthn/TPM) fixes that — the CSP and output escaping are what keep
  that door shut today.

## Key custody (KMS)

The AES wrapping key used for the server-side envelope no longer lives in
`server/`. It sits in a separate process (`kms/kms_daemon.py`) holding it
in `~/.local/share/quantum-auth-kms/master.key` (0600), reachable only over
a 0600 unix socket. The app requests *derived, per-file* keys and never
holds the master key.

This closes the naive-backup hole: a `tar` of `server/` no longer captures
anything that can decrypt `storage/`.

It does **not** defend against root on this host, and an attacker who
compromises the running app can still ask the KMS to derive keys. Real HSMs
have the same property — they prevent key *exfiltration*, not misuse by an
already-compromised client.

The server **fails to start** if the KMS is unreachable, rather than
falling back to a local key file.

```bash
# terminal 1 -- must be running before the server
python3 kms/kms_daemon.py

# terminal 2
cd server && uvicorn main:app --host 127.0.0.1 --port 8443 \
  --ssl-certfile certs/cert.pem --ssl-keyfile certs/key.pem
```

## Security hardening

A security assessment on 2026-08-17
(`quantum-auth-poc-testing/summary/findings-report.md`) found 10 actionable
issues. All are fixed, with regression tests in `client/test_security.py`:

| # | Finding | Fix |
|---|---|---|
| 1 | **Stored XSS** via `account_id` / `filename` (Critical) | Charset allowlist on `account_id`, filename sanitiser (`server/validation.py`); every `innerHTML` sink in the frontend now goes through `esc()` in `web/src/common.js` |
| 2 | Path traversal via `account_id` | Same allowlist, plus `safe_account_dir()` resolves and asserts the path stays under `storage/` before any filesystem call |
| 3 | Account enumeration via `/register` | Rate limited. The 409 itself is kept — self-service registration has to tell you a name is taken — and the trade-off is documented in the endpoint |
| 4 | Unbounded `pending_sessions` (DoS) | TTL sweep on every `/session/init` + a hard `MAX_PENDING_SESSIONS` cap that sheds load with a 503 |
| 5 | Content-Disposition injection | RFC 6266 `filename*=UTF-8''` encoding (`content_disposition()`) |
| 6 | `/docs`, `/redoc`, `/openapi.json` exposed | Disabled |
| 7 | No security headers | `SecurityHeadersMiddleware` — CSP (no `unsafe-inline` for scripts), HSTS, `nosniff`, `DENY`, `no-referrer`, `no-store` |
| 8 | 500 on malformed base64 | Validated → 400 |
| 9 | Public key not validated | Length-checked against ML-DSA-65's 1952 bytes |
| 10 | Stale run instructions in docstring | Corrected to point at this README |

Findings 11 and 12 (decorative KEM secret, wrapping key beside the DB) are
informational and remain accepted POC limitations — see below.

**Rate limits** are per source IP and sized so shared egress (NAT, office)
doesn't lock legitimate users out: 120/min handshakes, 60/min logins,
20/min registrations. They're a speed bump — the real DoS control is the
`pending_sessions` cap, and the real credential-guessing control is the
per-account lockout in `passwords.py`.

Run the suites in this order — `test_security.py` deliberately exhausts the
rate limits, so run it last:

```bash
cd client
python3 test_auth.py      # 20 assertions -- two-factor login, token lifecycle
python3 test_e2e.py       # 22 assertions -- server cannot read stored files
python3 test_sharing.py   # 31 assertions -- share/revoke/delete authorisation
python3 test_security.py  # 26 assertions -- the 10 assessment findings stay closed
```

## What's not in scope for this POC

- No HSM/KMS — the AES wrapping key and the server's ML-DSA identity key are
  both held by the application process, not a hardware-backed key vault.
  The wrapping key is at least persisted to disk (0600) so restarts don't
  orphan existing files; the identity key still regenerates each restart,
  which is fine given tokens are short-lived (10 min) anyway.
- No real QRNG hardware — see `simulated_qrng_bytes()`.
- **Sharing is access control, not end-to-end encryption.** The server holds
  the wrapping key and decrypts on the way out, so a share changes *who may
  ask* for a file — not who can mathematically open it. Anyone with the
  wrapping key (or root on the server) can read any file regardless of
  shares. True E2E sharing would mean the client encrypts before upload and
  the owner re-wraps the file's data key to the recipient's long-term
  ML-KEM public key, so the server never holds plaintext or a usable key.
  That needs long-term KEM keys enrolled per account (today only ML-DSA
  signing keys are enrolled; KEM keys are ephemeral per session) and
  client-side encryption throughout — a real re-architecture, not a flag.
  This is the same trade-off Google Drive and Dropbox make by default.
- Shares are read-only; there's no write/edit permission tier.
- 25MB upload cap, no chunked/resumable upload.
- No user-facing delete — only admins can delete files (`/admin/files/{id}`).
- Identity secret keys live in `localStorage`, which any XSS on this origin
  could read. A real deployment keeps them in a hardware-backed credential
  (WebAuthn authenticator, TPM, OS keychain) that signs without ever
  exposing the key to JS. `localStorage` is used here only so login can
  meaningfully differ from registration without standing up a full WebAuthn
  ceremony — see the note in `web/src/common.js`.
- Account identity is per-browser: registering on another device or clearing
  site data means that browser can no longer sign in as that account. There
  is **no recovery, rotation, or re-issuance flow** — `/enroll` refuses any
  account_id that already exists (409), because enrollment is
  unauthenticated and an upsert there would let anyone re-pin any account's
  public key and take it over, admin scope included. Rotation needs a
  separate flow proving possession of the current key; that isn't built.

These map directly to the design doc's phase-1 rollout scope (§08): hybrid
handshake and signed tokens first, hardware QRNG and HSM custody are
additive upgrades layered in later without changing the protocol.

## Contributing

This started as a proof of concept, built and tested in one long session
rather than hardened over time — so contributions that close real gaps are
welcome, especially the ones already named above (SQLAlchemy/Alembic
migrations, WebAuthn-backed key storage, splitting the KMS into its own
container, multi-stage Docker build to drop the compiler toolchain from
the final image).

Before opening a PR:

1. Run the full test suite — it has to stay green:
   ```bash
   cd client
   python3 test_auth.py && python3 test_e2e.py && \
   python3 test_sharing.py && python3 test_security.py
   ```
2. If you touch the crypto (`server/pqc_utils.py`, `web/src/common.js`,
   `client/e2e.py`), keep the JS and Python HKDF implementations in sync —
   `client/e2e.py` exists specifically to exercise the same wire format the
   browser produces. A mismatch there means passing tests with unopenable
   files in production.
3. CI (`.github/workflows/tests.yml`) runs all four suites on every push;
   a PR that fails it won't merge.
4. Explain the *why* behind security-relevant changes in the PR
   description — the code itself is comment-free by design (stripped
   intentionally), so that context has nowhere else to live.

Bug reports and design-doc-scope questions are just as welcome as code —
open an issue.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it; no warranty, see
the standard MIT disclaimer for what that means in practice.
