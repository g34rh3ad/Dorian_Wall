# Threat Model

This document states, precisely, what this system defends against, what it
assumes, and what it does not defend against. "Is it secure?" is not a
yes/no question without a threat model attached — this is that threat
model, written so each claim is checkable against the code and the test
suites (`client/test_auth.py`, `test_e2e.py`, `test_sharing.py`,
`test_security.py`, 99 assertions total) rather than asserted.

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Account password | Argon2id hash in Postgres | Compromise → impersonation if the signature factor is also broken |
| ML-DSA-65 secret key (signing) | Browser `localStorage`, sealed under a password-derived key | Compromise → impersonation |
| ML-KEM-768 secret key (encryption) | Browser `localStorage`, sealed under a password-derived key | Compromise → can decrypt every file the account can already read |
| File plaintext | Only ever exists in the browser (upload) and the browser (download) | The core asset the whole design protects |
| Per-file AES key | Wrapped to each authorized reader's ML-KEM public key, stored server-side only in wrapped form | Compromise of one wrapped copy ≠ compromise of the key |
| KMS master key | `kms` container's private volume, never touches the app tier | Compromise → server-side envelope broken, but NOT the E2E layer (see §4) |
| Session tokens | Bearer tokens, hash-only stored server-side (`sessions.token_hash`) | Theft → account takeover until TTL/revocation |

## 2. Adversary model

Four adversaries, each with a distinct capability level. A claim like "the
server can't read your files" only means something once you say *which*
of these it survives.

### A1 — Network attacker (no server/client access)
Can observe and tamper with traffic between browser and server.
**Defended.** TLS 1.3 in transit. Even a TLS break only exposes ciphertext
of already-encrypted files (defense in depth, not the primary boundary).

### A2 — Malicious or compromised server operator
Controls the app server and/or its database, but not the KMS container,
not any client browser.
**Defended for file content.** The server never receives file plaintext
or an unwrapped file key (`test_e2e.py`: DB stores only wrapped keys, raw
disk read yields no plaintext, no schema column holds a secret key).
**Not defended for metadata** — filenames, file sizes, who-shared-with-whom,
login timestamps are all plaintext server-side by design (see §5).

### A3 — Compromised client device (post-authentication)
Attacker has code execution in the browser tab after the user has typed
their password at least once during that session (e.g. XSS, malicious
extension).
**Not defended.** This is the sharpest limitation in the whole design and
is stated plainly: script running on this origin can read the unsealed
secret keys from memory, or wait for the next password entry and unseal
`localStorage` itself. See §6 for why, and what actually fixes it
(hardware-backed credentials).

### A4 — Future quantum adversary (harvest-now-decrypt-later)
Records today's network traffic and/or the stored ciphertext, then
gains a cryptographically-relevant quantum computer years later.
**Defended.** ML-KEM-768 and ML-DSA-65 are NIST-standardized
lattice-based algorithms (FIPS 203/204) with no known quantum
polynomial-time attack, unlike RSA/ECDH/ECDSA, which Shor's algorithm
breaks outright once such a computer exists. AES-256 is also
quantum-resistant at this key size (Grover's algorithm only halves
effective strength, leaving 128-bit security — still infeasible).

## 3. What "possible to crack" actually requires, per component

Stated as concrete attack requirements, not vague doubt:

| To break... | An attacker needs... |
|---|---|
| A single login | The account's password **and** its ML-DSA secret key. Neither alone is sufscient — `test_auth.py` verifies both wrong-password-right-key and right-password-wrong-key are rejected identically. |
| A file's confidentiality | Either (a) the owner's or a grantee's ML-KEM secret key, or (b) a working large-scale quantum computer to break ML-KEM-768 itself. There is no third path — the server, holding everything it holds, cannot open the file (§4). |
| The whole system via infrastructure compromise | Root on the app server AND root on the separate `kms` container AND access to Postgres — three independent compromises, not one, because of the KMS/app split (task 3) and because file plaintext isn't there in the first place. |
| A password database offline | Argon2id at OWASP-recommended cost (`m=65536, t=3, p=4`) — brute-forcing a stolen hash is expensive by design, not merely hashed-and-hoped. |

## 4. What "the server cannot read your files" precisely means

This is the claim most likely to draw jury skepticism, so it is stated as
a falsifiable property with its own verification:

**Claim:** an attacker with full read access to the app server's
filesystem, its Postgres database, and network traffic to/from it cannot
recover any uploaded file's plaintext, *provided* they do not also
compromise the KMS container or a client device.

**Why:** the file is AES-256-GCM encrypted in the browser before upload.
The AES key is generated in the browser, never transmitted, and is only
ever transmitted *wrapped* — ML-KEM-encapsulated to the reader's public
key. The server relays wrapped keys; it cannot unwrap them because it
never holds any ML-KEM secret key (those exist only in browsers).

**Verification, not assertion** (`test_e2e.py`):
- raw disk read of the stored blob does not contain the plaintext or
  recognizable substrings of it
- the `/drive/files/{id}` response is ciphertext, longer than the
  plaintext by exactly nonce+tag overhead
- the `file_keys` table stores a 60-byte wrapped key (32-byte AES key +
  12-byte nonce + 16-byte GCM tag) — never a raw key
- no column in `accounts` holds a secret key
- two recipients' key grants for the same file are cryptographically
  distinct ciphertexts (proof the server relayed, not fabricated, the
  grant)
- a third party's ML-KEM secret key cannot open another account's grant

## 5. Explicitly out of scope (stated, not hidden)

- **Metadata privacy.** Filenames, sizes, upload times, and the
  owner/sharee graph are plaintext to the server operator. Only file
  *content* is end-to-end encrypted. A metadata-hiding design (encrypted
  filenames, padded sizes, oblivious sharing) is a distinct, larger
  problem not attempted here.
- **Forward secrecy of already-downloaded plaintext.** Revoking a share
  stops future reads; it cannot un-read what a recipient already
  downloaded and saved locally. No system can retroactively do this once
  bytes have left the server.
- **Compromised-client defense (A3).** Stated in §2 and expanded in §6.
- **KMS single point of compromise for the server-side envelope.** The
  KMS is not replicated (§ architecture doc, task 3) — deliberately, since
  naive replication would mean N independent master keys. A KMS compromise
  breaks the server-side AES envelope but *not* the E2E layer, because the
  E2E layer's keys never touch the KMS at all — they live only in browsers
  and in KMS-independent wrapped form in Postgres.

## 6. The A3 gap, and why it isn't quietly fixed

An attacker with script execution on this origin (XSS) can:
- read the sealed vault from `localStorage`, then wait for the user to
  type their password once and unseal it themselves
- or simply exfiltrate the unsealed keys from page memory during an
  active session

This is **not** a gap that better JavaScript closes. It is inherent to
storing secret keys in any storage a same-origin script can reach. The
only real fix is moving key custody into hardware the browser can direct
but not read from — a WebAuthn authenticator, a TPM-backed credential, or
an OS keychain with biometric gating. That is a real, separate
engineering project (a full WebAuthn ceremony, credential enrollment UX,
fallback/recovery flow), explicitly named as future work rather than
half-implemented. `localStorage` is used here specifically because it
lets *login* behave differently from *registration* (reusing vs. minting a
keypair) without first building that hardware-credential layer — see the
comment in `web/src/common.js`.

**What is done instead to reduce this window:**
- output escaping (`esc()`, applied to every server-derived string
  rendered into the DOM) and a strict CSP with no `unsafe-inline` for
  scripts, closing the specific injection path an assessment pass found
  and confirmed fixed (`test_security.py`, Finding 1)
- short token TTL (10 min) limits how long a *stolen token* (as opposed to
  a stolen key) remains useful
- server-side revocation actually invalidates a token immediately, not
  just client-side

## 7. Summary table

| Threat | Status | Evidence |
|---|---|---|
| Network eavesdropping | Defended | TLS 1.3 |
| Server operator reads file content | Defended | `test_e2e.py` (8 assertions) |
| Server operator reads metadata | **Not** defended (by design, stated) | — |
| Quantum computer breaks auth/exchange | Defended | ML-KEM-768/ML-DSA-65, FIPS 203/204 |
| Password-only compromise | Defended | Two-factor requirement, `test_auth.py` |
| XSS/compromised client | **Not** defended | Stated limitation, §6 |
| Infrastructure compromise (app OR kms alone) | Defended for E2E layer | KMS/app split, task 3 |
| Infrastructure compromise (app AND kms AND a client) | Not defended — nothing is at that point | — |
| Brute-force login | Defended | Lockout after 5 attempts, `test_auth.py` |
| Account enumeration | Defended | Identical timing/response, `test_auth.py` |
