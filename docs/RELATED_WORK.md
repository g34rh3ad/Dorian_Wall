# Related Work & Positioning

**A note on sourcing, stated up front:** the facts below (NIST
standardization dates, Signal's PQXDH, browser PQC-TLS rollout) are
well-documented public events and are described at the level of general
knowledge, not pulled from a live search. Specific competitor products'
*current* internal cryptographic stacks are described based on their
public documentation as generally known — **verify each product claim
against that product's current published documentation before citing this
section in a formal submission**, since product crypto stacks change and
this was not re-checked against live sources at time of writing.

## 1. Where post-quantum cryptography stands (context)

NIST finalized the first post-quantum cryptography standards in August
2024: **FIPS 203 (ML-KEM**, derived from CRYSTALS-Kyber, key
encapsulation**)**, **FIPS 204 (ML-DSA**, derived from CRYSTALS-Dilithium,
signatures**)**, and FIPS 205 (SLH-DSA, hash-based signatures). This
project uses the first two.

Production adoption of PQC key exchange is already underway at the
transport layer: major browsers and CDN operators have deployed **hybrid**
key exchange (classical X25519 combined with a PQC KEM, originally Kyber,
now ML-KEM) in TLS 1.3, specifically to close the "harvest now, decrypt
later" window — the same threat this project's design doc cites as its
core justification (§1 of the original design document). Signal's
protocol added **PQXDH**, a post-quantum extension to its X3DH key
agreement, for the same reason, in its messaging protocol.

**What is less common:** applying PQC not just at the transport layer
(TLS) but at the *application* layer for both authentication (signatures)
and end-to-end file encryption (KEM-wrapped per-file keys), as a working,
tested system rather than a protocol proposal. That combination — PQC
transport-independent auth *and* PQC-wrapped E2E file sharing — is the
specific contribution this project makes, positioned against the existing
work below.

## 2. Comparison: existing E2E cloud storage products

| | Key exchange / auth | File encryption | Quantum-resistant? | Sharing model |
|---|---|---|---|---|
| **Google Drive / Dropbox** | Classical (RSA/ECC), server-managed keys | Server-side (server can read files) | No | Server-mediated ACL |
| **Proton Drive** | Classical ECC (X25519/Ed25519 per public documentation) | Client-side E2E | No (as of public docs) | Public-key encrypted per recipient |
| **Tresorit** | Classical RSA/ECC | Client-side E2E | No (as of public docs) | Public-key encrypted per recipient |
| **Mega** | Classical RSA/AES | Client-side E2E | No | Key sharing via RSA |
| **This project** | **ML-KEM-768 + ML-DSA-65** | Client-side E2E, AES-256-GCM under ML-KEM-wrapped keys | **Yes** | ML-KEM re-wrap per recipient (§ design doc) |

The architectural *pattern* — client-side encryption, server relays
ciphertext and wrapped keys, sharing = re-wrapping a key to a recipient's
public key — is the same pattern Proton Drive, Tresorit, and Mega already
use and have used in production for years. **This project's distinction
is not inventing that pattern; it's substituting quantum-vulnerable
primitives (RSA/ECC) for quantum-resistant ones (ML-KEM/ML-DSA) inside an
otherwise well-established E2E architecture**, and doing so all the way
through — authentication, session establishment, and file sharing, not
just transport.

## 3. What this project does not claim

- **Not a new cryptographic primitive.** ML-KEM and ML-DSA are NIST's
  standards, implemented via the Open Quantum Safe project's `liboqs`, not
  designed here. The contribution is systems/architecture — integrating
  standardized PQC correctly end-to-end — not cryptography research.
- **Not the first PQC-TLS deployment.** Browsers and CDNs got there first,
  at the transport layer. This project's distinction is depth (auth +
  E2E file sharing, not just the transport handshake), not priority.
- **Not immune to the same open problems the field has.** Signature size
  overhead (§ benchmarks — ML-DSA-65 signatures are ~46× larger than
  ECDSA's) is a known, unsolved cost of lattice-based signatures
  generally, not something this project's design avoids.

## 4. Where this project sits

A systems-integration contribution: a working, tested (99 assertions
across four suites), horizontally-scaled deployment demonstrating that
NIST's 2024-finalized PQC standards can replace classical primitives
**throughout** a real application's auth and storage stack — not just at
the TLS layer where the existing production deployments (browsers, CDNs,
Signal) have focused — while keeping the same E2E-encrypted-sharing
architecture already proven in production by classical-crypto products
like Proton Drive and Tresorit.

The threat model (`docs/THREAT_MODEL.md`) and benchmarks
(`docs/BENCHMARKS.md`) are written to make this a checkable claim, not an
assertion: what's defended, what's measured, and what's explicitly not
attempted (metadata privacy, compromised-client defense) are all stated
rather than implied.
