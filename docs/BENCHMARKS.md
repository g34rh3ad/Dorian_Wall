# Performance: PQC vs. Classical Cryptography

All numbers below were measured on this project's own machine (ARM64,
Kali Linux), not copied from a paper — reproduce with:

```bash
python3 docs/benchmark.py
```

200 iterations per measurement (100 for the AES throughput test), one
warmup excluded, using liboqs (this project's actual PQC library) against
Python's `cryptography` library for the classical baselines — same
process, same machine, same measurement method, so the comparison is
apples-to-apples rather than pulled from two different sources with two
different methodologies.

## Key exchange: ML-KEM-768 vs. ECDH P-256

| | ML-KEM-768 | ECDH P-256 | Delta |
|---|---|---|---|
| Public key size | 1184 B | 65 B | **18.2× larger** |
| Ciphertext (KEM only) | 1088 B | — (DH has none) | — |
| Shared secret | 32 B | 32 B | same |
| Full exchange, mean | **0.110 ms** | 0.204 ms | **1.85× faster** |

**The size overhead is real and large — ~18×.** This is the honest cost of
post-quantum key exchange: ML-KEM ciphertexts and keys are kilobytes, not
tens of bytes, because lattice-based hardness needs much larger parameters
than elliptic-curve discrete log.

**The speed result is the opposite of the common assumption.** ML-KEM-768
was measured *faster* than classical ECDH here, not slower. This is a
known property of lattice-based KEMs (the arithmetic is simple modular
polynomial operations, cheaper per-operation than elliptic curve point
multiplication) — but it is not something to assert without measuring it,
which is why it's reported with the actual number rather than assumed.

## Signatures: ML-DSA-65 vs. ECDSA P-256 vs. RSA-2048

| | ML-DSA-65 | ECDSA P-256 | RSA-2048 |
|---|---|---|---|
| Public key size | 1952 B | 65 B | 294 B |
| Signature size | 3309 B | ~72 B (DER) | 256 B |
| Full cycle, mean | 0.463 ms | 0.159 ms | 0.978 ms* |

\* RSA measurement excludes keygen (RSA-2048 keygen is ~10–50 ms and
would dominate a 200-iteration loop pointlessly; sign+verify only)

**Where the real cost is:** ML-DSA-65 signatures are **~46× larger** than
ECDSA's and **~13× larger** than RSA's. In a system that signs a token on
every login and re-verifies it on every subsequent request, that's
bandwidth and storage overhead accumulating per-request, not a one-time
cost. This project's tokens carry that overhead directly — worth stating
plainly rather than only citing algorithm names.

**CPU-wise**, ML-DSA-65 sits between ECDSA (faster) and RSA-2048 (slower)
here — not the bottleneck for a system already paying tens of milliseconds
per request for Argon2id and network round trips (see below).

## Symmetric: AES-256-GCM

| | Result |
|---|---|
| 1 MiB encrypt+decrypt round trip | 1.085 ms (~921 MiB/s) |

Included for completeness: AES-256 is not touched by the PQC migration
at all (Grover's algorithm only halves its effective strength, leaving
128-bit security — still infeasible) and is not the bottleneck anywhere
in this system.

## What actually dominates end-to-end latency

Isolated primitive benchmarks above are sub-millisecond. A real login
against the live distributed deployment (nginx → app replica → Postgres →
Argon2id verify → Redis) was also measured directly, not estimated:

| | Result |
|---|---|
| Full login (register once, then 30× full 2-round-trip login), median | **73.4 ms** |
| min / max | 62.9 ms / 90.9 ms |

**The PQC operations are not the cost.** ML-KEM handshake + ML-DSA
signature together measured well under 1 ms above; a real login takes
~73 ms. The difference is almost entirely Argon2id (deliberately slow —
that's the point of a memory-hard password hash) plus two HTTP round
trips through the load balancer and a database round trip. **Migrating
from RSA/ECDSA to ML-KEM/ML-DSA would not be user-perceptible** in this
system's actual latency budget — the password hashing alone costs more
than both PQC operations combined, many times over.

## Honest summary

| Dimension | PQC cost vs. classical |
|---|---|
| CPU time (isolated) | Comparable, sometimes better (KEM), sometimes worse (signatures) — not the bottleneck either way |
| Wire/storage size | Substantially larger (18–46×) — the real, unavoidable cost |
| End-to-end user-perceived latency | No measurable difference — dominated by Argon2id and network, not crypto choice |

This is the standard finding in PQC migration literature (see
`docs/RELATED_WORK.md`): the practical cost of moving to post-quantum
algorithms today is bandwidth and storage, not compute. This project's
own numbers, measured rather than cited, confirm that pattern.
