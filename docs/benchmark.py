"""
Real measurements, not textbook numbers -- run on this project's own
liboqs build vs. Python's `cryptography` library for the classical
baselines, same machine, same process.

Run: python3 docs/benchmark.py
"""
import statistics
import time

import oqs
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

N = 200


def timeit(fn, n=N):
    # one warmup, excluded from the timed samples
    fn()
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return statistics.mean(times), statistics.median(times), statistics.stdev(times)


def fmt(row):
    mean, median, stdev = row
    return f"{mean:.3f} ms (median {median:.3f}, σ {stdev:.3f})"


def section(title):
    print(f"\n## {title}\n")


def main():
    print(f"N = {N} iterations per measurement, one warmup excluded.\n")

    section("Key exchange: ML-KEM-768 vs X25519 (ECDH)")

    def kem_full_exchange():
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        pk = kem.generate_keypair()
        ct, ss1 = kem.encap_secret(pk)
        ss2 = kem.decap_secret(ct)
        assert ss1 == ss2

    kem_keygen = oqs.KeyEncapsulation("ML-KEM-768")
    pk_tmp = kem_keygen.generate_keypair()
    ct_tmp, ss_tmp = kem_keygen.encap_secret(pk_tmp)
    print(f"ML-KEM-768 measured sizes: pk={len(pk_tmp)}B  ciphertext={len(ct_tmp)}B  shared_secret={len(ss_tmp)}B")
    print(f"ML-KEM-768 full exchange (keygen+encap+decap): {fmt(timeit(kem_full_exchange))}")

    def x25519_full_exchange():
        priv_a = ec.generate_private_key(ec.SECP256R1())
        priv_b = ec.generate_private_key(ec.SECP256R1())
        shared_a = priv_a.exchange(ec.ECDH(), priv_b.public_key())
        shared_b = priv_b.exchange(ec.ECDH(), priv_a.public_key())
        assert shared_a == shared_b

    pub_bytes = priv = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    print(f"ECDH P-256 measured pk size: {len(pub_bytes)}B (no ciphertext step -- DH has no encapsulation artifact)")
    print(f"ECDH P-256 full exchange (2x keygen+exchange):  {fmt(timeit(x25519_full_exchange))}")

    section("Signatures: ML-DSA-65 vs ECDSA P-256 vs RSA-2048")

    def dsa_sign_verify():
        sig = oqs.Signature("ML-DSA-65")
        pk = sig.generate_keypair()
        msg = b"benchmark message payload, 32 bytes long!!"
        s = sig.sign(msg)
        ok = sig.verify(msg, s, pk)
        assert ok

    sig_tmp = oqs.Signature("ML-DSA-65")
    pk_tmp2 = sig_tmp.generate_keypair()
    sig_bytes_tmp = sig_tmp.sign(b"x" * 32)
    print(f"ML-DSA-65 measured sizes: pk={len(pk_tmp2)}B  signature={len(sig_bytes_tmp)}B")
    print(f"ML-DSA-65 full cycle (keygen+sign+verify): {fmt(timeit(dsa_sign_verify))}")

    def ecdsa_sign_verify():
        priv = ec.generate_private_key(ec.SECP256R1())
        msg = b"benchmark message payload, 32 bytes long!!"
        s = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
        priv.public_key().verify(s, msg, ec.ECDSA(hashes.SHA256()))

    priv_tmp = ec.generate_private_key(ec.SECP256R1())
    pub_bytes_tmp = priv_tmp.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    ecdsa_sig_tmp = priv_tmp.sign(b"x" * 32, ec.ECDSA(hashes.SHA256()))
    print(f"ECDSA P-256 measured sizes: pk={len(pub_bytes_tmp)}B  signature~={len(ecdsa_sig_tmp)}B (DER, variable)")
    print(f"ECDSA P-256 full cycle (keygen+sign+verify): {fmt(timeit(ecdsa_sign_verify))}")

    def rsa_sign_verify(priv):
        msg = b"benchmark message payload, 32 bytes long!!"
        s = priv.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        priv.public_key().verify(s, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub_bytes = rsa_priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    rsa_sig_tmp = rsa_priv.sign(b"x" * 32, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    print(f"RSA-2048 measured sizes: pk={len(rsa_pub_bytes)}B  signature={len(rsa_sig_tmp)}B")
    print(f"RSA-2048 sign+verify only (keygen excluded, too slow to loop 200x): {fmt(timeit(lambda: rsa_sign_verify(rsa_priv)))}")

    section("Symmetric: AES-256-GCM throughput")
    key = AESGCM.generate_key(256)
    aes = AESGCM(key)
    payload = b"x" * (1024 * 1024)  # 1 MiB

    def aes_roundtrip():
        nonce = b"0" * 12
        ct = aes.encrypt(nonce, payload, None)
        pt = aes.decrypt(nonce, ct, None)
        assert pt == payload

    mean, median, stdev = timeit(aes_roundtrip, n=100)
    mb_per_sec = (1.0 / (mean / 1000)) if mean > 0 else float("inf")
    print(f"AES-256-GCM 1 MiB encrypt+decrypt: {mean:.3f} ms  (~{mb_per_sec:.0f} MiB/s round-trip)")

    section("Summary (see docs/BENCHMARKS.md for the write-up)")
    print("Raw numbers above; do not hand-copy without re-running -- these vary by machine.")


if __name__ == "__main__":
    main()
