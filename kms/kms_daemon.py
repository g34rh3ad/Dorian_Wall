
import base64
import hashlib
import hmac
import json
import os
import socket
import socketserver
import stat
import sys
from pathlib import Path


KMS_HOME = Path(os.environ.get("QAD_KMS_HOME", Path.home() / ".local/share/quantum-auth-kms"))
MASTER_KEY_PATH = KMS_HOME / "master.key"
DEFAULT_SOCKET = KMS_HOME / "kms.sock"

MAX_REQUEST_BYTES = 4096


def load_or_create_master_key() -> bytes:
    KMS_HOME.mkdir(parents=True, exist_ok=True)
    os.chmod(KMS_HOME, 0o700)
    if MASTER_KEY_PATH.exists():
        mode = stat.S_IMODE(MASTER_KEY_PATH.stat().st_mode)
        if mode & 0o077:
            raise SystemExit(
                f"refusing to start: {MASTER_KEY_PATH} is group/world accessible "
                f"(mode {mode:04o}); run: chmod 600 {MASTER_KEY_PATH}"
            )
        return MASTER_KEY_PATH.read_bytes()

    key = os.urandom(32)
    MASTER_KEY_PATH.write_bytes(key)
    os.chmod(MASTER_KEY_PATH, 0o600)
    print(f"generated new master key at {MASTER_KEY_PATH}")
    return key


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha384).digest()
        out += t
        counter += 1
    return out[:length]


class KMSHandler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline(MAX_REQUEST_BYTES)
        if not raw:
            return
        try:
            req = json.loads(raw)
            op = req.get("op")
            if op == "derive":
                info = req.get("info")
                if not isinstance(info, str) or not info or len(info) > 256:
                    raise ValueError("bad info")
                key = hkdf_expand(self.server.master_key, info.encode())
                resp = {"key": base64.b64encode(key).decode()}
            elif op == "ping":
                resp = {"pong": True}
            else:
                raise ValueError("unknown op")
        except Exception as e:
            resp = {"error": str(e)}
        self.wfile.write((json.dumps(resp) + "\n").encode())


class KMSServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path, master_key):
        self.master_key = master_key
        super().__init__(path, KMSHandler)


def main():
    sock_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SOCKET
    master_key = load_or_create_master_key()

    if sock_path.exists():
        sock_path.unlink()
    server = KMSServer(str(sock_path), master_key)

    os.chmod(sock_path, 0o600)

    print(f"KMS listening on {sock_path} (master key: {MASTER_KEY_PATH})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if sock_path.exists():
            sock_path.unlink()


if __name__ == "__main__":
    main()
