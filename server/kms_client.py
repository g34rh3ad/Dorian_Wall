
import base64
import json
import os
import socket
from pathlib import Path

DEFAULT_SOCKET = Path(
    os.environ.get(
        "QAD_KMS_SOCKET",
        str(Path.home() / ".local/share/quantum-auth-kms/kms.sock"),
    )
)
TIMEOUT_SECONDS = 5


class KMSUnavailable(RuntimeError):
    pass


class KMSClient:
    def __init__(self, socket_path: Path = DEFAULT_SOCKET):
        self.socket_path = Path(socket_path)

    def _request(self, payload: dict) -> dict:
        if not self.socket_path.exists():
            raise KMSUnavailable(
                f"KMS socket not found at {self.socket_path}. "
                f"Start it with: python3 kms/kms_daemon.py"
            )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT_SECONDS)
                s.connect(str(self.socket_path))
                s.sendall((json.dumps(payload) + "\n").encode())
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
        except (OSError, socket.timeout) as e:
            raise KMSUnavailable(f"KMS request failed: {e}")

        resp = json.loads(buf)
        if "error" in resp:
            raise KMSUnavailable(f"KMS error: {resp['error']}")
        return resp

    def ping(self) -> bool:
        return bool(self._request({"op": "ping"}).get("pong"))

    def derive_key(self, info: str) -> bytes:

        resp = self._request({"op": "derive", "info": info})
        return base64.b64decode(resp["key"])
