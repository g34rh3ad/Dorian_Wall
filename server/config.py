from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="QAD_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8443
    cert_file: Path = Path("certs/cert.pem")
    key_file: Path = Path("certs/key.pem")

    db_path: Path = Path("./drive.db")
    storage_dir: Path = Path("./storage")
    static_dir: Path = Path("../web/dist")

    kms_socket: Path = Path.home() / ".local/share/quantum-auth-kms/kms.sock"

    max_upload_mb: int = 25
    token_ttl_seconds: int = 600
    handshake_ttl_seconds: int = 30
    max_pending_sessions: int = 5000

    rate_limit_init_per_min: int = 120
    rate_limit_register_per_min: int = 20
    rate_limit_login_per_min: int = 60

    log_level: str = "INFO"
    log_json: bool = True

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


settings = Settings()
