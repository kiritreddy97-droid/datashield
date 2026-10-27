import logging
import os
from dataclasses import dataclass
from functools import lru_cache

from cryptography.fernet import Fernet

log = logging.getLogger("datashield.config")

# Public, obviously-fake values so local dev and tests work with zero setup. Rejected when APP_ENV=production.
_DEV_JWT_SECRET = "dev-only-jwt-secret-do-not-use-in-production-0000"
_DEV_BLIND_KEY = "dev-only-blind-index-key-do-not-use-in-production"
_DEV_FERNET_KEY = "ZGV2LW9ubHktZmVybmV0LWtleS1ub3Qtc2VjcmV0ISE="  # placeholder, not secret


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    app_env: str
    jwt_secret: str
    access_token_ttl_minutes: int
    encryption_keys: str  # comma separated Fernet keys; the first encrypts, all decrypt (rotation)
    blind_index_key: str
    otp_sender: str  # console | smtp
    otp_ttl_minutes: int
    otp_max_attempts: int
    otp_max_per_window: int  # codes that may be issued per identifier per 10 minutes
    removal_sender: str  # smtp | fake
    smtp_host: str | None
    smtp_port: int
    smtp_user: str | None
    smtp_password: str | None
    smtp_from: str | None
    smtp_starttls: bool
    removal_reply_to: str | None
    fixture_scanner_path: str | None
    rate_limit_per_minute: int

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    def validate(self) -> None:
        """Fail fast at startup. In production, refuse to run with dev defaults or leaky senders."""
        if not self.is_production:
            return
        problems = []
        if self.jwt_secret == _DEV_JWT_SECRET or len(self.jwt_secret) < 32:
            problems.append("JWT_SECRET must be set to a random string of at least 32 characters")
        if self.encryption_keys == _DEV_FERNET_KEY:
            problems.append("ENCRYPTION_KEY must be set (Fernet key)")
        else:
            try:
                for k in self.encryption_keys.split(","):
                    Fernet(k.strip())
            except ValueError:
                problems.append("ENCRYPTION_KEY must be one or more comma separated Fernet keys")
        if self.blind_index_key == _DEV_BLIND_KEY or len(self.blind_index_key) < 32:
            problems.append("BLIND_INDEX_KEY must be set to a random string of at least 32 characters")
        if self.otp_sender == "console":
            problems.append("OTP_SENDER=console prints codes to logs; set OTP_SENDER=smtp (or add a provider)")
        if problems:
            raise ConfigError("; ".join(problems))


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, default))


@lru_cache
def get_settings() -> Settings:
    return Settings(
        app_env=os.getenv("APP_ENV", "dev").lower(),
        jwt_secret=os.getenv("JWT_SECRET") or _DEV_JWT_SECRET,
        access_token_ttl_minutes=_int("ACCESS_TOKEN_TTL_MINUTES", 60),
        encryption_keys=os.getenv("ENCRYPTION_KEY") or _DEV_FERNET_KEY,
        blind_index_key=os.getenv("BLIND_INDEX_KEY") or _DEV_BLIND_KEY,
        otp_sender=os.getenv("OTP_SENDER", "console").lower(),
        otp_ttl_minutes=_int("OTP_TTL_MINUTES", 10),
        otp_max_attempts=_int("OTP_MAX_ATTEMPTS", 5),
        otp_max_per_window=_int("OTP_MAX_PER_WINDOW", 3),
        removal_sender=os.getenv("REMOVAL_SENDER", "smtp").lower(),
        smtp_host=os.getenv("SMTP_HOST") or None,
        smtp_port=_int("SMTP_PORT", 587),
        smtp_user=os.getenv("SMTP_USER") or None,
        smtp_password=os.getenv("SMTP_PASSWORD") or None,
        smtp_from=os.getenv("SMTP_FROM") or None,
        smtp_starttls=os.getenv("SMTP_STARTTLS", "1") != "0",
        removal_reply_to=os.getenv("REMOVAL_REPLY_TO") or None,
        fixture_scanner_path=os.getenv("FIXTURE_SCANNER_PATH") or None,
        rate_limit_per_minute=_int("RATE_LIMIT_PER_MINUTE", 120),
    )
