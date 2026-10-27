"""Encryption at rest for identifiers, plus keyed blind indexes so encrypted columns stay searchable."""

import hashlib
import hmac
import re
from datetime import datetime, timezone
from functools import lru_cache

from cryptography.fernet import Fernet, MultiFernet
from sqlalchemy import DateTime, Text
from sqlalchemy.types import TypeDecorator

from .config import get_settings


@lru_cache
def _fernet() -> MultiFernet:
    keys = [k.strip() for k in get_settings().encryption_keys.split(",") if k.strip()]
    return MultiFernet([Fernet(k) for k in keys])


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


def blind_index(kind: str, value: str) -> str:
    """Deterministic keyed hash for equality lookups (login, uniqueness). Not reversible without the key."""
    key = get_settings().blind_index_key.encode()
    return hmac.new(key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()


def normalize_email(value: str) -> str:
    v = value.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v) or len(v) > 200:
        raise ValueError("invalid email address")
    return v


def normalize_phone(value: str) -> str:
    """Indian mobile numbers only for now. Returns +91XXXXXXXXXX."""
    digits = re.sub(r"[\s\-()]", "", value)
    digits = re.sub(r"^(\+91|91|0)(?=\d{10}$)", "", digits)
    if not re.fullmatch(r"[6-9]\d{9}", digits):
        raise ValueError("invalid Indian mobile number")
    return f"+91{digits}"


class EncryptedText(TypeDecorator):
    """Transparent Fernet encryption. Ciphertext is not searchable; use blind_index() columns for lookups."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else encrypt(value)

    def process_result_value(self, value, dialect):
        return None if value is None else decrypt(value)


class UTCDateTime(TypeDecorator):
    """Timezone-aware datetimes on every backend. Rejects naive values; SQLite drops tzinfo, so restore UTC."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime; use app.clock.utcnow()")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
