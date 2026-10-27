import pytest
from sqlalchemy import text

from app import crypto
from app.config import ConfigError, Settings, get_settings
from app.logging_config import JsonFormatter


def test_encrypt_roundtrip_and_ciphertext_differs():
    c = crypto.encrypt("asha@example.com")
    assert c != "asha@example.com" and "asha" not in c and crypto.decrypt(c) == "asha@example.com"
    assert crypto.encrypt("asha@example.com") != c  # random IV: ciphertext is not a lookup key


def test_key_rotation_decrypts_old_data(monkeypatch):
    from cryptography.fernet import Fernet
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setenv("ENCRYPTION_KEY", old)
    get_settings.cache_clear(), crypto._fernet.cache_clear()
    token = crypto.encrypt("hello")
    monkeypatch.setenv("ENCRYPTION_KEY", f"{new},{old}")
    get_settings.cache_clear(), crypto._fernet.cache_clear()
    try:
        assert crypto.decrypt(token) == "hello"
        assert crypto.decrypt(crypto.encrypt("x")) == "x"
    finally:
        monkeypatch.undo()
        get_settings.cache_clear(), crypto._fernet.cache_clear()


def test_blind_index_is_keyed_and_deterministic():
    assert crypto.blind_index("email", "a@x.in") == crypto.blind_index("email", "a@x.in")
    assert crypto.blind_index("email", "a@x.in") != crypto.blind_index("phone", "a@x.in")
    assert len(crypto.blind_index("email", "a@x.in")) == 64


@pytest.mark.parametrize("raw,norm", [("9876543210", "+919876543210"), ("+91 98765-43210", "+919876543210"),
                                      ("09876543210", "+919876543210"), ("919876543210", "+919876543210")])
def test_phone_normalisation(raw, norm):
    assert crypto.normalize_phone(raw) == norm


@pytest.mark.parametrize("raw", ["12345", "5876543210", "+1 415 555 0100", "abcdefghij"])
def test_bad_phones_rejected(raw):
    with pytest.raises(ValueError):
        crypto.normalize_phone(raw)


def test_naive_datetimes_are_refused_by_the_database_layer(db):
    from datetime import datetime

    from app.models import AuditEvent
    db.add(AuditEvent(at=datetime(2026, 1, 1), action="x"))
    with pytest.raises(Exception, match="naive datetime"):
        db.flush()
    db.rollback()


def test_datetimes_come_back_timezone_aware(db):
    from app.clock import utcnow
    from app.models import AuditEvent
    db.add(AuditEvent(at=utcnow(), action="x"))
    db.commit()
    assert db.query(AuditEvent).one().at.tzinfo is not None
    assert db.execute(text("select count(*) from audit_events")).scalar() == 1


def test_no_naive_utcnow_left_in_the_code():
    from pathlib import Path
    for f in (Path(__file__).parent.parent / "app").rglob("*.py"):
        assert "datetime.utcnow" not in f.read_text(), f


def _prod(**kw) -> Settings:
    return Settings(**{**get_settings().__dict__, "app_env": "production", **kw})


def test_production_refuses_dev_defaults():
    with pytest.raises(ConfigError) as e:
        _prod().validate()
    msg = str(e.value)
    for needle in ("JWT_SECRET", "ENCRYPTION_KEY", "BLIND_INDEX_KEY", "OTP_SENDER"):
        assert needle in msg


def test_production_accepts_real_settings():
    from cryptography.fernet import Fernet
    _prod(jwt_secret="j" * 40, encryption_keys=Fernet.generate_key().decode(), blind_index_key="b" * 40,
          otp_sender="smtp").validate()
    with pytest.raises(ConfigError, match="Fernet"):
        _prod(jwt_secret="j" * 40, encryption_keys="k" * 44, blind_index_key="b" * 40, otp_sender="smtp").validate()


def test_dev_defaults_are_fine_outside_production():
    get_settings().validate()


def test_json_formatter_emits_extras():
    import json
    import logging
    rec = logging.LogRecord("n", logging.INFO, "", 0, "hello %s", ("w",), None)
    rec.request_id = "abc"
    out = json.loads(JsonFormatter().format(rec))
    assert out["msg"] == "hello w" and out["request_id"] == "abc" and out["level"] == "INFO"
