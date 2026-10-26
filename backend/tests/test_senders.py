import smtplib

import pytest

from app.config import Settings, get_settings
from app.otp import FakeOtpSender, OtpDeliveryError, SmtpOtpSender, build_otp_sender
from app.removal_sender import Letter, SendError, SmtpRemovalSender


def _settings(**kw) -> Settings:
    base = {**get_settings().__dict__, "smtp_host": "smtp.example.invalid", "smtp_port": 2525, "smtp_user": "u",
            "smtp_password": "p", "smtp_from": "no-reply@datashield.example", "smtp_starttls": True,
            "removal_reply_to": "grievances@datashield.example"}
    return Settings(**{**base, **kw})


class FakeSMTP:
    instances: list["FakeSMTP"] = []
    fail = False

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.calls, self.msg = host, port, [], None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        self.calls.append("starttls")

    def login(self, user, pw):
        self.calls.append(("login", user))

    def send_message(self, msg):
        if FakeSMTP.fail:
            raise smtplib.SMTPException("boom")
        self.msg = msg


@pytest.fixture(autouse=True)
def fake_smtp(monkeypatch):
    FakeSMTP.instances, FakeSMTP.fail = [], False
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)


def test_smtp_removal_sender_builds_and_sends_the_letter():
    SmtpRemovalSender(_settings()).send(Letter("site@example.invalid", "Subject [DS-1]", "Body", "DS-1"))
    smtp = FakeSMTP.instances[0]
    assert smtp.calls == ["starttls", ("login", "u")]
    assert smtp.msg["To"] == "site@example.invalid" and smtp.msg["Reply-To"] == "grievances@datashield.example"
    assert smtp.msg.get_content().strip() == "Body"


def test_smtp_failure_becomes_send_error():
    FakeSMTP.fail = True
    with pytest.raises(SendError):
        SmtpRemovalSender(_settings()).send(Letter("a@b.invalid", "s", "b", "DS-1"))


def test_smtp_otp_sender_is_email_only():
    sender = SmtpOtpSender(_settings())
    sender.send("email", "a@x.in", "123456")
    assert "123456" in FakeSMTP.instances[0].msg.get_content()
    with pytest.raises(OtpDeliveryError):
        sender.send("phone", "+919876543210", "123456")


def test_fake_otp_sender_records_and_can_fail():
    s = FakeOtpSender()
    s.send("email", "a@x.in", "111111")
    assert s.last_code("a@x.in") == "111111"
    s.fail = True
    with pytest.raises(OtpDeliveryError):
        s.send("email", "a@x.in", "222222")


def test_default_otp_sender_is_the_console_one():
    assert type(build_otp_sender()).__name__ == "ConsoleOtpSender"
