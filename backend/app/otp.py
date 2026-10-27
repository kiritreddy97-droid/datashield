"""One-time-code delivery behind an interface, so SMS/email providers can be swapped in without touching routes."""

import logging
import smtplib
from email.message import EmailMessage
from typing import Protocol

from .config import Settings, get_settings

log = logging.getLogger("datashield.otp")


class OtpDeliveryError(Exception):
    pass


class OtpSender(Protocol):
    def send(self, channel: str, destination: str, code: str) -> None:
        """Deliver `code` to an email address or phone number. Raise OtpDeliveryError on failure."""


class ConsoleOtpSender:
    """Development only: prints the code to the log. Refused at startup when APP_ENV=production."""

    def send(self, channel: str, destination: str, code: str) -> None:
        log.warning("DEV OTP for %s %s: %s", channel, destination, code)


class FakeOtpSender:
    """Test double that remembers what was sent."""

    def __init__(self):
        self.sent: list[tuple[str, str, str]] = []
        self.fail = False

    def send(self, channel: str, destination: str, code: str) -> None:
        if self.fail:
            raise OtpDeliveryError("fake failure")
        self.sent.append((channel, destination, code))

    def last_code(self, destination: str) -> str:
        return next(c for _, d, c in reversed(self.sent) if d == destination)


class SmtpOtpSender:
    """Email codes over SMTP. Phone codes need an SMS provider (DLT-registered in India): add an OtpSender for it."""

    def __init__(self, settings: Settings):
        if not (settings.smtp_host and settings.smtp_from):
            raise OtpDeliveryError("SMTP_HOST and SMTP_FROM are required for OTP_SENDER=smtp")
        self.s = settings

    def send(self, channel: str, destination: str, code: str) -> None:
        if channel != "email":
            raise OtpDeliveryError(f"channel {channel} is not configured")
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.s.smtp_from, destination, "Your DataShield verification code"
        msg.set_content(f"Your DataShield verification code is {code}. It expires in {self.s.otp_ttl_minutes} "
                        f"minutes. If you did not ask for it, ignore this email.")
        try:
            with smtplib.SMTP(self.s.smtp_host, self.s.smtp_port, timeout=15) as smtp:
                if self.s.smtp_starttls:
                    smtp.starttls()
                if self.s.smtp_user:
                    smtp.login(self.s.smtp_user, self.s.smtp_password or "")
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as e:
            raise OtpDeliveryError(type(e).__name__) from e


def build_otp_sender() -> OtpSender:
    settings = get_settings()
    if settings.otp_sender == "smtp":
        return SmtpOtpSender(settings)
    return ConsoleOtpSender()
