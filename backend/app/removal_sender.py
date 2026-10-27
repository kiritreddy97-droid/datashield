"""Delivery of removal letters to sites, behind an interface."""

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

from .config import Settings, get_settings

log = logging.getLogger("datashield.removal")


class SendError(Exception):
    pass


@dataclass
class Letter:
    to: str
    subject: str
    body: str
    reference: str  # e.g. DS-123, so replies can be matched to a request


class RemovalSender(Protocol):
    def send(self, letter: Letter) -> None:
        """Deliver the letter or raise SendError."""


class FakeRemovalSender:
    """Records letters instead of sending them. Used in tests and for dry runs (REMOVAL_SENDER=fake)."""

    def __init__(self):
        self.outbox: list[Letter] = []
        self.fail_for: set[str] = set()

    def send(self, letter: Letter) -> None:
        if letter.to in self.fail_for:
            raise SendError("fake failure")
        self.outbox.append(letter)
        log.info("fake send", extra={"reference": letter.reference})


class SmtpRemovalSender:
    def __init__(self, settings: Settings):
        if not (settings.smtp_host and settings.smtp_from):
            raise SendError("SMTP_HOST and SMTP_FROM are required for REMOVAL_SENDER=smtp")
        self.s = settings

    def send(self, letter: Letter) -> None:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.s.smtp_from, letter.to, letter.subject
        if self.s.removal_reply_to:
            msg["Reply-To"] = self.s.removal_reply_to
        msg.set_content(letter.body)
        try:
            with smtplib.SMTP(self.s.smtp_host, self.s.smtp_port, timeout=30) as smtp:
                if self.s.smtp_starttls:
                    smtp.starttls()
                if self.s.smtp_user:
                    smtp.login(self.s.smtp_user, self.s.smtp_password or "")
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as e:
            raise SendError(type(e).__name__) from e


def build_removal_sender() -> RemovalSender:
    settings = get_settings()
    if settings.removal_sender == "fake":
        return FakeRemovalSender()
    return SmtpRemovalSender(settings)
