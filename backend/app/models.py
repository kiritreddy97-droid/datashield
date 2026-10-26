from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .clock import utcnow
from .crypto import EncryptedText, UTCDateTime
from .db import Base


class Person(Base):
    """The data principal and the account holder. A row exists only after OTP proof of a contact.

    name/email/phone are encrypted at rest; *_hash are keyed blind indexes used only for lookup.
    """

    __tablename__ = "people"

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    email: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    email_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, nullable=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    phone: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    phone_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, nullable=True)
    phone_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    scan_consent_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    scan_consent_revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Finding(Base):
    """One place a person's data was found. Nothing is acted on until the person consents to this finding."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    person_id: Mapped[int] = mapped_column(ForeignKey("people.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(120))  # site name
    url: Mapped[str] = mapped_column(EncryptedText)
    data_types: Mapped[str] = mapped_column(String(200))  # csv: phone,email,address
    contact_email: Mapped[str | None] = mapped_column(String(200), nullable=True)  # site's grievance contact
    # found -> removal_requested -> removed | refused | escalated
    status: Mapped[str] = mapped_column(String(20), default="found")
    found_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class RemovalConsent(Base):
    """Explicit, per-finding, revocable permission to contact the site on the person's behalf."""

    __tablename__ = "removal_consents"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), unique=True)
    granted_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class RemovalRequest(Base):
    """A letter to a site. state: pending (queued for the worker) -> sent | failed | cancelled."""

    __tablename__ = "removal_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20), default="initial")  # initial | escalation
    state: Mapped[str] = mapped_column(String(20), default="pending")
    body: Mapped[str] = mapped_column(EncryptedText)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    follow_up_due: Mapped[datetime] = mapped_column(UTCDateTime)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(300), nullable=True)


class OtpChallenge(Base):
    """A one-time code. Holds only keyed hashes: no plaintext identifier or code is stored."""

    __tablename__ = "otp_challenges"

    id: Mapped[int] = mapped_column(primary_key=True)
    channel: Mapped[str] = mapped_column(String(10))  # email | phone
    purpose: Mapped[str] = mapped_column(String(10))  # login | link
    identifier_hash: Mapped[str] = mapped_column(String(64), index=True)
    person_id: Mapped[int | None] = mapped_column(ForeignKey("people.id", ondelete="CASCADE"), nullable=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuditEvent(Base):
    """Append-only record of consent and action events. `detail` must never contain personal data."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime)
    person_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)  # no FK: see erase_person
    action: Mapped[str] = mapped_column(String(40))
    subject_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    subject_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str | None] = mapped_column(String(300), nullable=True)
