from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class Person(Base):
    """The data principal. Search identifiers are stored hashed-at-rest in production (see docs/05)."""

    __tablename__ = "people"

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(160))
    email: Mapped[str] = mapped_column(String(200), unique=True)
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    scan_consent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    scan_consent_revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Finding(Base):
    """One place a person's data was found. Nothing is acted on until the person consents to this finding."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    person_id: Mapped[int] = mapped_column(ForeignKey("people.id"), index=True)
    source: Mapped[str] = mapped_column(String(120))  # site name
    url: Mapped[str] = mapped_column(String(500))
    data_types: Mapped[str] = mapped_column(String(200))  # csv: phone,email,address
    # found -> removal_requested -> removed | refused | escalated
    status: Mapped[str] = mapped_column(String(20), default="found")
    found_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RemovalConsent(Base):
    """Explicit, per-finding, revocable permission to contact the site on the person's behalf."""

    __tablename__ = "removal_consents"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), unique=True)
    granted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RemovalRequest(Base):
    __tablename__ = "removal_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    body: Mapped[str] = mapped_column(String(4000))
    sent_at: Mapped[datetime] = mapped_column(DateTime)
    follow_up_due: Mapped[datetime] = mapped_column(DateTime)
