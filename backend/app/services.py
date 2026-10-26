import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Protocol

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from .config import get_settings
from .crypto import blind_index
from .models import AuditEvent, Finding, OtpChallenge, Person, RemovalConsent, RemovalRequest

FOLLOW_UP_AFTER = timedelta(days=15)  # configurable per site; see docs/05-legal-compliance.md
MAX_SEND_ATTEMPTS = 5
OTP_WINDOW = timedelta(minutes=10)


class ConsentError(Exception):
    """A consent rule blocks the action (HTTP 403)."""


class VerificationError(Exception):
    """The person has not proven control of their identifiers (HTTP 403)."""


class OtpError(Exception):
    """Wrong, expired, used or exhausted code. Deliberately one message for all cases (HTTP 400)."""


class OtpRateLimited(Exception):
    """Too many codes requested for one identifier (HTTP 429)."""


class ContactConflict(Exception):
    """The contact already belongs to another account (HTTP 409)."""


@dataclass
class Hit:
    source: str
    url: str
    data_types: list[str] = field(default_factory=list)
    contact_email: str | None = None  # the site's grievance/data-protection address, if known


class Scanner(Protocol):
    """One implementation per data source. Every real source needs legal review first (docs/05)."""

    def scan(self, person: Person) -> list[Hit]: ...


class StaticScanner:
    """Deterministic scanner for tests and demos."""

    def __init__(self, hits: list[Hit]):
        self._hits = hits

    def scan(self, person: Person) -> list[Hit]:
        return list(self._hits)


# ---------------------------------------------------------------- audit log

def audit(db: Session, now: datetime, person_id: int | None, action: str, subject_type: str | None = None,
          subject_id: int | None = None, detail: str | None = None) -> None:
    """Append an event. Never put names, emails, phones or URLs in `detail`."""
    db.add(AuditEvent(at=now, person_id=person_id, action=action, subject_type=subject_type,
                      subject_id=subject_id, detail=detail))


def audit_trail(db: Session, person: Person) -> list[AuditEvent]:
    q = select(AuditEvent).where(AuditEvent.person_id == person.id).order_by(AuditEvent.id)
    return list(db.scalars(q))


# ---------------------------------------------------------------- verification (OTP)

def _code_hash(challenge_id: int, code: str) -> str:
    key = get_settings().jwt_secret.encode()
    return hmac.new(key, f"otp:{challenge_id}:{code}".encode(), sha256).hexdigest()


def issue_otp(db: Session, now: datetime, channel: str, identifier: str, purpose: str,
              person_id: int | None = None) -> str:
    """Create a challenge and return the plaintext code for the sender. `identifier` must be normalised."""
    h = blind_index(channel, identifier)
    recent = db.scalar(select(func.count()).select_from(OtpChallenge).where(
        OtpChallenge.identifier_hash == h, OtpChallenge.created_at > now - OTP_WINDOW))
    if recent >= get_settings().otp_max_per_window:
        raise OtpRateLimited("too many codes requested; try again later")
    code = f"{secrets.randbelow(10**6):06d}"
    ch = OtpChallenge(channel=channel, purpose=purpose, identifier_hash=h, person_id=person_id, code_hash="",
                      created_at=now, expires_at=now + timedelta(minutes=get_settings().otp_ttl_minutes))
    db.add(ch)
    db.flush()
    ch.code_hash = _code_hash(ch.id, code)
    db.flush()
    return code


def check_otp(db: Session, now: datetime, channel: str, identifier: str, code: str, purpose: str,
              person_id: int | None = None) -> bool:
    """Consume the newest open challenge on a correct code. Counts every wrong guess; the caller must commit."""
    h = blind_index(channel, identifier)
    ch = db.scalar(
        select(OtpChallenge)
        .where(OtpChallenge.identifier_hash == h, OtpChallenge.purpose == purpose,
               OtpChallenge.person_id.is_(None) if person_id is None else OtpChallenge.person_id == person_id,
               OtpChallenge.consumed_at.is_(None), OtpChallenge.expires_at > now,
               OtpChallenge.attempts < get_settings().otp_max_attempts)
        .order_by(OtpChallenge.id.desc()).limit(1))
    if ch is None:
        return False
    ch.attempts += 1
    if not hmac.compare_digest(ch.code_hash, _code_hash(ch.id, code)):
        db.flush()
        return False
    db.execute(update(OtpChallenge).where(
        OtpChallenge.identifier_hash == h, OtpChallenge.consumed_at.is_(None)).values(consumed_at=now))
    db.flush()
    return True


def set_contact(person: Person, channel: str, identifier: str, now: datetime) -> None:
    h = blind_index(channel, identifier)
    if channel == "email":
        person.email, person.email_hash, person.email_verified_at = identifier, h, now
    else:
        person.phone, person.phone_hash, person.phone_verified_at = identifier, h, now


def owner_of(db: Session, channel: str, identifier: str) -> Person | None:
    col = Person.email_hash if channel == "email" else Person.phone_hash
    return db.scalar(select(Person).where(col == blind_index(channel, identifier)))


def login_with_contact(db: Session, now: datetime, channel: str, identifier: str) -> Person:
    """Call only after check_otp succeeded. Creates the account on first successful proof."""
    person = owner_of(db, channel, identifier)
    if person is None:
        person = Person(created_at=now)
        set_contact(person, channel, identifier, now)
        db.add(person)
        db.flush()
        audit(db, now, person.id, "account_created", "person", person.id, f"via {channel}")
    else:
        set_contact(person, channel, identifier, now)
    audit(db, now, person.id, "login", "person", person.id, f"via {channel}")
    return person


def link_contact(db: Session, now: datetime, person: Person, channel: str, identifier: str) -> Person:
    """Call only after check_otp succeeded for this person: attach a newly proven email or phone."""
    owner = owner_of(db, channel, identifier)
    if owner is not None and owner.id != person.id:
        raise ContactConflict("contact belongs to another account")
    set_contact(person, channel, identifier, now)
    audit(db, now, person.id, "contact_verified", "person", person.id, channel)
    db.flush()
    return person


def require_verified(person: Person, need_name: bool = True) -> None:
    """Scans and removals run only on identifiers whose ownership was proven by OTP."""
    if not (person.email_verified_at or person.phone_verified_at):
        raise VerificationError("verify your email or phone first")
    if (person.email and not person.email_verified_at) or (person.phone and not person.phone_verified_at):
        raise VerificationError("every identifier on the profile must be verified")
    if need_name and not person.full_name:
        raise VerificationError("add your full name to your profile first")


# ---------------------------------------------------------------- consent and scanning

def grant_scan_consent(db: Session, person: Person, now: datetime) -> None:
    person.scan_consent_at, person.scan_consent_revoked_at = now, None
    audit(db, now, person.id, "scan_consent_granted", "person", person.id)
    db.flush()


def revoke_scan_consent(db: Session, person: Person, now: datetime) -> None:
    person.scan_consent_revoked_at = now
    audit(db, now, person.id, "scan_consent_revoked", "person", person.id)
    db.flush()


def run_scan(db: Session, person: Person, scanners: list[Scanner], now: datetime) -> list[Finding]:
    if not person.scan_consent_at or person.scan_consent_revoked_at:
        raise ConsentError("scan consent required")
    require_verified(person)
    known = {f.url for f in db.scalars(select(Finding).where(Finding.person_id == person.id))}
    created = []
    for scanner in scanners:
        for hit in scanner.scan(person):
            if hit.url in known:
                continue
            known.add(hit.url)
            f = Finding(person_id=person.id, source=hit.source, url=hit.url, data_types=",".join(hit.data_types),
                        contact_email=hit.contact_email, found_at=now)
            db.add(f)
            created.append(f)
    db.flush()
    audit(db, now, person.id, "scan_run", "person", person.id, f"scanners={len(scanners)} new={len(created)}")
    return created


def grant_removal_consent(db: Session, finding: Finding, now: datetime) -> RemovalConsent:
    existing = db.scalar(select(RemovalConsent).where(RemovalConsent.finding_id == finding.id))
    if existing:
        existing.granted_at, existing.revoked_at = now, None
        c = existing
    else:
        c = RemovalConsent(finding_id=finding.id, granted_at=now)
        db.add(c)
    audit(db, now, finding.person_id, "removal_consent_granted", "finding", finding.id)
    db.flush()
    return c


def revoke_removal_consent(db: Session, finding: Finding, now: datetime) -> None:
    """Revoking stops everything not yet sent and all future follow-ups for this finding."""
    c = db.scalar(select(RemovalConsent).where(RemovalConsent.finding_id == finding.id))
    if c is None:
        return
    c.revoked_at = now
    db.execute(update(RemovalRequest).where(
        RemovalRequest.finding_id == finding.id, RemovalRequest.state == "pending").values(state="cancelled"))
    sent = db.scalar(select(func.count()).select_from(RemovalRequest).where(
        RemovalRequest.finding_id == finding.id, RemovalRequest.state == "sent"))
    if finding.status == "removal_requested" and not sent:
        finding.status = "found"
    audit(db, now, finding.person_id, "removal_consent_revoked", "finding", finding.id)
    db.flush()


# ---------------------------------------------------------------- removal requests

def draft_request(person: Person, finding: Finding) -> str:
    return (
        f"To the Grievance Officer / Data Protection contact, {finding.source},\n\n"
        f"I, {person.full_name} ({person.email or person.phone}), request erasure of my personal data "
        f"({finding.data_types}) published at {finding.url}, under my right to correction and erasure of "
        f"personal data under the Digital Personal Data Protection Act, 2023. I do not consent to its continued "
        f"processing or display. This request is sent on my behalf with my written authorisation.\n\n"
        f"Please confirm removal in writing.\n"
    )


def draft_escalation(person: Person, finding: Finding, first_sent_at: datetime | None) -> str:
    when = first_sent_at.date().isoformat() if first_sent_at else "earlier"
    return (
        f"To the Grievance Officer / Data Protection contact, {finding.source},\n\n"
        f"Reminder and escalation. On {when} I asked for erasure of my personal data ({finding.data_types}) "
        f"published at {finding.url}, under the Digital Personal Data Protection Act, 2023. I have not "
        f"received confirmation that it was removed. Please remove it and confirm in writing. If this is not "
        f"resolved I may take the grievance further under the Act.\n\n"
        f"- {person.full_name}, via DataShield (authorised representative)\n"
    )


def request_removal(db: Session, person: Person, finding: Finding, now: datetime) -> RemovalRequest:
    if finding.person_id != person.id:
        raise ConsentError("finding does not belong to this person")
    require_verified(person)
    consent = db.scalar(select(RemovalConsent).where(RemovalConsent.finding_id == finding.id))
    if consent is None or consent.revoked_at is not None:
        raise ConsentError("no active consent for this listing")
    if finding.status != "found":
        raise ConsentError(f"finding is {finding.status}")
    req = RemovalRequest(finding_id=finding.id, kind="initial", state="pending", body=draft_request(person, finding),
                         created_at=now, follow_up_due=now + FOLLOW_UP_AFTER)
    finding.status = "removal_requested"
    db.add(req)
    audit(db, now, person.id, "removal_requested", "finding", finding.id)
    db.flush()
    return req


def active_consent(db: Session, finding: Finding) -> bool:
    c = db.scalar(select(RemovalConsent).where(RemovalConsent.finding_id == finding.id))
    return c is not None and c.revoked_at is None


def pending_requests(db: Session) -> list[RemovalRequest]:
    q = select(RemovalRequest).where(RemovalRequest.state == "pending", RemovalRequest.attempts < MAX_SEND_ATTEMPTS)
    return list(db.scalars(q.order_by(RemovalRequest.id)))


def mark_sent(db: Session, req: RemovalRequest, finding: Finding, now: datetime) -> None:
    req.state, req.sent_at, req.last_error = "sent", now, None
    req.attempts += 1
    req.follow_up_due = now + FOLLOW_UP_AFTER  # the clock starts when the letter actually left
    audit(db, now, finding.person_id, "removal_sent", "finding", finding.id, req.kind)
    db.flush()


def mark_send_failed(db: Session, req: RemovalRequest, finding: Finding, error: str, now: datetime) -> None:
    req.attempts += 1
    req.last_error = error[:300]
    if req.attempts >= MAX_SEND_ATTEMPTS:
        req.state = "failed"
        audit(db, now, finding.person_id, "removal_send_failed", "finding", finding.id, req.kind)
    db.flush()


def cancel_request(db: Session, req: RemovalRequest, reason: str) -> None:
    req.state, req.last_error = "cancelled", reason
    db.flush()


def mark_result(db: Session, finding: Finding, removed: bool, now: datetime) -> Finding:
    if finding.status not in ("removal_requested", "escalated"):
        raise ConsentError(f"finding is {finding.status}")
    finding.status = "removed" if removed else "refused"
    audit(db, now, finding.person_id, "result_marked", "finding", finding.id, finding.status)
    db.flush()
    return finding


def due_follow_ups(db: Session, now: datetime) -> list[Finding]:
    """Findings whose sent request is overdue, still unresolved and still consented; the worker escalates these."""
    q = (
        select(Finding)
        .join(RemovalRequest, RemovalRequest.finding_id == Finding.id)
        .join(RemovalConsent, RemovalConsent.finding_id == Finding.id)
        .where(Finding.status == "removal_requested", RemovalConsent.revoked_at.is_(None),
               RemovalRequest.kind == "initial", RemovalRequest.state == "sent", RemovalRequest.follow_up_due <= now)
    )
    return list(db.scalars(q))


def escalate(db: Session, finding: Finding, now: datetime) -> RemovalRequest:
    """Mark escalated and queue the reminder letter for the worker to send."""
    person = db.get(Person, finding.person_id)
    first = db.scalar(select(RemovalRequest).where(
        RemovalRequest.finding_id == finding.id, RemovalRequest.kind == "initial").order_by(RemovalRequest.id))
    finding.status = "escalated"
    req = RemovalRequest(finding_id=finding.id, kind="escalation", state="pending", created_at=now,
                         body=draft_escalation(person, finding, first.sent_at if first else None),
                         follow_up_due=now + FOLLOW_UP_AFTER)
    db.add(req)
    audit(db, now, finding.person_id, "removal_escalated", "finding", finding.id)
    db.flush()
    return req


# ---------------------------------------------------------------- erasure

def erase_person(db: Session, person: Person, now: datetime) -> dict[str, int]:
    """Delete everything we hold about this person. Leaves one anonymous audit row (no person id, no PII)."""
    pid = person.id
    finding_ids = list(db.scalars(select(Finding.id).where(Finding.person_id == pid)))
    counts = {"findings": len(finding_ids)}
    if finding_ids:
        db.execute(delete(RemovalRequest).where(RemovalRequest.finding_id.in_(finding_ids)))
        db.execute(delete(RemovalConsent).where(RemovalConsent.finding_id.in_(finding_ids)))
        db.execute(delete(Finding).where(Finding.id.in_(finding_ids)))
    hashes = [h for h in (person.email_hash, person.phone_hash) if h]
    db.execute(delete(OtpChallenge).where(
        (OtpChallenge.person_id == pid) | (OtpChallenge.identifier_hash.in_(hashes))))
    db.execute(delete(AuditEvent).where(AuditEvent.person_id == pid))
    db.expunge(person)
    db.execute(delete(Person).where(Person.id == pid))
    audit(db, now, None, "account_erased", None, None, f"findings={counts['findings']}")
    db.flush()
    return counts
