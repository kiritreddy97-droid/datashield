from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Finding, Person, RemovalConsent, RemovalRequest

FOLLOW_UP_AFTER = timedelta(days=15)  # configurable per site; see docs/05-legal-compliance.md


class ConsentError(Exception):
    pass


@dataclass
class Hit:
    source: str
    url: str
    data_types: list[str]


class Scanner(Protocol):
    """One implementation per data source (people-search sites, leaked-listing pages, ...)."""

    def scan(self, person: Person) -> list[Hit]: ...


class StaticScanner:
    """Deterministic scanner for tests and demos. Real scanners live in app/scanners/ per source."""

    def __init__(self, hits: list[Hit]):
        self._hits = hits

    def scan(self, person: Person) -> list[Hit]:
        return list(self._hits)


def grant_scan_consent(db: Session, person: Person, now: datetime) -> None:
    person.scan_consent_at, person.scan_consent_revoked_at = now, None
    db.flush()


def revoke_scan_consent(db: Session, person: Person, now: datetime) -> None:
    person.scan_consent_revoked_at = now
    db.flush()


def run_scan(db: Session, person: Person, scanners: list[Scanner]) -> list[Finding]:
    if not person.scan_consent_at or person.scan_consent_revoked_at:
        raise ConsentError("scan consent required")
    known = {f.url for f in db.scalars(select(Finding).where(Finding.person_id == person.id))}
    created = []
    for scanner in scanners:
        for hit in scanner.scan(person):
            if hit.url in known:
                continue
            known.add(hit.url)
            f = Finding(person_id=person.id, source=hit.source, url=hit.url, data_types=",".join(hit.data_types))
            db.add(f)
            created.append(f)
    db.flush()
    return created


def grant_removal_consent(db: Session, finding: Finding, now: datetime) -> RemovalConsent:
    existing = db.scalar(select(RemovalConsent).where(RemovalConsent.finding_id == finding.id))
    if existing:
        existing.granted_at, existing.revoked_at = now, None
        return existing
    c = RemovalConsent(finding_id=finding.id, granted_at=now)
    db.add(c)
    db.flush()
    return c


def revoke_removal_consent(db: Session, finding: Finding, now: datetime) -> None:
    c = db.scalar(select(RemovalConsent).where(RemovalConsent.finding_id == finding.id))
    if c:
        c.revoked_at = now
        db.flush()


def draft_request(person: Person, finding: Finding) -> str:
    return (
        f"To the Grievance Officer / Data Protection contact, {finding.source},\n\n"
        f"I, {person.full_name} ({person.email}), request erasure of my personal data ({finding.data_types}) "
        f"published at {finding.url}, under my right to correction and erasure of personal data "
        f"under the Digital Personal Data Protection Act, 2023. I do not consent to its continued "
        f"processing or display. This request is sent on my behalf with my written authorisation.\n\n"
        f"Please confirm removal in writing.\n"
    )


def request_removal(db: Session, person: Person, finding: Finding, now: datetime) -> RemovalRequest:
    if finding.person_id != person.id:
        raise ConsentError("finding does not belong to this person")
    consent = db.scalar(select(RemovalConsent).where(RemovalConsent.finding_id == finding.id))
    if consent is None or consent.revoked_at is not None:
        raise ConsentError("no active consent for this listing")
    if finding.status != "found":
        raise ConsentError(f"finding is {finding.status}")
    req = RemovalRequest(finding_id=finding.id, body=draft_request(person, finding), sent_at=now,
                         follow_up_due=now + FOLLOW_UP_AFTER)
    finding.status = "removal_requested"
    db.add(req)
    db.flush()
    return req


def mark_result(db: Session, finding: Finding, removed: bool) -> Finding:
    if finding.status not in ("removal_requested", "escalated"):
        raise ConsentError(f"finding is {finding.status}")
    finding.status = "removed" if removed else "refused"
    db.flush()
    return finding


def due_follow_ups(db: Session, now: datetime) -> list[Finding]:
    """Findings whose request is overdue and still unresolved; the worker escalates these."""
    q = (
        select(Finding)
        .join(RemovalRequest, RemovalRequest.finding_id == Finding.id)
        .where(Finding.status == "removal_requested", RemovalRequest.follow_up_due <= now)
    )
    return list(db.scalars(q))


def escalate(db: Session, finding: Finding) -> Finding:
    finding.status = "escalated"
    db.flush()
    return finding
