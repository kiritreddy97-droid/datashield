from datetime import timedelta

import pytest
from conftest import HITS, make_person

from app import services, worker
from app.clock import utcnow
from app.models import RemovalRequest
from app.removal_sender import FakeRemovalSender

NOW = utcnow()


def _queued(db, which=0):
    p = make_person(db)
    services.grant_scan_consent(db, p, NOW)
    finding = services.run_scan(db, p, [services.StaticScanner(HITS)], NOW)[which]
    services.grant_removal_consent(db, finding, NOW)
    return p, finding, services.request_removal(db, p, finding, NOW)


def test_sends_queued_letter_once_and_starts_followup_clock(db):
    _, f, req = _queued(db)
    sender = FakeRemovalSender()
    later = NOW + timedelta(hours=2)
    assert worker.run_once(db, sender, later).sent == 1
    assert worker.run_once(db, sender, later).sent == 0  # idempotent
    assert len(sender.outbox) == 1 and sender.outbox[0].reference == f"DS-{req.id}"
    assert req.state == "sent" and req.follow_up_due == later + services.FOLLOW_UP_AFTER


def test_consent_withdrawn_after_queueing_is_honoured_at_send_time(db):
    _, f, req = _queued(db)
    from app.models import RemovalConsent
    db.query(RemovalConsent).filter_by(finding_id=f.id).one().revoked_at = NOW  # bypass the service on purpose
    sender = FakeRemovalSender()
    s = worker.run_once(db, sender, NOW)
    assert (s.cancelled, s.sent) == (1, 0) and sender.outbox == [] and req.state == "cancelled"


def test_listing_without_known_contact_waits_for_manual_handling(db):
    _, f, req = _queued(db, which=1)
    sender = FakeRemovalSender()
    assert worker.run_once(db, sender, NOW).needs_manual == 1
    assert sender.outbox == [] and req.state == "pending" and "manually" in req.last_error


def test_failures_are_retried_then_marked_failed(db):
    p, f, req = _queued(db)
    sender = FakeRemovalSender()
    sender.fail_for.add("grievance@sitea.example")
    for _ in range(services.MAX_SEND_ATTEMPTS):
        assert worker.run_once(db, sender, NOW).failed == 1
    assert req.state == "failed" and f.status == "removal_requested"
    assert worker.run_once(db, sender, NOW).failed == 0  # no more retries
    assert [e.action for e in services.audit_trail(db, p)][-1] == "removal_send_failed"


def test_overdue_findings_are_escalated_once_and_the_reminder_is_sent(db):
    _, f, _ = _queued(db)
    sender = FakeRemovalSender()
    worker.run_once(db, sender, NOW)
    due = NOW + services.FOLLOW_UP_AFTER
    assert worker.run_once(db, sender, due - timedelta(minutes=1)).escalated == 0
    s = worker.run_once(db, sender, due)
    assert (s.escalated, s.sent) == (1, 1) and f.status == "escalated"
    assert worker.run_once(db, sender, due + timedelta(days=30)).escalated == 0
    kinds = [r.kind for r in db.query(RemovalRequest).order_by(RemovalRequest.id)]
    assert kinds == ["initial", "escalation"]


def test_no_followup_after_consent_is_withdrawn(db):
    _, f, _ = _queued(db)
    sender = FakeRemovalSender()
    worker.run_once(db, sender, NOW)
    services.revoke_removal_consent(db, f, NOW)
    assert worker.run_once(db, sender, NOW + timedelta(days=60)).escalated == 0
    assert f.status == "removal_requested" and len(sender.outbox) == 1


@pytest.mark.parametrize("env", [{}, {"SMTP_HOST": "smtp.example.invalid"}])
def test_smtp_sender_requires_configuration(monkeypatch, env):
    from app.config import get_settings
    from app.removal_sender import SendError, build_removal_sender
    for k in ("SMTP_HOST", "SMTP_FROM", "REMOVAL_SENDER"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    try:
        with pytest.raises(SendError):
            build_removal_sender()
    finally:
        get_settings.cache_clear()
