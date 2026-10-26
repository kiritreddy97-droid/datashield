from datetime import timedelta

import pytest
from conftest import HITS, make_person

from app import services
from app.clock import utcnow
from app.models import AuditEvent, Finding, Person, RemovalRequest

NOW = utcnow()


def _scanned(db, person=None):
    p = person or make_person(db)
    services.grant_scan_consent(db, p, NOW)
    return p, *services.run_scan(db, p, [services.StaticScanner(HITS)], NOW)


def test_scan_requires_consent(db):
    with pytest.raises(services.ConsentError, match="scan consent"):
        services.run_scan(db, make_person(db), [services.StaticScanner(HITS)], NOW)


def test_scan_requires_verified_contact(db):
    p = make_person(db, verified=False)
    services.grant_scan_consent(db, p, NOW)
    with pytest.raises(services.VerificationError):
        services.run_scan(db, p, [services.StaticScanner(HITS)], NOW)


def test_scan_requires_every_identifier_verified(db):
    p = make_person(db)
    p.phone_verified_at = None  # a phone is on the profile but unproven
    services.grant_scan_consent(db, p, NOW)
    with pytest.raises(services.VerificationError, match="every identifier"):
        services.run_scan(db, p, [services.StaticScanner(HITS)], NOW)


def test_scan_requires_name(db):
    p = make_person(db, name=None)
    services.grant_scan_consent(db, p, NOW)
    with pytest.raises(services.VerificationError, match="full name"):
        services.run_scan(db, p, [services.StaticScanner(HITS)], NOW)


def test_scan_dedupes_repeat_runs(db):
    p, *_ = _scanned(db)
    assert services.run_scan(db, p, [services.StaticScanner(HITS)], NOW) == []
    assert db.query(Finding).count() == 2


def test_revoked_scan_consent_blocks_scan(db):
    p = make_person(db)
    services.grant_scan_consent(db, p, NOW)
    services.revoke_scan_consent(db, p, NOW)
    with pytest.raises(services.ConsentError):
        services.run_scan(db, p, [services.StaticScanner(HITS)], NOW)


def test_only_selected_listings_are_removed(db):
    p, a, b = _scanned(db)
    services.grant_removal_consent(db, a, NOW)
    req = services.request_removal(db, p, a, NOW)
    assert a.status == "removal_requested" and req.state == "pending"
    assert "Digital Personal Data Protection Act" in req.body
    with pytest.raises(services.ConsentError, match="no active consent"):
        services.request_removal(db, p, b, NOW)
    assert b.status == "found"


def test_unverified_person_cannot_request_removal(db):
    p, a, _ = _scanned(db)
    services.grant_removal_consent(db, a, NOW)
    p.email_verified_at = None
    with pytest.raises(services.VerificationError):
        services.request_removal(db, p, a, NOW)


def test_revoked_consent_blocks_removal(db):
    p, a, _ = _scanned(db)
    services.grant_removal_consent(db, a, NOW)
    services.revoke_removal_consent(db, a, NOW)
    with pytest.raises(services.ConsentError):
        services.request_removal(db, p, a, NOW)


def test_revoking_before_send_cancels_the_queued_letter(db):
    p, a, _ = _scanned(db)
    services.grant_removal_consent(db, a, NOW)
    req = services.request_removal(db, p, a, NOW)
    services.revoke_removal_consent(db, a, NOW)
    assert req.state == "cancelled" and a.status == "found"


def test_follow_up_requires_sent_letter_and_active_consent(db):
    p, a, _ = _scanned(db)
    services.grant_removal_consent(db, a, NOW)
    req = services.request_removal(db, p, a, NOW)
    assert services.due_follow_ups(db, NOW + services.FOLLOW_UP_AFTER * 2) == []  # never sent: nothing to chase
    services.mark_sent(db, req, a, NOW)
    assert services.due_follow_ups(db, NOW + timedelta(days=1)) == []
    assert services.due_follow_ups(db, NOW + services.FOLLOW_UP_AFTER) == [a]
    services.revoke_removal_consent(db, a, NOW)
    assert services.due_follow_ups(db, NOW + services.FOLLOW_UP_AFTER) == []


def test_escalation_queues_a_letter_and_result_can_be_marked(db):
    p, a, _ = _scanned(db)
    services.grant_removal_consent(db, a, NOW)
    services.mark_sent(db, services.request_removal(db, p, a, NOW), a, NOW)
    esc = services.escalate(db, a, NOW)
    assert a.status == "escalated" and esc.kind == "escalation" and esc.state == "pending"
    services.mark_result(db, a, removed=True, now=NOW)
    assert a.status == "removed"


def test_cannot_act_on_someone_elses_finding(db):
    p, a, _ = _scanned(db)
    other = make_person(db, email="o@x.in", phone=None, name="Other")
    services.grant_removal_consent(db, a, NOW)
    with pytest.raises(services.ConsentError, match="does not belong"):
        services.request_removal(db, other, a, NOW)


def test_audit_trail_records_consents_scans_and_requests_without_pii(db):
    p, a, _ = _scanned(db)
    services.grant_removal_consent(db, a, NOW)
    services.request_removal(db, p, a, NOW)
    services.revoke_removal_consent(db, a, NOW)
    services.revoke_scan_consent(db, p, NOW)
    actions = [e.action for e in services.audit_trail(db, p)]
    assert actions == ["scan_consent_granted", "scan_run", "removal_consent_granted", "removal_requested",
                       "removal_consent_revoked", "scan_consent_revoked"]
    blob = " ".join(str(e.detail) for e in db.query(AuditEvent))
    assert "m@x.in" not in blob and "Meera" not in blob and "sitea" not in blob


def test_otp_roundtrip_attempt_limit_and_single_use(db):
    code = services.issue_otp(db, NOW, "email", "a@x.in", "login")
    assert services.check_otp(db, NOW, "email", "a@x.in", "000000" if code != "000000" else "111111", "login") is False
    assert services.check_otp(db, NOW, "email", "a@x.in", code, "login") is True
    assert services.check_otp(db, NOW, "email", "a@x.in", code, "login") is False  # consumed


def test_otp_expires_and_locks_after_too_many_guesses(db):
    code = services.issue_otp(db, NOW, "email", "a@x.in", "login")
    assert services.check_otp(db, NOW + timedelta(minutes=11), "email", "a@x.in", code, "login") is False
    code = services.issue_otp(db, NOW, "email", "b@x.in", "login")
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        services.check_otp(db, NOW, "email", "b@x.in", wrong, "login")
    assert services.check_otp(db, NOW, "email", "b@x.in", code, "login") is False  # locked even with the right code


def test_otp_purpose_and_owner_are_bound(db):
    p = make_person(db)
    code = services.issue_otp(db, NOW, "phone", "+919111111111", "link", p.id)
    assert services.check_otp(db, NOW, "phone", "+919111111111", code, "login") is False
    assert services.check_otp(db, NOW, "phone", "+919111111111", code, "link", p.id + 1) is False
    assert services.check_otp(db, NOW, "phone", "+919111111111", code, "link", p.id) is True


def test_otp_issue_is_rate_limited_per_identifier(db):
    for _ in range(3):
        services.issue_otp(db, NOW, "email", "a@x.in", "login")
    with pytest.raises(services.OtpRateLimited):
        services.issue_otp(db, NOW, "email", "a@x.in", "login")
    services.issue_otp(db, NOW + timedelta(minutes=11), "email", "a@x.in", "login")


def test_erase_person_removes_everything_but_leaves_an_anonymous_audit_row(db):
    p, a, _ = _scanned(db)
    services.grant_removal_consent(db, a, NOW)
    services.request_removal(db, p, a, NOW)
    services.issue_otp(db, NOW, "email", "m@x.in", "login")
    other = make_person(db, email="o@x.in", phone=None, name="Other")
    services.erase_person(db, p, NOW)
    db.commit()
    assert db.query(Person).all() == [other]
    assert db.query(Finding).count() == 0 and db.query(RemovalRequest).count() == 0
    rows = db.query(AuditEvent).all()
    assert [(r.action, r.person_id) for r in rows] == [("account_erased", None)]
