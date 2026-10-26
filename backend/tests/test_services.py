from datetime import datetime, timedelta

import pytest

from app import services
from app.models import Person

NOW = datetime(2026, 11, 1, 10, 0)
HITS = [
    services.Hit("SiteA", "https://sitea.example/p/1", ["phone", "email"]),
    services.Hit("SiteB", "https://siteb.example/u/9", ["phone"]),
]


def _person(db):
    p = Person(full_name="Meera Iyer", email="m@x.in", phone="9000000000")
    db.add(p)
    db.flush()
    return p


def test_scan_requires_consent(db):
    with pytest.raises(services.ConsentError, match="scan consent"):
        services.run_scan(db, _person(db), [services.StaticScanner(HITS)])


def test_scan_dedupes_repeat_runs(db):
    p = _person(db)
    services.grant_scan_consent(db, p, NOW)
    assert len(services.run_scan(db, p, [services.StaticScanner(HITS)])) == 2
    assert services.run_scan(db, p, [services.StaticScanner(HITS)]) == []


def test_revoked_scan_consent_blocks_scan(db):
    p = _person(db)
    services.grant_scan_consent(db, p, NOW)
    services.revoke_scan_consent(db, p, NOW)
    with pytest.raises(services.ConsentError):
        services.run_scan(db, p, [services.StaticScanner(HITS)])


def test_only_selected_listings_are_removed(db):
    p = _person(db)
    services.grant_scan_consent(db, p, NOW)
    a, b = services.run_scan(db, p, [services.StaticScanner(HITS)])
    services.grant_removal_consent(db, a, NOW)
    req = services.request_removal(db, p, a, NOW)
    assert a.status == "removal_requested" and "Digital Personal Data Protection Act" in req.body
    with pytest.raises(services.ConsentError, match="no active consent"):
        services.request_removal(db, p, b, NOW)
    assert b.status == "found"


def test_revoked_consent_blocks_removal(db):
    p = _person(db)
    services.grant_scan_consent(db, p, NOW)
    a, _ = services.run_scan(db, p, [services.StaticScanner(HITS)])
    services.grant_removal_consent(db, a, NOW)
    services.revoke_removal_consent(db, a, NOW)
    with pytest.raises(services.ConsentError):
        services.request_removal(db, p, a, NOW)


def test_follow_up_and_resolution(db):
    p = _person(db)
    services.grant_scan_consent(db, p, NOW)
    a, _ = services.run_scan(db, p, [services.StaticScanner(HITS)])
    services.grant_removal_consent(db, a, NOW)
    services.request_removal(db, p, a, NOW)
    assert services.due_follow_ups(db, NOW + timedelta(days=1)) == []
    assert services.due_follow_ups(db, NOW + services.FOLLOW_UP_AFTER) == [a]
    services.escalate(db, a)
    services.mark_result(db, a, removed=True)
    assert a.status == "removed"


def test_cannot_act_on_someone_elses_finding(db):
    p = _person(db)
    other = Person(full_name="Other", email="o@x.in")
    db.add(other)
    db.flush()
    services.grant_scan_consent(db, p, NOW)
    a, _ = services.run_scan(db, p, [services.StaticScanner(HITS)])
    services.grant_removal_consent(db, a, NOW)
    with pytest.raises(services.ConsentError, match="does not belong"):
        services.request_removal(db, other, a, NOW)
