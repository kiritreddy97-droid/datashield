import logging
from datetime import timedelta

import jwt
import pytest
from sqlalchemy import text

from app import worker
from app.config import get_settings
from app.models import Finding
from app.removal_sender import FakeRemovalSender
from app.security import ALGORITHM


def _scan_and_get_findings(client, h):
    assert client.post("/me/scan-consent", headers=h).status_code == 200
    assert client.post("/me/scan", headers=h).json() == {"new_findings": 2}
    return client.get("/me/findings", headers=h).json()


def test_health_and_openapi(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert "/health" in client.get("/openapi.json").json()["paths"]


# ---------------------------------------------------------------- authentication

PROTECTED = [
    ("get", "/me"), ("patch", "/me"), ("delete", "/me"), ("get", "/me/audit"), ("post", "/me/scan-consent"),
    ("delete", "/me/scan-consent"), ("post", "/me/scan"), ("get", "/me/findings"), ("post", "/me/contacts/otp"),
    ("post", "/me/contacts/verify"), ("post", "/findings/1/consent"), ("delete", "/findings/1/consent"),
    ("post", "/findings/1/remove"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_every_data_route_requires_a_token(client, method, path):
    assert getattr(client, method)(path).status_code == 401
    bad = {"Authorization": "Bearer not-a-token"}
    assert getattr(client, method)(path, headers=bad).status_code == 401


def test_login_creates_account_and_issues_working_token(client, users):
    h = users.login("Asha@Example.com", name=None)
    me = client.get("/me", headers=h).json()
    assert me["email"] == "asha@example.com" and me["email_verified"] and not me["phone_verified"]


def test_second_login_reuses_the_account(client, users):
    first = client.get("/me", headers=users.login("a@x.in")).json()["id"]
    assert client.get("/me", headers=users.login("A@x.in", name=None)).json()["id"] == first


def test_wrong_code_is_rejected_and_locks_out_after_attempts(client, otp):
    client.post("/auth/otp/request", json={"channel": "email", "identifier": "a@x.in"})
    real = otp.last_code("a@x.in")
    wrong = "000000" if real != "000000" else "111111"
    for _ in range(5):
        assert client.post("/auth/otp/verify", json={
            "channel": "email", "identifier": "a@x.in", "code": wrong}).status_code == 400
    r = client.post("/auth/otp/verify", json={"channel": "email", "identifier": "a@x.in", "code": real})
    assert r.status_code == 400 and "access_token" not in r.text


def test_expired_and_reused_codes_fail(client, otp, clock):
    client.post("/auth/otp/request", json={"channel": "email", "identifier": "a@x.in"})
    code = otp.last_code("a@x.in")
    body = {"channel": "email", "identifier": "a@x.in", "code": code}
    clock.advance(minutes=11)
    assert client.post("/auth/otp/verify", json=body).status_code == 400
    clock.advance(minutes=1)
    client.post("/auth/otp/request", json={"channel": "email", "identifier": "a@x.in"})
    body["code"] = otp.last_code("a@x.in")
    assert client.post("/auth/otp/verify", json=body).status_code == 200
    assert client.post("/auth/otp/verify", json=body).status_code == 400


def test_otp_request_does_not_reveal_whether_an_account_exists(client, users):
    users.login("known@x.in")
    a = client.post("/auth/otp/request", json={"channel": "email", "identifier": "known@x.in"})
    b = client.post("/auth/otp/request", json={"channel": "email", "identifier": "new@x.in"})
    assert (a.status_code, a.json()) == (b.status_code, b.json())


def test_invalid_identifiers_and_codes_are_422(client):
    for body in ({"channel": "email", "identifier": "nope"}, {"channel": "phone", "identifier": "12345"},
                 {"channel": "fax", "identifier": "a@x.in"}):
        assert client.post("/auth/otp/request", json=body).status_code == 422
    assert client.post("/auth/otp/verify", json={
        "channel": "email", "identifier": "a@x.in", "code": "12"}).status_code == 422


def test_otp_delivery_failure_is_503_and_leaves_no_usable_code(client, otp):
    otp.fail = True
    assert client.post("/auth/otp/request", json={"channel": "email", "identifier": "a@x.in"}).status_code == 503


def test_expired_token_and_wrong_signature_are_rejected(client, users, clock):
    h = users.login("a@x.in")
    me = client.get("/me", headers=h).json()
    now = clock.now
    expired = jwt.encode({"sub": str(me["id"]), "iat": now - timedelta(hours=3), "exp": now - timedelta(hours=2)},
                         get_settings().jwt_secret, algorithm=ALGORITHM)
    forged = jwt.encode({"sub": str(me["id"]), "iat": now, "exp": now + timedelta(hours=1)}, "x" * 40,
                        algorithm=ALGORITHM)
    unsigned = jwt.encode({"sub": str(me["id"]), "iat": now, "exp": now + timedelta(hours=1)}, None, algorithm="none")
    for t in (expired, forged, unsigned):
        assert client.get("/me", headers={"Authorization": f"Bearer {t}"}).status_code == 401


# ---------------------------------------------------------------- phone / email ownership

def test_phone_must_be_proven_before_it_is_stored_or_used(client, users, otp):
    h = users.login("a@x.in")
    assert client.get("/me", headers=h).json()["phone"] is None
    assert client.post("/me/contacts/otp", json={"channel": "phone", "identifier": "98765 43210"},
                       headers=h).status_code == 202
    assert client.get("/me", headers=h).json()["phone"] is None  # requested but not proven: not on the profile
    wrong = client.post("/me/contacts/verify", json={"channel": "phone", "identifier": "9876543210",
                                                     "code": "000000"}, headers=h)
    assert wrong.status_code == 400
    ok = client.post("/me/contacts/verify", json={
        "channel": "phone", "identifier": "+91 9876543210", "code": otp.last_code("+919876543210")}, headers=h)
    assert ok.status_code == 200
    me = client.get("/me", headers=h).json()
    assert me["phone"] == "+919876543210" and me["phone_verified"]


def test_contact_codes_are_bound_to_the_requesting_account(client, users, otp):
    a, b = users.login("a@x.in"), users.login("b@x.in")
    client.post("/me/contacts/otp", json={"channel": "phone", "identifier": "9876543210"}, headers=a)
    code = otp.last_code("+919876543210")
    stolen = client.post("/me/contacts/verify", json={"channel": "phone", "identifier": "9876543210", "code": code},
                         headers=b)
    assert stolen.status_code == 400 and client.get("/me", headers=b).json()["phone"] is None


def test_cannot_claim_a_contact_that_belongs_to_someone_else(client, users, otp):
    a, b = users.login("a@x.in"), users.login("b@x.in")
    client.post("/me/contacts/otp", json={"channel": "phone", "identifier": "9876543210"}, headers=a)
    client.post("/me/contacts/verify", json={"channel": "phone", "identifier": "9876543210",
                                             "code": otp.last_code("+919876543210")}, headers=a)
    sent_before = len(otp.sent)
    r = client.post("/me/contacts/otp", json={"channel": "phone", "identifier": "9876543210"}, headers=b)
    assert r.status_code == 202 and len(otp.sent) == sent_before  # same answer, nothing sent, nothing leaked


# ---------------------------------------------------------------- consent gates

def test_scan_needs_scan_consent(client, users):
    h = users.login("a@x.in")
    r = client.post("/me/scan", headers=h)
    assert r.status_code == 403 and "consent" in r.json()["detail"]


def test_scan_needs_a_name_and_revoked_consent_blocks_again(client, users):
    h = users.login("a@x.in", name=None)
    client.post("/me/scan-consent", headers=h)
    assert client.post("/me/scan", headers=h).status_code == 403
    client.patch("/me", json={"full_name": "Asha Rao"}, headers=h)
    assert client.post("/me/scan", headers=h).status_code == 200
    client.delete("/me/scan-consent", headers=h)
    assert client.post("/me/scan", headers=h).status_code == 403


def test_removal_needs_consent_for_that_exact_listing(client, users):
    h = users.login("a@x.in")
    a, b = _scan_and_get_findings(client, h)
    assert client.post(f"/findings/{a['id']}/remove", headers=h).status_code == 403
    client.post(f"/findings/{a['id']}/consent", headers=h)
    assert client.post(f"/findings/{a['id']}/remove", headers=h).status_code == 201
    assert client.post(f"/findings/{b['id']}/remove", headers=h).status_code == 403  # B never consented
    assert client.post(f"/findings/{a['id']}/remove", headers=h).status_code == 403  # already requested


def test_withdrawn_removal_consent_blocks_removal(client, users):
    h = users.login("a@x.in")
    a, _ = _scan_and_get_findings(client, h)
    client.post(f"/findings/{a['id']}/consent", headers=h)
    client.delete(f"/findings/{a['id']}/consent", headers=h)
    assert client.post(f"/findings/{a['id']}/remove", headers=h).status_code == 403


# ---------------------------------------------------------------- ownership

def test_users_cannot_see_or_touch_each_others_data(client, users, db):
    a, b = users.login("a@x.in"), users.login("b@x.in", name="Bina Rao")
    fa, _ = _scan_and_get_findings(client, a)
    assert client.get("/me/findings", headers=b).json() == []
    for method, path in (("post", "consent"), ("delete", "consent"), ("post", "remove")):
        assert getattr(client, method)(f"/findings/{fa['id']}" + f"/{path}", headers=b).status_code == 404
    assert client.post("/findings/99999/consent", headers=b).status_code == 404  # same answer as "not yours"
    client.post(f"/findings/{fa['id']}/consent", headers=a)
    assert client.post(f"/findings/{fa['id']}/remove", headers=a).status_code == 201
    assert db.get(Finding, fa["id"]).status == "removal_requested"  # b's attempts changed nothing
    assert all("sitea" not in str(e) for e in client.get("/me/audit", headers=b).json())


def test_other_users_consent_does_not_unlock_my_removal(client, users):
    a, b = users.login("a@x.in"), users.login("b@x.in", name="Bina Rao")
    fa, _ = _scan_and_get_findings(client, a)
    fb, _ = _scan_and_get_findings(client, b)
    client.post(f"/findings/{fb['id']}/consent", headers=b)
    assert client.post(f"/findings/{fa['id']}/remove", headers=a).status_code == 403


# ---------------------------------------------------------------- end to end

def test_full_journey_with_worker_followup_and_audit(client, users, db, clock):
    h = users.login("a@x.in")
    a, _ = _scan_and_get_findings(client, h)
    client.post(f"/findings/{a['id']}/consent", headers=h)
    r = client.post(f"/findings/{a['id']}/remove", headers=h)
    assert r.status_code == 201 and r.json()["state"] == "pending"

    sender = FakeRemovalSender()
    s = worker.run_once(db, sender, clock.now)
    assert (s.sent, s.escalated) == (1, 0)
    assert sender.outbox[0].to == "grievance@sitea.example" and "Asha Rao" in sender.outbox[0].body

    clock.advance(days=16)
    s = worker.run_once(db, sender, clock.now)
    assert (s.escalated, s.sent) == (1, 1)
    assert "Reminder and escalation" in sender.outbox[1].body
    assert client.get("/me/findings", headers=h).json()[0]["status"] == "escalated"
    assert worker.run_once(db, sender, clock.now + timedelta(days=60)).escalated == 0  # escalates once

    actions = [e["action"] for e in client.get("/me/audit", headers=h).json()]
    for expected in ("scan_consent_granted", "scan_run", "removal_consent_granted", "removal_requested",
                     "removal_sent", "removal_escalated", "login"):
        assert expected in actions


def test_delete_my_data_erases_the_account_and_invalidates_the_token(client, users, db):
    a, b = users.login("a@x.in"), users.login("b@x.in", name="Bina Rao")
    fa, _ = _scan_and_get_findings(client, a)
    _scan_and_get_findings(client, b)
    client.post(f"/findings/{fa['id']}/consent", headers=a)
    client.post(f"/findings/{fa['id']}/remove", headers=a)
    r = client.delete("/me", headers=a)
    assert r.status_code == 200 and r.json() == {"erased": True, "findings": 2}
    assert client.get("/me", headers=a).status_code == 401
    assert len(client.get("/me/findings", headers=b).json()) == 2  # the other user is untouched
    left = db.execute(text("select count(*) from findings")).scalar()
    assert left == 2


def test_personal_data_is_encrypted_at_rest(client, users, db):
    h = users.login("secret.person@example.com", name="Asha Rao")
    client.post("/me/contacts/otp", json={"channel": "phone", "identifier": "9876543210"}, headers=h)
    client.post("/me/scan-consent", headers=h)
    client.post("/me/scan", headers=h)
    f = client.get("/me/findings", headers=h).json()[0]
    client.post(f"/findings/{f['id']}/consent", headers=h)
    client.post(f"/findings/{f['id']}/remove", headers=h)
    dump = " ".join(str(v) for t in ("people", "findings", "removal_requests", "otp_challenges", "audit_events")
                    for row in db.execute(text(f"select * from {t}")) for v in row)
    for plaintext in ("secret.person", "Asha", "9876543210", "sitea.example/p/1"):
        assert plaintext not in dump


# ---------------------------------------------------------------- rate limiting and logging

def test_otp_requests_are_rate_limited_per_client(client):
    codes = [client.post("/auth/otp/request", json={"channel": "email", "identifier": f"u{i}@x.in"}).status_code
             for i in range(12)]
    assert codes[:10] == [202] * 10 and codes[10:] == [429, 429]
    r = client.post("/auth/otp/request", json={"channel": "email", "identifier": "u99@x.in"})
    assert "retry-after" in r.headers


def test_per_identifier_code_limit(client):
    codes = [client.post("/auth/otp/request", json={"channel": "email", "identifier": "a@x.in"}).status_code
             for _ in range(5)]
    assert codes == [202, 202, 202, 429, 429]


def test_global_rate_limit_applies_but_not_to_health(client, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "get_settings", lambda: type("S", (), {"rate_limit_per_minute": 3})())
    assert [client.get("/openapi.json").status_code for _ in range(4)] == [200, 200, 200, 429]
    assert client.get("/health").status_code == 200


def test_request_logs_are_structured_and_free_of_personal_data(client, users, caplog):
    with caplog.at_level(logging.INFO, logger="datashield.api"):
        h = users.login("leaky@example.com")
        client.get("/me?secret=1", headers=h)
    recs = [r for r in caplog.records if r.getMessage() == "request"]
    assert recs and all(hasattr(r, "route") and hasattr(r, "status") and hasattr(r, "request_id") for r in recs)
    text_ = " ".join(str(r.__dict__) for r in caplog.records if r.name.startswith("datashield"))
    assert "leaky@example.com" not in text_ and "secret=1" not in text_ and h["Authorization"] not in text_
    assert any(r.route == "/me" for r in recs)


def test_unhandled_errors_return_500_without_details(client, users, monkeypatch):
    from app import main
    h = users.login("a@x.in")
    monkeypatch.setattr(main.services, "audit_trail", lambda *a: 1 / 0)
    r = client.get("/me/audit", headers=h)
    assert r.status_code == 500 and r.json() == {"detail": "internal error"} and "x-request-id" in r.headers
