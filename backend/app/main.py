import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from functools import lru_cache
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StringConstraints, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import services
from .config import get_settings
from .crypto import normalize_email, normalize_phone
from .db import get_db
from .logging_config import configure_logging
from .models import Finding, Person
from .otp import OtpDeliveryError, OtpSender, build_otp_sender
from .ratelimit import client_ip, limit, limiter
from .scanners import build_scanners
from .security import create_access_token, current_person, get_now

log = logging.getLogger("datashield.api")


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging()
    get_settings().validate()
    yield


app = FastAPI(title="DataShield India", lifespan=lifespan)


@app.middleware("http")
async def request_log(request: Request, call_next):
    """Request id, global per-IP rate limit and one structured log line per request (no query string or body)."""
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
    start = time.perf_counter()
    response = None
    try:
        if request.url.path != "/health":
            try:
                limiter.check("global", client_ip(request), get_settings().rate_limit_per_minute, 60)
            except HTTPException as e:
                response = JSONResponse({"detail": e.detail}, status_code=e.status_code, headers=e.headers)
        if response is None:
            response = await call_next(request)
    except Exception:
        log.exception("unhandled error", extra={"request_id": request_id, "method": request.method})
        response = JSONResponse({"detail": "internal error"}, status_code=500)
    route = request.scope.get("route")
    log.info("request", extra={
        "request_id": request_id, "method": request.method, "route": getattr(route, "path", "unmatched"),
        "status": response.status_code, "ms": round((time.perf_counter() - start) * 1000, 1),
        "person_id": getattr(request.state, "person_id", None)})
    response.headers["x-request-id"] = request_id
    return response


@app.exception_handler(services.ConsentError)
@app.exception_handler(services.VerificationError)
async def _forbidden(_: Request, exc: Exception):
    return JSONResponse({"detail": str(exc)}, status_code=403)


@lru_cache
def get_otp_sender() -> OtpSender:
    return build_otp_sender()


@lru_cache
def get_scanners() -> list[services.Scanner]:
    """Real scanners are registered in app/scanners/ and enabled only after legal review (docs/05)."""
    return build_scanners()


# ---------------------------------------------------------------- schemas

class ContactIn(BaseModel):
    channel: Literal["email", "phone"]
    identifier: str = Field(max_length=200)

    @model_validator(mode="after")
    def _normalise(self):
        try:
            self.identifier = (normalize_email if self.channel == "email" else normalize_phone)(self.identifier)
        except ValueError as e:
            raise ValueError(str(e)) from None
        return self


class OtpVerifyIn(ContactIn):
    code: Annotated[str, StringConstraints(pattern=r"^\d{6}$")]


class ProfileIn(BaseModel):
    full_name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160)]


def _own_finding(db: Session, person: Person, finding_id: int) -> Finding:
    """404 (not 403) for other people's findings, so ids cannot be probed."""
    f = db.get(Finding, finding_id)
    if f is None or f.person_id != person.id:
        raise HTTPException(404, "finding not found")
    return f


def _send_otp(db: Session, sender: OtpSender, now: datetime, body: ContactIn, purpose: str,
              person_id: int | None = None) -> None:
    try:
        code = services.issue_otp(db, now, body.channel, body.identifier, purpose, person_id)
    except services.OtpRateLimited as e:
        raise HTTPException(429, str(e))
    try:
        sender.send(body.channel, body.identifier, code)
    except OtpDeliveryError:
        db.rollback()
        log.error("otp delivery failed", extra={"channel": body.channel})
        raise HTTPException(503, f"could not send a code by {body.channel}")
    db.commit()


# ---------------------------------------------------------------- routes

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/otp/request", status_code=202, dependencies=[Depends(limit("otp_request", 10, 600))])
def otp_request(body: ContactIn, db: Session = Depends(get_db), sender: OtpSender = Depends(get_otp_sender),
                now: datetime = Depends(get_now)):
    """Send a login code. Same response whether or not the contact already has an account."""
    _send_otp(db, sender, now, body, "login")
    return {"status": "sent"}


@app.post("/auth/otp/verify", dependencies=[Depends(limit("otp_verify", 30, 600))])
def otp_verify(body: OtpVerifyIn, db: Session = Depends(get_db), now: datetime = Depends(get_now)):
    ok = services.check_otp(db, now, body.channel, body.identifier, body.code, "login")
    db.commit()  # persist the attempt counter even on failure
    if not ok:
        raise HTTPException(400, "invalid or expired code")
    try:
        person = services.login_with_contact(db, now, body.channel, body.identifier)
        db.commit()
    except IntegrityError:  # two first logins raced; the other one created the account
        db.rollback()
        person = services.login_with_contact(db, now, body.channel, body.identifier)
        db.commit()
    token, ttl = create_access_token(person.id, now)
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl}


@app.get("/me")
def me(person: Person = Depends(current_person)):
    return {
        "id": person.id, "full_name": person.full_name, "email": person.email, "phone": person.phone,
        "email_verified": person.email_verified_at is not None, "phone_verified": person.phone_verified_at is not None,
        "scan_consent": bool(person.scan_consent_at and not person.scan_consent_revoked_at),
    }


@app.patch("/me")
def update_me(body: ProfileIn, person: Person = Depends(current_person), db: Session = Depends(get_db)):
    person.full_name = body.full_name
    db.commit()
    return {"full_name": person.full_name}


@app.delete("/me")
def erase_me(person: Person = Depends(current_person), db: Session = Depends(get_db),
             now: datetime = Depends(get_now)):
    """'Delete my data': removes the account, findings, consents, requests and audit rows for this person."""
    counts = services.erase_person(db, person, now)
    db.commit()
    return {"erased": True, **counts}


@app.post("/me/contacts/otp", status_code=202, dependencies=[Depends(limit("otp_request", 10, 600))])
def contact_otp(body: ContactIn, person: Person = Depends(current_person), db: Session = Depends(get_db),
                sender: OtpSender = Depends(get_otp_sender), now: datetime = Depends(get_now)):
    """Prove ownership of another email/phone. Silent no-op if it belongs to someone else (no enumeration)."""
    owner = services.owner_of(db, body.channel, body.identifier)
    if owner is None or owner.id == person.id:
        _send_otp(db, sender, now, body, "link", person.id)
    return {"status": "sent"}


@app.post("/me/contacts/verify", dependencies=[Depends(limit("otp_verify", 30, 600))])
def contact_verify(body: OtpVerifyIn, person: Person = Depends(current_person), db: Session = Depends(get_db),
                   now: datetime = Depends(get_now)):
    ok = services.check_otp(db, now, body.channel, body.identifier, body.code, "link", person.id)
    db.commit()
    if not ok:
        raise HTTPException(400, "invalid or expired code")
    try:
        services.link_contact(db, now, person, body.channel, body.identifier)
        db.commit()
    except (services.ContactConflict, IntegrityError):
        db.rollback()
        raise HTTPException(409, "this contact cannot be linked")
    return {"verified": body.channel}


@app.get("/me/audit")
def my_audit(person: Person = Depends(current_person), db: Session = Depends(get_db)):
    return [{"at": e.at, "action": e.action, "subject_type": e.subject_type, "subject_id": e.subject_id,
             "detail": e.detail} for e in services.audit_trail(db, person)]


@app.post("/me/scan-consent")
def scan_consent(person: Person = Depends(current_person), db: Session = Depends(get_db),
                 now: datetime = Depends(get_now)):
    services.grant_scan_consent(db, person, now)
    db.commit()
    return {"scan_consent": True}


@app.delete("/me/scan-consent")
def revoke_scan(person: Person = Depends(current_person), db: Session = Depends(get_db),
                now: datetime = Depends(get_now)):
    services.revoke_scan_consent(db, person, now)
    db.commit()
    return {"scan_consent": False}


@app.post("/me/scan", dependencies=[Depends(limit("scan", 10, 3600))])
def scan(person: Person = Depends(current_person), db: Session = Depends(get_db),
         scanners: list[services.Scanner] = Depends(get_scanners), now: datetime = Depends(get_now)):
    created = services.run_scan(db, person, scanners, now)
    db.commit()
    return {"new_findings": len(created)}


@app.get("/me/findings")
def findings(person: Person = Depends(current_person), db: Session = Depends(get_db)):
    return [
        {"id": f.id, "source": f.source, "url": f.url, "data_types": f.data_types.split(","), "status": f.status}
        for f in db.scalars(select(Finding).where(Finding.person_id == person.id).order_by(Finding.id))
    ]


@app.post("/findings/{finding_id}/consent")
def consent(finding_id: int, person: Person = Depends(current_person), db: Session = Depends(get_db),
            now: datetime = Depends(get_now)):
    services.grant_removal_consent(db, _own_finding(db, person, finding_id), now)
    db.commit()
    return {"consent": True}


@app.delete("/findings/{finding_id}/consent")
def withdraw(finding_id: int, person: Person = Depends(current_person), db: Session = Depends(get_db),
             now: datetime = Depends(get_now)):
    services.revoke_removal_consent(db, _own_finding(db, person, finding_id), now)
    db.commit()
    return {"consent": False}


@app.post("/findings/{finding_id}/remove", status_code=201)
def remove(finding_id: int, person: Person = Depends(current_person), db: Session = Depends(get_db),
           now: datetime = Depends(get_now)):
    """Queues the letter. The worker sends it (and re-checks consent at send time)."""
    req = services.request_removal(db, person, _own_finding(db, person, finding_id), now)
    db.commit()
    return {"request_id": req.id, "state": req.state, "follow_up_due": req.follow_up_due}
