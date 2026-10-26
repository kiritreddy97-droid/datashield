from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import services
from .db import Base, engine, get_db
from .models import Finding, Person


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="DataShield India", lifespan=lifespan)

# Register real scanners here (one per source). Empty by default: scans find nothing until configured.
SCANNERS: list[services.Scanner] = []


class PersonIn(BaseModel):
    full_name: str
    email: str
    phone: str | None = None


def _get(db: Session, model, id_: int):
    obj = db.get(model, id_)
    if obj is None:
        raise HTTPException(404, f"{model.__name__} {id_} not found")
    return obj


def _consent_guard(fn, *args):
    try:
        return fn(*args)
    except services.ConsentError as e:
        raise HTTPException(403, str(e))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/people", status_code=201)
def create_person(body: PersonIn, db: Session = Depends(get_db)):
    p = Person(**body.model_dump())
    db.add(p)
    db.commit()
    return {"id": p.id}


@app.post("/people/{person_id}/scan-consent")
def scan_consent(person_id: int, db: Session = Depends(get_db)):
    services.grant_scan_consent(db, _get(db, Person, person_id), datetime.utcnow())
    db.commit()
    return {"scan_consent": True}


@app.delete("/people/{person_id}/scan-consent")
def revoke_scan(person_id: int, db: Session = Depends(get_db)):
    services.revoke_scan_consent(db, _get(db, Person, person_id), datetime.utcnow())
    db.commit()
    return {"scan_consent": False}


@app.post("/people/{person_id}/scan")
def scan(person_id: int, db: Session = Depends(get_db)):
    created = _consent_guard(services.run_scan, db, _get(db, Person, person_id), SCANNERS)
    db.commit()
    return {"new_findings": len(created)}


@app.get("/people/{person_id}/findings")
def findings(person_id: int, db: Session = Depends(get_db)):
    _get(db, Person, person_id)
    return [
        {"id": f.id, "source": f.source, "url": f.url, "data_types": f.data_types.split(","), "status": f.status}
        for f in db.scalars(select(Finding).where(Finding.person_id == person_id))
    ]


@app.post("/findings/{finding_id}/consent")
def consent(finding_id: int, db: Session = Depends(get_db)):
    services.grant_removal_consent(db, _get(db, Finding, finding_id), datetime.utcnow())
    db.commit()
    return {"consent": True}


@app.delete("/findings/{finding_id}/consent")
def withdraw(finding_id: int, db: Session = Depends(get_db)):
    services.revoke_removal_consent(db, _get(db, Finding, finding_id), datetime.utcnow())
    db.commit()
    return {"consent": False}


@app.post("/findings/{finding_id}/remove", status_code=201)
def remove(finding_id: int, db: Session = Depends(get_db)):
    f = _get(db, Finding, finding_id)
    req = _consent_guard(services.request_removal, db, _get(db, Person, f.person_id), f, datetime.utcnow())
    db.commit()
    return {"request_id": req.id, "follow_up_due": req.follow_up_due}
