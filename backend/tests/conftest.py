import os
import tempfile
from datetime import datetime, timedelta

os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mkdtemp()}/test.db")

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, delete  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app import services  # noqa: E402
from app.clock import utcnow  # noqa: E402
from app.db import Base, get_db  # noqa: E402
from app.main import app, get_otp_sender, get_scanners  # noqa: E402
from app.models import Person  # noqa: E402
from app.otp import FakeOtpSender  # noqa: E402
from app.ratelimit import limiter  # noqa: E402
from app.security import get_now  # noqa: E402

HITS = [
    services.Hit("SiteA", "https://sitea.example/p/1", ["phone", "email"], contact_email="grievance@sitea.example"),
    services.Hit("SiteB", "https://siteb.example/u/9", ["phone"]),  # no contact address known
]


@pytest.fixture(scope="session")
def engine():
    """In-memory SQLite by default. Set TEST_DATABASE_URL to run the whole suite on Postgres via the migrations."""
    url = os.getenv("TEST_DATABASE_URL")
    if url:
        cfg = Config("alembic.ini")
        cfg.attributes["url"] = url
        command.upgrade(cfg, "head")
        eng = create_engine(url)
    else:
        eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine):
    session = sessionmaker(bind=engine, autoflush=False)()
    yield session
    session.close()
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(delete(table))


@pytest.fixture(autouse=True)
def _fresh_rate_limits():
    limiter.reset()


class Clock:
    def __init__(self):
        self.now: datetime = utcnow()

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def otp():
    return FakeOtpSender()


@pytest.fixture
def client(engine, db, otp, clock):
    factory = sessionmaker(bind=engine, autoflush=False)

    def _db():
        s = factory()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_otp_sender] = lambda: otp
    app.dependency_overrides[get_scanners] = lambda: [services.StaticScanner(HITS)]
    app.dependency_overrides[get_now] = lambda: clock.now
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


class Users:
    """Log users in through the real OTP endpoints."""

    def __init__(self, client, otp):
        self.client, self.otp = client, otp

    def login(self, email: str, name: str | None = "Asha Rao") -> dict:
        assert self.client.post("/auth/otp/request", json={"channel": "email", "identifier": email}).status_code == 202
        r = self.client.post("/auth/otp/verify", json={
            "channel": "email", "identifier": email, "code": self.otp.last_code(email.lower())})
        assert r.status_code == 200, r.text
        headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
        if name:
            assert self.client.patch("/me", json={"full_name": name}, headers=headers).status_code == 200
        return headers


@pytest.fixture
def users(client, otp):
    return Users(client, otp)


def make_person(db, email="m@x.in", name="Meera Iyer", phone="+919000000000", verified=True) -> Person:
    """A person who has proven control of their contacts, for service-level tests."""
    now = utcnow()
    p = Person(full_name=name, created_at=now)
    if email:
        services.set_contact(p, "email", email, now)
        p.email_verified_at = now if verified else None
    if phone:
        services.set_contact(p, "phone", phone, now)
        p.phone_verified_at = now if verified else None
    db.add(p)
    db.flush()
    return p
