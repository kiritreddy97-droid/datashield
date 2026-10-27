import os
import tempfile

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from app import models  # noqa: F401
from app.db import Base


def _cfg(url: str) -> Config:
    cfg = Config("alembic.ini")
    cfg.attributes["url"] = url
    return cfg


def test_migrations_match_the_models_and_roll_back_cleanly():
    """On SQLite by default; CI also runs this against Postgres via MIGRATION_TEST_URL."""
    url = os.getenv("MIGRATION_TEST_URL") or f"sqlite:///{tempfile.mkdtemp()}/m.db"
    cfg = _cfg(url)
    engine = create_engine(url)
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata) == []
        tables = set(inspect(conn).get_table_names())
    assert {"people", "findings", "removal_consents", "removal_requests", "otp_challenges", "audit_events"} <= tables
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")  # and forward again
    engine.dispose()
