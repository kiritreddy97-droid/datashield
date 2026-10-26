import json
from pathlib import Path

from conftest import make_person

from app import services
from app.clock import utcnow
from app.config import get_settings
from app.scanners import build_scanners
from app.scanners.fixture import FixtureScanner

SAMPLE = Path(__file__).parent.parent / "fixtures" / "exposures.sample.json"


def test_fixture_scanner_matches_only_the_persons_verified_identifiers(db):
    asha = make_person(db, email="Asha@Example.com", phone=None)
    both = make_person(db, email="other@x.in", phone="+91 90000 00001")
    nobody = make_person(db, email="nobody@x.in", phone=None)
    scanner = FixtureScanner(SAMPLE)
    assert [h.source for h in scanner.scan(asha)] == ["Example Directory (fictional)"]
    assert scanner.scan(asha)[0].contact_email == "grievance@directory.example.invalid"
    assert [h.url for h in scanner.scan(both)] == ["https://listings.example.invalid/u/9000000001"]
    assert scanner.scan(nobody) == []


def test_fixture_scanner_end_to_end_through_the_service(db):
    p = make_person(db, email="asha@example.com", phone=None)
    now = utcnow()
    services.grant_scan_consent(db, p, now)
    assert len(services.run_scan(db, p, [FixtureScanner(SAMPLE)], now)) == 1


def test_fixture_file_is_synthetic_only():
    text = SAMPLE.read_text()
    assert all(u.endswith(".invalid") or ".invalid/" in u for u in
               (e["url"].split("//")[1].split("/")[0] for e in json.loads(text)))


def test_scanners_are_off_by_default_and_enabled_by_env(monkeypatch):
    monkeypatch.delenv("FIXTURE_SCANNER_PATH", raising=False)
    get_settings.cache_clear()
    assert build_scanners() == []
    monkeypatch.setenv("FIXTURE_SCANNER_PATH", str(SAMPLE))
    get_settings.cache_clear()
    try:
        assert len(build_scanners()) == 1
    finally:
        get_settings.cache_clear()
