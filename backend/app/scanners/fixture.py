import json
from pathlib import Path

from ..crypto import normalize_email, normalize_phone
from ..models import Person
from ..services import Hit


class FixtureScanner:
    """Matches a person against a local JSON file. No network access; for demos, tests and as a template.

    File format: a list of {"match": {"email"?, "phone"?}, "source", "url", "data_types", "contact_email"?}.
    An entry matches when any given identifier equals one of the person's verified identifiers.
    """

    def __init__(self, path: str | Path):
        self._entries = json.loads(Path(path).read_text())

    def scan(self, person: Person) -> list[Hit]:
        mine = {"email": person.email and normalize_email(person.email),
                "phone": person.phone and normalize_phone(person.phone)}
        hits = []
        for e in self._entries:
            m = e["match"]
            if any(v and mine.get(k) and _norm(k, v) == mine[k] for k, v in m.items()):
                hits.append(Hit(source=e["source"], url=e["url"], data_types=e.get("data_types", []),
                                contact_email=e.get("contact_email")))
        return hits


def _norm(kind: str, value: str) -> str:
    return normalize_email(value) if kind == "email" else normalize_phone(value)
