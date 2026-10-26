from datetime import datetime, timezone


def utcnow() -> datetime:
    """Timezone-aware 'now'. Naive datetimes are rejected by the database layer."""
    return datetime.now(timezone.utc)
