"""Background worker: python -m app.worker [--loop SECONDS]. Run on a schedule (cron job) or as a loop."""

import argparse
import logging
import time
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from . import services
from .clock import utcnow
from .config import get_settings
from .db import SessionLocal
from .logging_config import configure_logging
from .models import Finding
from .removal_sender import Letter, RemovalSender, SendError, build_removal_sender

log = logging.getLogger("datashield.worker")


@dataclass
class RunSummary:
    escalated: int = 0
    sent: int = 0
    failed: int = 0
    cancelled: int = 0
    needs_manual: int = 0


def run_once(db: Session, sender: RemovalSender, now: datetime) -> RunSummary:
    """Escalate overdue findings, then send every queued letter that is still consented."""
    out = RunSummary()
    for finding in services.due_follow_ups(db, now):
        services.escalate(db, finding, now)
        out.escalated += 1
    db.commit()

    for req in services.pending_requests(db):
        finding = db.get(Finding, req.finding_id)
        if not services.active_consent(db, finding):  # consent may have been withdrawn since queuing
            services.cancel_request(db, req, "consent withdrawn")
            out.cancelled += 1
        elif not finding.contact_email:
            req.last_error = "no grievance contact known; submit manually"
            out.needs_manual += 1
        else:
            letter = Letter(to=finding.contact_email, subject=f"Erasure request under the DPDP Act [DS-{req.id}]",
                            body=req.body, reference=f"DS-{req.id}")
            try:
                sender.send(letter)
            except SendError as e:
                services.mark_send_failed(db, req, finding, str(e), now)
                out.failed += 1
            else:
                services.mark_sent(db, req, finding, now)
                out.sent += 1
        db.commit()
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Send due removal letters and escalate overdue ones.")
    parser.add_argument("--loop", type=int, metavar="SECONDS", help="repeat forever with this pause")
    args = parser.parse_args()
    configure_logging()
    get_settings().validate()  # never run against production data with dev keys
    sender = build_removal_sender()
    while True:
        with SessionLocal() as db:
            summary = run_once(db, sender, utcnow())
        log.info("worker run", extra={"summary": summary.__dict__})
        if not args.loop:
            return
        time.sleep(args.loop)


if __name__ == "__main__":
    main()
