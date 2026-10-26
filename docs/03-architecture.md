# DataShield India: Architecture

```
 Web / mobile client
        |  HTTPS
   FastAPI service  (backend/app/main.py: routes only)
        |
   services.py      (all business rules; pure functions over a DB session; unit-tested)
        |
   SQLAlchemy models --> PostgreSQL (SQLite for local dev and tests)
```

## Principles
- Business rules live in `services.py`, not in route handlers, so they are testable without HTTP.
- Time is passed in (`now`/`today`) so rules are deterministic in tests.
- Route handlers translate domain errors to HTTP status codes and commit the transaction.
- Money is stored in integer rupees or paise; never floats.

## Production hardening checklist (not yet implemented)
- Authentication and authorisation (e.g. OTP login + JWT); several endpoints are marked as admin/partner/webhook-only in comments and must be protected before launch.
- Database migrations (Alembic) instead of `create_all`.
- Payments via a licensed gateway; webhooks verified by signature.
- Rate limiting, structured logging, error tracking, backups.
- Secrets in the host's secret manager, never in the repo.

## Environments
`local` (SQLite or docker compose Postgres), `staging` and `production` on a cloud host. See [08-cloud-deploy.md](08-cloud-deploy.md).
