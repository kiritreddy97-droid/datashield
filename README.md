# DataShield India

> Find where your personal data is exposed, and remove it, only with your permission.

Idea from a creator video: people's phone numbers and details appear on random websites; a platform finds exposed data, lets the user choose which listings to act on, and handles removal with the user's permission.

## What is in this repo
| Path | Purpose |
|---|---|
| `docs/` | Business plan, product requirements, architecture, roadmap, legal checklist, go-to-market, financial model, cloud setup |
| `backend/app/` | FastAPI service: `models.py`, `services.py` (business rules), `main.py` (routes), `otp.py` / `removal_sender.py` / `scanners/` (pluggable edges), `worker.py` |
| `backend/migrations/` | Alembic migrations (the only way the schema is created) |
| `backend/tests/` | Unit tests for every rule plus end-to-end API tests (auth, consent, ownership, erasure, worker) |
| `web/index.html` | Draft landing page |
| `finance/model.py` | Editable unit-economics model |
| `Dockerfile`, `docker-compose.yml`, `render.yaml` | Container and cloud deployment |
| `.github/workflows/ci.yml` | Lint, tests, Postgres migrations + full suite on Postgres, Docker build and boot |
| `.devcontainer/` | Cloud dev environment (GitHub Codespaces) |

## Quick start
```bash
cd backend
pip install -r requirements-dev.txt
pytest                              # SQLite; set TEST_DATABASE_URL=postgresql+psycopg://... to run on Postgres
alembic upgrade head                # create the local SQLite schema
uvicorn app.main:app --reload       # http://localhost:8000/docs
python -m app.worker                # send queued removal letters, escalate overdue ones (REMOVAL_SENDER=fake to dry-run)
```
Local dev needs no configuration: OTP codes are printed in the server log (`DEV OTP for email ...`) and dev-only keys are used. With Postgres: `docker compose up --build`. Copy `.env.example` for all settings.

Try the flow: `POST /auth/otp/request {"channel":"email","identifier":"you@example.com"}`, read the code from the log, `POST /auth/otp/verify`, then use the token. To see a demo finding set `FIXTURE_SCANNER_PATH=fixtures/exposures.sample.json` (from `backend/`) and log in as `asha@example.com`.

## Status
Launchable privacy-safe backend MVP: OTP login + JWT, ownership checks on every route, OTP proof of identifiers before any scan or removal, encrypted identifiers, audit log, erase-my-data, Alembic migrations, SMTP removal sender + worker, rate limiting, structured logs. No scanner for a real website exists, on purpose: each needs legal review first ([docs/05](docs/05-legal-compliance.md)).

Not launched: nothing is deployed and no real secrets are configured. What the owner still has to do (Render deploy, SMTP/SMS providers, keys, legal review) is in [docs/03](docs/03-architecture.md) and [docs/08](docs/08-cloud-deploy.md).

Start reading at `docs/01-business-plan.md`.
