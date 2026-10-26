# DataShield India

> Find where your personal data is exposed, and remove it, only with your permission.

Idea from a creator video: people's phone numbers and details appear on random websites; a platform finds exposed data, lets the user choose which listings to act on, and handles removal with the user's permission.

## What is in this repo
| Path | Purpose |
|---|---|
| `docs/` | Business plan, product requirements, architecture, roadmap, legal checklist, go-to-market, financial model, cloud setup |
| `backend/app/` | FastAPI service: `models.py`, `services.py` (business rules), `main.py` (routes) |
| `backend/tests/` | Unit tests for every business rule, plus an API smoke test |
| `web/index.html` | Draft landing page |
| `finance/model.py` | Editable unit-economics model |
| `Dockerfile`, `docker-compose.yml`, `render.yaml` | Container and cloud deployment |
| `.github/workflows/ci.yml` | Lint, test, build on every push |
| `.devcontainer/` | Cloud dev environment (GitHub Codespaces) |

## Quick start
```bash
cd backend
pip install -r requirements-dev.txt
pytest
uvicorn app.main:app --reload     # http://localhost:8000/docs
```
With Postgres: `docker compose up --build`.

## Status
Backend MVP of the core rules is implemented and tested. Not production-ready: authentication, migrations, payments and integrations are listed as to-do in `docs/03-architecture.md`.

Start reading at `docs/01-business-plan.md`.
