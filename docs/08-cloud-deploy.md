# DataShield India: Cloud Setup

Everything is designed to run in the cloud, not on a laptop.

## 1. Develop in the cloud (GitHub Codespaces)
Push this repo to GitHub, open it in a Codespace. `.devcontainer/devcontainer.json` installs dependencies automatically. Run:
```bash
cd backend && uvicorn app.main:app --reload
```

## 2. Test in the cloud
`.github/workflows/ci.yml` runs lint, tests and a Docker build on every push and pull request.

## 3. Deploy in the cloud (Render, free tier to start)
1. Push to GitHub.
2. In Render choose New > Blueprint and select the repo. `render.yaml` creates the API (from the Dockerfile) and a Postgres database.
3. Open `https://<service>.onrender.com/docs`.

Alternatives: Fly.io, Railway, Google Cloud Run (image from the Dockerfile) or AWS App Runner. Set `DATABASE_URL` from the managed Postgres.

## 4. Before real users
Follow the hardening checklist in [03-architecture.md](03-architecture.md).
