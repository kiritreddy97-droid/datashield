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
3. Set the secrets below in the Render dashboard (the API refuses to start in production without them, by design).
4. Open `https://<service>.onrender.com/docs`.

Alternatives: Fly.io, Railway, Google Cloud Run (image from the Dockerfile) or AWS App Runner. Set `DATABASE_URL` from the managed Postgres.

## 4. Configuration (environment variables)
| Variable | Required in production | Notes |
|---|---|---|
| `APP_ENV=production` | yes | Turns on startup checks: dev keys and `OTP_SENDER=console` are refused |
| `DATABASE_URL` | yes | Provided by `render.yaml` from the managed Postgres |
| `JWT_SECRET` | yes | 32+ random characters (`render.yaml` asks Render to generate it) |
| `ENCRYPTION_KEY` | yes | Fernet key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. **Back it up outside Render**: losing it makes stored identifiers unreadable. Rotate with `new,old` |
| `BLIND_INDEX_KEY` | yes | 32+ random characters. **Back it up; never change it** once users exist |
| `OTP_SENDER` | yes | `smtp` (email codes). Phone codes need an SMS adapter implementing `app.otp.OtpSender` |
| `SMTP_HOST/PORT/USER/PASSWORD/FROM`, `SMTP_STARTTLS` | yes | Email provider credentials (used for OTP emails and removal letters) |
| `REMOVAL_SENDER` | yes | `smtp`, or `fake` for a dry run that sends nothing |
| `REMOVAL_REPLY_TO` | recommended | Shared grievance mailbox that sites reply to |
| `FORWARDED_ALLOW_IPS=*` | on Render | So rate limiting sees client IPs behind Render's proxy |
| `RATE_LIMIT_PER_MINUTE` | no | Global per-IP limit, default 120 |
| `FIXTURE_SCANNER_PATH` | no | Demo scanner only; leave unset in production |

The Docker image runs `alembic upgrade head` before starting. With more than one API instance, run migrations as a single release step instead.

## 5. The worker
Letters are only queued by the API. Something must run `python -m app.worker` on a schedule (every few hours) for them to be sent and for overdue requests to be escalated. Options: a Render cron job (paid plan; a commented example is in `render.yaml`), another host's scheduler, or `docker compose up worker` locally (`REMOVAL_SENDER=fake`). Start with `REMOVAL_SENDER=fake` and read the logs before enabling real email.

## 6. Before real users
Follow the hardening checklist in [03-architecture.md](03-architecture.md).
