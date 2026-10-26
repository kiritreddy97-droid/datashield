# DataShield India: Architecture

```
 Web / mobile client
        |  HTTPS + Bearer JWT
   FastAPI service  (backend/app/main.py: routes, auth dependency, rate limits, request logs)
        |
   services.py      (all business rules; pure functions over a DB session; unit-tested)
        |                          \
   SQLAlchemy models              pluggable edges: OtpSender (otp.py), RemovalSender (removal_sender.py),
   --> PostgreSQL (SQLite for     Scanner (scanners/)
       local dev and tests)
                                   worker.py  (python -m app.worker): sends queued letters, escalates overdue ones
```

## Principles
- Business rules live in `services.py`, not in route handlers, so they are testable without HTTP.
- Time is passed in (`now`) and always timezone-aware (`app/clock.py`), so rules are deterministic in tests. The database layer rejects naive datetimes.
- Route handlers translate domain errors to HTTP status codes and commit the transaction.
- Money is stored in integer rupees or paise; never floats.
- Everything that talks to the outside world (OTP, letters, scanners) is behind an interface with a fake for tests.

## Identity, consent and ownership
- **Login** is by OTP (`POST /auth/otp/request`, `/auth/otp/verify`) and returns a short-lived JWT (HS256, `ACCESS_TOKEN_TTL_MINUTES`, default 60). There are no refresh tokens: the client logs in again. Codes are 6 digits, expire in 10 minutes, allow 5 guesses, are single-use, and at most 3 are issued per identifier per 10 minutes. Only keyed hashes of codes and identifiers are stored.
- **An account exists only after OTP proof of a contact**, and a phone/email is stored on the profile only after its own OTP (`/me/contacts/otp`, `/me/contacts/verify`). Scans and removals additionally require that *every* identifier on the profile is verified (`services.require_verified`), so the scanner never searches for an identifier the user has not proven they control.
- **Ownership**: the person is the account (`/me/...`). Findings are reached by id, and a finding that is not yours returns 404 (same as a missing one) so ids cannot be probed. Services also re-check `finding.person_id`.
- **Consent**: scan consent (revocable) gates scans; per-finding revocable consent gates each removal. Consent is re-checked when the worker sends, so withdrawing consent cancels a queued letter and stops follow-ups.

## Data protection
- `full_name`, `email`, `phone`, finding `url` and letter bodies are encrypted at rest with Fernet (`ENCRYPTION_KEY`; comma-separated keys rotate: first encrypts, all decrypt). Lookups use keyed HMAC blind indexes (`BLIND_INDEX_KEY`) so equality search and uniqueness work without storing plaintext. Never change `BLIND_INDEX_KEY` after users exist (they could not log in again).
- `audit_events` records consent grants/revocations, scans, removal requests/sends/escalations, logins and erasure. `detail` never holds personal data. Users can read their own trail at `GET /me/audit`.
- `DELETE /me` ("delete my data") erases the account, findings, consents, requests, challenges and the user's audit rows, and leaves one anonymous `account_erased` row (no person id). Whether law requires keeping any evidence longer is a question for the legal review (docs/05).
- Logs are JSON on stdout. Request logs carry route template, status, duration, request id and person id; never query strings, bodies, tokens, emails or phone numbers.

## Removal letters and the worker
`POST /findings/{id}/remove` only queues a letter (`removal_requests.state = pending`). `python -m app.worker` (run it on a schedule, or with `--loop SECONDS`):
1. escalates findings returned by `services.due_follow_ups` (initial letter sent, follow-up date passed, consent still active), queueing a reminder letter and setting the finding to `escalated`;
2. sends every pending letter through the `RemovalSender` (SMTP in production, fake for dry runs) after re-checking consent; failures retry up to 5 times, then `failed`;
3. leaves letters for listings without a known grievance address as `pending` and reports them as `needs_manual`.

`services.mark_result` (removed / refused) has no HTTP route yet: it is for the operator console or a future inbound-reply handler.

## Database migrations
Alembic (`backend/migrations`). The schema is created only by migrations (`alembic upgrade head`; the Docker image does this on start). Autogenerate new revisions with `alembic revision --autogenerate -m "..."` from `backend/`. CI applies the migrations to Postgres, runs `alembic check` (fails if the models drifted from the migrations), downgrades, upgrades again, and runs the whole test suite on Postgres.

## Production hardening checklist
Done in this repo:
- [x] OTP login with JWT, ownership checks on every route, OTP proof of identifiers before scans/removals
- [x] Encryption of identifiers at rest, audit log, erase-my-data
- [x] Alembic migrations with a Postgres CI check
- [x] Timezone-aware time
- [x] Removal sender interface (SMTP + fake) and worker
- [x] Rate limiting (per-IP, per-route, per-identifier OTP) and structured logging

Still open (needs credentials, accounts or decisions; see the "Owner actions" in the PR and docs/08):
- [ ] SMS provider adapter for phone OTP (India needs DLT registration); email OTP works with SMTP
- [ ] Real secrets in the host's secret manager, encryption-key backup and a rotation drill
- [ ] Rate-limit counters in Redis if you run more than one API instance (they are per process today)
- [ ] Error tracking (e.g. Sentry) and database backups on the host
- [ ] Payments via a licensed gateway; webhooks verified by signature
- [ ] Operator/admin console for `mark_result`, manual letters and inbound replies
- [ ] Legal review of every scanner source and the letter/escalation wording (docs/05)

## Environments
`local` (SQLite or docker compose Postgres), `staging` and `production` on a cloud host. See [08-cloud-deploy.md](08-cloud-deploy.md).
