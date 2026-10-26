# DataShield India: Product Requirements (MVP)

## MVP scope
- Consent-first onboarding with revocable scan consent
- Scanner interface with pluggable sources
- Findings list with per-listing removal consent
- Removal request drafting, tracking, follow-up and escalation
- Monitoring: rescan and alert on re-appearance (phase 2)
- Evidence log for grievance-board escalation (phase 2)

## Personas
- Individuals receiving spam/scam calls
- Women and public-facing professionals worried about doxxing
- Families (add parents/children)
- Later: businesses protecting employee/executive data

## Non-goals for MVP
- Native mobile apps (web first), advanced analytics, internationalisation.

## Acceptance
- Every rule in `backend/app/services.py` has tests in `backend/tests/`.
- `/health` responds and the API deploys from the Dockerfile.
- Pricing and legal pages are reviewed against `05-legal-compliance.md` before real users are onboarded.

## API
Run the backend and open `/docs` for the generated OpenAPI documentation.

| Route | Purpose |
|---|---|
| `POST /auth/otp/request`, `POST /auth/otp/verify` | OTP login (email or Indian mobile); returns a JWT |
| `GET/PATCH /me`, `DELETE /me` | Profile; "delete my data" |
| `POST /me/contacts/otp`, `POST /me/contacts/verify` | Prove ownership of another phone/email |
| `POST/DELETE /me/scan-consent`, `POST /me/scan`, `GET /me/findings` | Scan consent, scan, list findings |
| `POST/DELETE /findings/{id}/consent`, `POST /findings/{id}/remove` | Per-listing consent; queue a removal letter |
| `GET /me/audit` | The user's own consent and action history |

All routes except `/health` and `/auth/*` require `Authorization: Bearer <token>` and only ever touch the caller's own data.
