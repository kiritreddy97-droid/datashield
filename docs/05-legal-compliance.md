# DataShield India: Legal and Compliance Checklist

This is a working checklist, not legal advice. Have an Indian lawyer review it before launch.

- DPDP Act, 2023: we are a data fiduciary; collect only what is needed, with notice and consent, and support withdrawal and erasure of our own copy
- Verify the requester controls the identifiers (OTP on phone/email) before scanning or removal
- Encrypt identifiers at rest; hash where possible; minimal retention; audit logs
- Removal letters sent only for consented listings and with the user's written authorisation
- Get legal review of each scanner source before enabling (see below)

## Always
- Privacy policy and terms of service before collecting any real user data.
- A grievance officer and a data-deletion path for users.
- Entity setup (e.g. private limited company), GST registration when thresholds apply.

## Implemented controls (backend)
- OTP proof of every phone/email before a scan or removal; scans only search identifiers the user verified.
- Per-listing, revocable removal consent, re-checked when a letter is actually sent; withdrawing stops follow-ups.
- Audit log of consent grants/revocations, scans, removal requests, sends and escalations, readable by the user (`GET /me/audit`).
- Identifiers and letters encrypted at rest; "delete my data" endpoint (`DELETE /me`).

Open legal questions for the lawyer: retention of evidence after erasure (the endpoint currently keeps only an anonymous `account_erased` row); the wording of the removal and escalation letters and whether a Data Protection Board complaint can be referenced as written; whether acting "on the person's behalf" needs a signed authorisation stored with the request; breach-notification duties; children's data (verifiable parental consent) before allowing under-18 users; cross-border processing if the host or SMTP provider is outside India.

## Scanner sources: legal review gate
A scanner is code that looks for a person's data somewhere. Every real source (a people-search site, a leak index, a marketplace listing) carries its own risk: the site's terms of service, the Information Technology Act, 2000 (unauthorised access, data extraction), copyright and database rights, and the DPDP Act itself (we would be processing the data we find).

**Rule: no scanner for a real source is merged or enabled until a written legal review of that source is attached to the PR.** The review must cover: lawful access method (official API, opt-out/search form that permits it, or data supplied by the user), terms of service and robots rules, what we store (prefer the URL and data types, not the content), and the site's removal channel.

This repo deliberately ships **no scrapers for real websites**. The only implementation is `backend/app/scanners/fixture.py`, which reads a local JSON file of fictional entries (`backend/fixtures/exposures.sample.json`, `.invalid` domains) and makes no network calls. It exists to demo the flow and as a template: a source implements `Scanner.scan(person) -> list[Hit]`, is registered in `app/scanners/__init__.py:build_scanners`, and is switched on explicitly (the fixture scanner only when `FIXTURE_SCANNER_PATH` is set). Do not point `FIXTURE_SCANNER_PATH` at real personal data in production.
