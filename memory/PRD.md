# SOCPilot AI — Product Requirements Document

## Original Problem Statement
Build "SOCPilot AI", an enterprise-grade AI application automating Level-1 SOC analysis for an MSSP environment using IBM QRadar. Ingest offenses via QRadar REST/Ariel, correlate events, RAG-match a per-tenant Knowledge Base, run local-LLM investigation (MITRE mapping, IOC extraction, risk scoring, verdict, recommendations), and route analyst-approved tickets to XSOAR / ServiceNow / Jira. Multi-tenant. Mock data drives the flow until QRadar credentials are configured.

## User Personas
- **L1 Analyst**: triages the offense queue, verifies verdicts, closes/escalates. Restricted to assigned tenants.
- **L2/L3 SME**: deep-dives escalated offenses; approves final ticket. Restricted to assigned tenants.
- **SOC Manager**: oversees clients, KB uploads, dashboards. Unrestricted (cross-tenant).
- **Admin**: settings, integrations, users/RBAC. Unrestricted.

## Core Capabilities (implemented)
- Multi-tenant clients with **hard tenant boundary** on every data endpoint
- QRadar client (offenses + Ariel event AQL) with mock fallback (`sample_data.py`, 12 seeded offenses/client)
- Async KB ingest (ChromaDB) with PROCESSING/READY/FAILED states, non-blocking upload
- AI investigation (rule engine + optional local LLM narrative) producing MSSP L1 report + MITRE + IOCs + risk + verdict (TP/FP/Suspicious)
- Threat-intel enrichment (VirusTotal, AbuseIPDB, MISP) — on-demand per artifact
- Ticket lifecycle: create → approve → push (mocked destinations XSOAR/ServiceNow/Jira/Slack/Teams/email)
- Analyst-coach learning loop feeding per-rule risk delta
- Dark/Light theme, Payload Field Explorer, Analyst Coach dashboard

## Security posture (Feb 2026 hardening pass)
- **Bootstrap credentials from env**: no more hard-coded default admin. `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` come from `.env`; if password is blank, a random 20-char password is generated once at first boot, logged, and the account is flagged `must_reset_password`.
- **Login throttling**: 5 failed attempts / 15 min → 429 lockout per email.
- **`POST /api/auth/change-password`** enforces current-password verification + ≥10-char new password.
- **Tenant isolation** — every list/read/write endpoint (`/offenses`, `/tickets`, `/kb*`, `/dashboard`, `/clients`, `/qradar/sync`, offense mutations) goes through `_tenant_filter()` or `_assert_tenant_access()`. Admin & SOC-Manager retain cross-tenant access.
- **Rate limits**: `/offenses/{id}/investigate` 30/h, `/offenses/{id}/vt-lookup` 60/h, per user, in-memory sliding window.
- **TLS defaults on**: `QRadarSettings.verify_ssl` and `ThreatIntelSettings.misp_verify_ssl` default to True.
- **MISP SSRF guard**: rejects loopback/private/link-local hostnames and non-http(s) schemes.
- **Login page** no longer prefills or advertises default credentials.
- **Audit trail** already covers login, close/escalate/status changes; password-change events logged (with `***` mask on password field).

### Known-accepted risks (P3 backlog, address before production)
- Integration tokens stored plaintext in Mongo (masked on read; consider KMS-wrapped column for prod).
- 8-hour non-rotating JWT held in `localStorage` (XSS surface is minimal — no confirmed sinks).
- `CORS_ORIGINS=*` in preview `.env`; production must set explicit origins.

## Recent Changes
See `/app/memory/CHANGELOG.md` for the full history. Highlights:

### 2026-02-23
- Editable MSSP analyst report (`PATCH /api/offenses/{id}/mssp-report`) — full override of fields, analysis lines, recommendations, verdict, analyst notes; edits are tenant-checked + audit-logged + stamped `edited_by/edited_at`.
- Multi-VirusTotal-key rotation — new `virustotal_api_keys` multiline setting; round-robin picker with 1h cooldown on 429/401/403. `GET /api/threat-intel/vt-health` snapshot. Legacy single-key field preserved.
- Full **ThreatGraph light-mode UI** — Deloitte green + cool gray, Manrope/Inter/JetBrains Mono, terminal-style comments, tg-surface cards, tg-sev / tg-status pills, lime accent header, live-pulse clock. Dark mode retained as toggle.
- Fix: `"__CLEAR__"` sentinel lets the UI explicitly clear any saved secret; empty submissions still preserve.

### 2026-02-22
- Security hardening pass (env-seeded admin, login throttling, tenant isolation, rate limits, TLS defaults on).
- Offenses list overhaul (horizontal scroll, bulk actions, per-row status dropdown).
- Artifacts tab + per-artifact VirusTotal button; MSSP report VT section.

## Backlog (prioritised)
### P0
- (none)

### P1
- Unify legacy action buttons (Approve/Reject/Escalate L3/Close/Create Ticket) with the newer `LifecycleActions` component on the offense detail page.
- Frontend UX for **must_reset_password**: force a change-password modal at first login when the field is true (backend already gates via the endpoint; UI plumbing pending).
- Real QRadar API + webhook integration (config-driven; `qradar_client.py` already implements offense + Ariel AQL).
- Real ITSM push for XSOAR / ServiceNow / Jira (replace `external_ref` mock).

### P2
- Full RBAC roles UI enforcement across nav + actions (backend already enforced).
- Multi-console / multi-domain QRadar support in Settings.
- Live event streaming / WebSocket dashboard.
- Encrypt vendor API tokens at rest (Fernet or KMS-wrapped).

## Key Files
- Backend: `server.py`, `auth.py`, `models.py`, `soc_engine.py`, `sample_data.py`, `threat_intel.py`, `qradar_client.py`, `rag_store.py`, `kb_ingest.py`
- Frontend: `pages/OffensesPage.jsx`, `pages/OffenseDetailPage.jsx`, `pages/LoginPage.jsx`, `components/MsspReport.jsx`, `components/LifecycleActions.jsx`

## Test Credentials
See `/app/memory/test_credentials.md`.
