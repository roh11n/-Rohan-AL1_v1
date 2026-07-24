# SOCPilot AI — CHANGELOG

## 2026-02-23 — Editable MSSP Report + VT Key Rotation + ThreatGraph UI
- **Editable MSSP report** (`PATCH /api/offenses/{id}/mssp-report`, `MsspReport.jsx` edit mode).
  Analyst can override every field (ID, offense name, severity, IPs, event name, category, log source…), rewrite the numbered analysis lines, add/remove recommendations, set verdict (TP/FP/Suspicious) + reason, and add Analyst Notes. Every save is tenant-checked, audit-logged, and stamped with `edited_by` + `edited_at`.
- **Multiple VirusTotal keys with round-robin rotation** (`threat_intel.py` — `_next_vt_key`, `_blacklist_vt_key`, `_vt_request`). New `virustotal_api_keys` multiline field. Keys are health-checked and a bad key (429/401/403) is cooled off for 1 h before retry. `GET /api/threat-intel/vt-health` snapshots the pool. Legacy single-key field kept for back-compat.
- **UI: full ThreatGraph light-mode redesign**. Deloitte Green + Cool Gray palette, Manrope (display) / Inter (body) / JetBrains Mono (labels), terminal-style `// comments` sub-headers, `.tg-surface` card system with soft shadow + hairline border, `.tg-sev-*` severity pills, `.tg-status-*` status pills, sidebar with lime-tint active nav + hexagon brand mark, header with lime accent strip and pulsing `LIVE · clock` badge. Dark mode retained as a `theme-toggle` button.
- **Bug fixes** (from testing agent iteration_10):
  - Sentinel `"__CLEAR__"` value on `virustotal_api_keys` (and any secret field) explicitly wipes the stored value; empty string still preserves. Settings UI shows a "Clear saved" button when any keys are saved.

## 2026-02-22 — Security Hardening
- Env-driven admin bootstrap; login throttling (5/15min); `/api/auth/change-password`; tenant isolation on every offense/ticket/KB/dashboard/clients endpoint; per-user rate limits on `investigate` (30/h) and `vt-lookup` (60/h); TLS-on defaults for QRadar/MISP; MISP SSRF guard.

## 2026-02-22 — Offenses Workflow
- Offenses list horizontal scroll + checkbox column + per-row status dropdown + bulk actions + close-with-comments modal.
- Removed AI Analysis tab; renamed IOCs → Artifacts (hosts, IPs, hashes, domains, URLs, cmd lines, usernames, hostnames). Per-artifact "Check VirusTotal" button; result shown inline and merged into MSSP report VT-lookups section.
- Backend endpoints: `POST /api/offenses/{id}/status`, `POST /api/offenses/bulk-status`, `POST /api/offenses/{id}/vt-lookup`.
- IOC domain regex hardened to reject CamelCase code identifiers (System.Net.WebClient).
