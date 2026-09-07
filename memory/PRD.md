# SOCPilot — Local Preview (Run As-Is)

## Original Problem Statement
Run the public repo `github.com/roh11n/-Rohan-AL1_v1` unchanged as a local preview.
React + FastAPI + MongoDB SOC copilot: ingests QRadar offenses, generates MSSP L1
analyst reports using a local Qwen2.5 LLM (CPU) + ChromaDB/sentence-transformers RAG.
User choices: try hard to make the local LLM work; adapt .env to this environment;
minimal fixes allowed; don't run sample_data.py (app auto-seeds).

## Architecture
- Frontend: React (CRACO), pages under frontend/src/pages, MsspReport component.
- Backend: FastAPI (server.py ~1900 lines), Motor/PyMongo, JWT auth + RBAC.
- DB: MongoDB local (mongodb://localhost:27017, DB test_database).
- LLM: local Qwen/Qwen2.5-0.5B-Instruct via HuggingFace transformers (CPU, torch 2.14 CPU build). llm_engine.py, lazy-loaded, single-worker executor.
- RAG: ChromaDB persistent at backend/.chroma_db + sentence-transformers all-MiniLM-L6-v2.
- Threat Intel: VirusTotal (key configured), AbuseIPDB, MISP (threat_intel.py).

## Deviations from "zero changes"
- Removed unused `emergentintegrations==0.2.0` from backend/requirements.txt (never imported; avoids extra-index dependency).
- Installed CPU-only torch (`--index-url .../whl/cpu`) instead of default CUDA build (disk/space; CPU target).
- backend/.env: set to environment values (MONGO_URL, DB_NAME) + added JWT_SECRET_KEY and SEED_* to bootstrap admin/analyst.
- frontend/.env: uses environment's external REACT_APP_BACKEND_URL.

## What's implemented / verified (2026-06)
- App runs end-to-end. Backend + frontend + mongodb up under supervisor.
- Auth/login (admin + L1 analyst), RBAC hides admin pages from L1.
- Auto-seed: 3 clients, 36 offenses (12 each), global settings.
- Investigate flow: instant rule-engine/KB report, then background local Qwen upgrades to LLM MSSP report (verdict + analysis lines + recommendations), ~15-20s CPU. Graceful fallback confirmed.
- Settings (Analysis Engine kb/llm), Knowledge Base (scope + manual add + CSV import), VirusTotal key configured.
- Testing agent: 8/8 frontend flows pass (iteration_1.json). Backend LLM path verified via API.

## Known non-blocking (pre-existing, left unchanged for run-as-is)
- Offense Detail: risk gauge SVG slightly overlaps Create Ticket button at 1920px.
- Recharts init "width/height(-1)" console warnings on dashboard load.
- Layout.jsx <option> contains <span> -> hydration warning.

## Credentials
See /app/memory/test_credentials.md.

## Backlog / Next
- P2: fix the 3 cosmetic issues above if moving beyond strict as-is.
- P2: optionally point Settings -> Model Name at a larger Qwen if more RAM/disk available (3B needs ~6GB disk for weights; current disk ~2GB free).

## Update 2026-06 — SOC L1 analysis quality upgrade
Fixed 4 user-reported flaws so reports read like a real MSSP L1 analyst:
1. Analysis now technical bullet points, grounded in offense fields/events/payload, with NO historical/other-offense comparison (llm_engine.build_llm_mssp_report_oneshot rewritten to a plain-text sectioned prompt + tolerant parser; small-model friendly).
2. Log source = the real onboarded device/tool from events (Zscaler/CrowdStrike/etc.); QRadar "Custom Rule Engine" (CRE) is skipped, LEEF vendor/product fallback (soc_engine._extract_log_source). Startup migration recomputes stale CRE log sources on pre-fix reports.
3. KB learning: kb.csv (Tenant Name,id,Ticket ID,occurred,name,severity,AnalystSeverity,Ticket Number,closeReason,closeNotes,ITSM_Analysis,ITSM_Impact,ITSM_Recommendations) imported -> vector DB; the matched use-case's analysis/impact/recommendations are fed to the LLM as reference and used to backfill any empty section (report always complete).
4. Report sections now ordered Analysis -> Impact -> Recommendations -> IOC Enrichment (VirusTotal only) -> Verdict. IOC Enrichment runs live via VirusTotal for any external IP (server._vt_ioc_enrichment) in both KB and LLM modes. Frontend MsspReport.jsx renders Impact + IOC Enrichment sections.

Verified: testing agent iteration_2.json 100% frontend + 2/2 backend pytest. Example: ACME CTI-outbound offense -> source=llm, real log source (Zscaler NSS), clean technical bullets, VT enrichment (Cloudflare/US/3 malicious), verdict TP.

Known non-blocking (pre-existing, not in this bug report): risk-donut overlaps Create Ticket button; <span>-in-<option> hydration warning.

## Update 2026-06 (b) — Payload coverage, deeper KB learning, review-logs
- Payload Field Coverage: soc_engine._structured_event_fields surfaces Process, Parent Process, Command Line, File Hash/SHA256/MD5, File Name/Path, Host, Registry, URL directly from event keys; broadened payload regexes. Verified: PowerShell offense shows Process=powershell.exe, Parent=outlook.exe, full -enc command line.
- Stronger KB learning: matched use-case's ITSM_Analysis/Impact/Recommendations are passed to the LLM as an authoritative "KB write-up" (llm_engine kb_ref) with adapt-to-this-offense instructions; output now clearly reflects/adapts KB content.
- Recommendations always include a "Review the <log source> logs and correlate ..." pointer (llm_engine._ensure_review_logs + kb_template).
- Cleanups: _sanitize_bullets drops code/script fragments and bare section markers (e.g. VARIABLES:). IOC Enrichment now also enriches the external IP found in extracted IOCs (server passes analysis.iocs.ipv4_external), fixing null-IOC + misleading TI verdict wording.
- Verified: testing agent iteration_3 -> fixes -> iteration_4 (4/4 backend pytest, 100% frontend). Report order Analysis -> Impact -> Recommendations -> IOC Enrichment -> Verdict.
