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


## 2026-06 — Real KB learning (consolidated ITSM knowledge, grounded output)
- Use-case matching: fuzzy name match kept, but conflicting words (Inbound/Outbound, Allowed/Denied, ...) or differing UC numbers => different use case (fixed 00317 Inbound matching 00316 Outbound KB).
- Consolidation: ALL kb.csv rows of the matched use case are merged (sentence dedupe, consensus weighting across tickets, verdict counts). `mssp_report.kb_learning` = {alert_name, ticket_count, match_score, verdict_counts}; UI badge "KB · N tickets · score%" (data-testid *-kb-learning).
- LLM: per-section generation (Analysis -> Impact -> Recommendations+Verdict) for the 0.5B model; junk/echo filtering, imperative routing to Recommendations, heading merge, truncated-bullet drop.
- Grounding: `kb_template.ground_sentence` injects this offense's IPs/host/user/process/port into KB & LLM bullets; deterministic grounded lead bullet when <2 bullets mention artifacts; inbound/outbound slips corrected vs alert name.
- Removed auto "Review the <log source> logs..." pointer (user request) + startup migration strips it from stored reports.
- Verdict remains LLM/threat-intel driven (KB verdict only in the instant kb-template pre-report).
- Legacy destructive test `tests/test_llm_mssp.py` is module-skipped (it swapped llm_engine.py on disk and once wiped edits).
- Verified: test_reports/iteration_6.json (4/4 backend, frontend E2E pass).

### Backlog
- P1: larger local model option (Qwen2.5-3B) if RAM/disk allow; file-hash VT enrichment for malware alerts.
- P2: secondary TI (OTX/AbuseIPDB); KB match insight panel (which sentences were learned/used).

## Update 2026-06 (c) — Triage moved to OpenRouter cloud (free model)
- LLM inference for MSSP report triage now runs on OpenRouter (OpenAI-compatible) instead of the local CPU Qwen. Configured via backend/.env `OPENROUTER_API_KEY` + `OPENROUTER_MODEL` (default `openrouter/free` auto-router — resilient to upstream per-provider rate limits).
- `llm_engine._chat_once` routes to `_openrouter_chat` (httpx, 429 retry + `openrouter/free` fallback, strips `<think>` reasoning) when the key is set; otherwise falls back to local transformers. `<think>` blocks and reasoning/instruction-echo lines are filtered.
- `llm_engine._section_bullets` + `_verdict_from` gained `_META_RE` filtering to drop reasoning-model leakage (e.g. "We need to output the ANALYSIS section", "each starting with '- '", "REASON: <one technical sentence>") and placeholder echoes.
- LLMSettings defaults changed to provider=`openrouter`, model=`openrouter/free`, analysis_mode=`llm`, enable_llm=true. Startup migration flips the global settings to the OpenRouter model when the key is present.
- Verified end-to-end on 3 offenses via external API: reports return `generated_by=llm:openrouter/free`, grounded technical Analysis/Recommendations, clean verdict+reason, no meta leaks. Report quality is markedly higher than the 0.5B local model.

## Update 2026-06 (d) — Trend Micro Apex Central / persistence extraction (UC-00508)
User reported the report for `IND-UC-00508-Virus Detected ... Behavior Monitoring: New startup program` didn't match the correct analyst analysis. Root cause: the Trend Micro Apex Central **CEF payload artifacts weren't extracted**, so the analysis was generic.
- `soc_engine._parse_payload_kv` now extracts CEF/EDR fields: `sproc`→process/file path, `TMCMLogTarget`→registry autorun key, `shost`/`TMCMLogDetectedHost`→host, `act`→action, and CEF `csNLabel=`/`csN=` pairs (Rule_Name/Operation/Risk_Level/Event_Type). These surface as `x_process`/`x_file_path`/`x_registry`/`x_host`/… and feed LLM grounding.
- Added a malware/behavior-monitoring/persistence branch to `_generate_analysis_lines` (weaves registry key + file path + host + action='Assess' meaning into one grounded sentence), a new deterministic `_generate_impact_lines` (startup/autorun persistence + "no evidence of confirmed compromise"), and a persistence branch to `_generate_recommendations` (verify file legitimacy → review startup/registry autorun/scheduled tasks → full AV/EDR scan → remove persistence/delete file). Recommendations cap raised to 4. Fixed a `user 'None'` rendering bug.
- Because these come from the deterministic base, the grounded output survives even when the OpenRouter free-tier LLM is empty/rate-limited. Verified: testing agent iteration_7.json — 100% backend, 2 consecutive passing runs, no issues.

## Update 2026-06 (e) — CTI IP-feed firewall report matches analyst template (UC-00317)
User supplied the exact desired MSSP L1 format for CTI/threat-intel IP-feed firewall-permit offenses. Required order: **Fields → Analysis → Impact → IOC Enrichment → Recommendations**, plus "remove the Historical similar incident line" and "use the extra fields in the payload".
- `soc_engine._parse_payload_kv` extracts firewall fields: policy/rule name, source/destination zone, NAT destination IP, session id/end reason, packets, action, firewall device (Palo Alto & Check Point). Deduped Policy Name==Rule Name and Destination NAT IP==Post NAT.
- New `_cti_feed_analysis` produces a field-driven 6-sentence analyst narrative (opener, CTI-monitored inbound on firewall, permitted connection w/ NAT + port, firewall policy, action, CTI-feed match, optional session bytes/packets/end-reason). `_generate_impact_lines` + `_generate_recommendations` have direction-aware CTI branches matching the reference (block IP / verify expected / review firewall rule).
- Removed the "Historical similar incident found …" correlation line from `_generate_analysis_lines` globally.
- `llm_engine.build_llm_mssp_report_oneshot` returns None for CTI/ip-feed offenses so the deterministic template is used verbatim (LLM won't reword it); `server._run_llm_report_bg` maps that None to `llm_status='done'` (source `rule-engine`), not 'failed'.
- `server._pick_external_ip` is now direction-aware (inbound ⇒ the source IP is the CTI indicator that gets VT-enriched). `_vt_ioc_enrichment` lines reworded to the reference phrasing ("We have reviewed the IP address … reputation is … belongs to … IOC Reference Link"). IOC Enrichment only renders when VirusTotal is ENABLED in Settings (currently disabled).
- Frontend `MsspReport.jsx`: section order Analysis → Impact → IOC Enrichment → Recommendations; copy-to-clipboard follows same order.
- Verified: testing agent iteration_8.json — 100% backend (2/2) + 100% frontend section-order, UC-00508 regression intact, no issues.

## Update 2026-06 (f) — New/arbitrary offenses now generate grounded analysis (payload field extraction)
User reported that for NEW offenses (beyond the tuned use cases) the analysis was thin and extracted payload fields weren't included. Root causes fixed in `backend/soc_engine.py`:
- **Field bleed:** payload key=value/colon parsing ran on payload+description joined, so a field's value swallowed the appended offense description (e.g. `session_end_reason = "aged-out  Palo Alto…"`). Now key=value/colon parse ONLY payload + event_description, and the value boundary stops at newline / 2+ spaces. Added fields: http_method, url_category, logon_type, workstation, status_code.
- **Wrong routing:** a "Malware Category URL" proxy alert matched the malware/persistence (registry-startup) branch, and substring `cti` matched inside "a**cti**vity" → CTI branch. Fixed: malware branch now requires real endpoint-persistence context; new `_is_cti_feed()` word-boundary matcher used everywhere (soc_engine analysis/impact/recs, llm_engine bypass, server template-bypass).
- **Fields not in analysis:** added `_grounded()` detail sentences plus dedicated branches for web/proxy (URL/method/category, blocked vs allowed), firewall-permit/traffic (direction, application, ports/protocol, policy, zones, bytes/packets — grammatical past-tense verb), and auth/brute-force (logon type, workstation, status code). `_generate_impact_lines` gained web/proxy + firewall branches.
- Verified: testing agent iteration_9.json — 100% backend (5/5): auth/proxy/firewall offenses now ground extracted fields, correct routing (no malware/CTI false positives), clean field values, CTI + UC-00508 regressions intact. (Minor: OpenRouter free-tier 429 log noise; rule-engine fallback keeps the deterministic report — no functional impact.)

## Update 2026-06 (g) — Login-failure use case (IND-GLUC-10020) uses the KB knowledge
User reported IND-GLUC-10020 (Multiple login failure from admin/administrator) generated incorrect analysis even though the KB (uploaded kb.csv, RAG-indexed) has the proper analysis/impact/recommendation. Root cause: the deterministic KB-template matcher only reads curated `entry_kind:manual` rows; the uploaded KB lives only in the vector store, so it was never applied — the report fell back to a thin generic auth write-up + a messy raw KB-snippet dump line.
- `server.py` investigate now builds a `kb_ref` from strong same-use-case RAG hits (`_extract_uc_id` + top-similarity/uc-id match) and passes it to the LLM as authoritative learned knowledge when no manual template matches.
- `soc_engine.py` now emits a proper deterministic KB-aligned narrative for login-failure/brute-force/password-spray: privileged-account framing, Logon Type meaning (`_LOGON_TYPES`), Windows status-code meaning (`_STATUS_MEANINGS`, e.g. 0xC000006D = bad username/invalid auth), credential-spray context; a 3-line Impact (unauthorized access, account compromise, lockout/service disruption); and 4 Recommendations (verify source IP, confirm with admin, check success-after-failure, monitor lockout/MFA). Removed the messy 'Historical KB reference' analysis dump line; whitespace-normalized the offense name.
- Because it's deterministic, the correct KB-aligned output shows even when the free-tier LLM 429s. Verified: testing agent iteration_10.json — 100% backend (4/4), CTI + malware + proxy regressions intact, no issues.

## Update 2026-06 (h) — Deterministic FALLBACK now matches LLM analysis depth (UC-00508)
User asked whether, when OpenRouter is rate-limited (429) and it falls back to the deterministic engine, the analysis is the same level — checked on UC-00508 (Virus Detected / New startup program).
- Expanded the malware/persistence branch in `soc_engine._generate_analysis_lines` from one dense compound sentence into MULTIPLE discrete analyst lines: detection (tool + host + user), the registry Run-key + file, the file-directory context (backslash-normalized Temp / AppData\\Local / Roaming / profile detection) requiring validation, the device-action meaning ('Assess' = detected/evaluated per policy, not auto-blocked), and a no-confirmed-compromise conclusion. Now ~6 grounded points matching the reference structure.
- Verified: testing agent iteration_11.json — 100% backend (3/3): UC-00508 fallback produces the multi-line grounded analysis, persistence Impact + 4 recs intact, login-failure + CTI regressions intact. The deterministic fallback (used on every 429) now matches the expected analysis level.
