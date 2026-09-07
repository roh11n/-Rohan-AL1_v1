# PRD — SOCPilot AI (Run/Preview Deploy of -Rohan-AL1_v1)

## Original Problem Statement
Run the existing Emergent app `-Rohan-AL1_v1` (SOCPilot AI — autonomous L1 SOC analyst for IBM QRadar MSSP) unmodified, wired to fresh infra, in a preview environment. No public deploy. Code stays untouched; only `.env`/config gets real values. VirusTotal is the external dependency.

## Architecture
- Frontend: React 19 (CRA + craco), shadcn/ui, react-router, served on :3000
- Backend: FastAPI on 0.0.0.0:8001 (supervisor, uvicorn), all routes prefixed `/api`
- DB: MongoDB (MONGO_URL), DB_NAME=socpilot_ai
- RAG: ChromaDB + sentence-transformers (CHROMA_PATH)
- Local LLM: Qwen2.5-3B via transformers/torch (CPU, lazy-loaded, best-effort → rule-engine fallback)
- Threat Intel: VirusTotal / AbuseIPDB / MISP — keys stored in Mongo `settings` doc via app Settings UI (NOT env vars)

## Required Env Vars (backend/.env)
- MONGO_URL (required), DB_NAME (required), JWT_SECRET_KEY (required — crashes if missing)
- CORS_ORIGINS, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, CHROMA_PATH
- SEED_ADMIN_EMAIL, SEED_ADMIN_PASSWORD, SEED_ANALYST_PASSWORD, SEED_DEMO_USERS
Frontend: REACT_APP_BACKEND_URL (preserved).

## Deploy Actions Done (2026-06)
- Cloned public repo, copied into /app unmodified (only .env written).
- Installed deps; installed CPU-only torch first to fit the 9.8G /app disk (CUDA torch exceeded space).
- Wired backend/.env (built-in Mongo, DB_NAME=socpilot_ai, generated JWT_SECRET_KEY, admin+analyst seed).
- Injected the provided VirusTotal key via the app's authenticated Settings API (data config, not code) → VT enabled, 1 healthy key (ending 43ef).
- Smoke test (testing agent): backend 17/17, frontend login (admin+analyst) + all 8 routes + VT settings + offense detail. No 5xx crashes.

## Test Credentials
- Admin: admin@socpilot.ai / Admin@12345
- Analyst: analyst@socpilot.ai / Analyst@123

## Known Non-Blocking Notes
- Benign React dev-mode warnings from emergent visual-editor instrumentation (option/hydration) + Recharts min-height. Not app bugs; left untouched.
- Only additive file from testing: backend/tests/test_smoke_deploy.py (regression smoke suite; run with `-n 0`).
- Local LLM report gen may be slow on CPU; falls back to rule engine (expected).

## Backlog / Next Steps
- P1: When ready, rotate/replace VT key; add AbuseIPDB/MISP keys in Settings.
- P2: Public URL — redo env wiring for a hosted target (separate phase).
- P2 (code-level, not this phase): split server.py into route modules.
