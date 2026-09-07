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
