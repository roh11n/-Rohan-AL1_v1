# Upgrade guide — SOCPilot AI (Local Qwen + KB analysis + Payload fields + Export)

Brings an older install up to date with these features added this session:
1. Local **Qwen LLM** + Settings switch between **KB Template** and **Local LLM** analysis
2. **Manual KB** "add historical data" entries + **All Tenants (ALL)** global KB scope
3. **Payload field extraction** (LEEF / key=value) + **full payload** display (no truncation)
4. **Offense export** to JSON (with events + payloads)

## Files changed (12)
Backend:
- `backend/models.py`          — LLMSettings.analysis_mode + default model Qwen2.5-0.5B; KBEntry manual fields
- `backend/kb_template.py`     — NEW (deterministic KB-template engine)
- `backend/llm_engine.py`      — default model 0.5B + build_llm_mssp_report_oneshot (tolerant parsing)
- `backend/server.py`          — /kb/manual, /offenses/export, ALL scope, investigate KB/LLM branch + background LLM task
- `backend/soc_engine.py`      — _parse_payload_kv() + payload fallback fields + timeline full payload
- `backend/requirements.txt`   — + accelerate
Frontend:
- `frontend/src/pages/SettingsPage.jsx`        — Analysis Engine selector (KB / LLM)
- `frontend/src/pages/KnowledgeBasePage.jsx`   — scope selector (+All Tenants) + manual add form
- `frontend/src/pages/OffensesPage.jsx`        — Export JSON button
- `frontend/src/pages/OffenseDetailPage.jsx`   — LLM pending banner + polling, Export button
- `frontend/src/components/MsspReport.jsx`     — source badge + renders all (incl. payload) fields
- `frontend/src/index.css`                     — .payload-viewer wrap (full payload)

## Apply the patch
From the repo root:
```bash
git apply UPGRADE_socpilot_llm_kb_export.patch        # or: git apply --3way ...
# if git apply fails on your older base, either resolve with --3way,
# or just copy the 12 files above from the new version over yours.
```

## Backend steps
```bash
cd backend
pip install -r requirements.txt      # installs `accelerate` (needed for local Qwen on CPU)
```
- The Qwen model (`Qwen/Qwen2.5-0.5B-Instruct`, ~1 GB) downloads on the first **LLM-mode** investigation.
  Ensure enough disk + RAM. To pre-download: `python -c "from huggingface_hub import snapshot_download; snapshot_download('Qwen/Qwen2.5-0.5B-Instruct')"`
  On a bigger server you can point Settings → Model Name at a larger/better model.

## Frontend steps
```bash
cd frontend
yarn install     # no new deps, safe to run
yarn build       # rebuild and redeploy static files
```

## Database migration
None required — all new fields have safe defaults:
- `LLMSettings.analysis_mode` defaults to `"kb"` (merged into existing settings automatically).
- New `KBEntry` fields are optional.

Recommended (optional) — update the existing global settings doc so LLM mode uses a model
your server can run (older installs may have Qwen-3B / TinyLlama):
```javascript
db.settings.updateOne({id:"global"}, {$set:{
  "llm.model_name":"Qwen/Qwen2.5-0.5B-Instruct",
  "llm.analysis_mode":"kb"
}})
```

## Restart
```bash
sudo supervisorctl restart backend frontend      # or your process manager
```

## New / changed API endpoints
- `POST /api/kb/manual`            — add historical KB entry (client_id can be "ALL")
- `POST /api/kb/import-csv`         — bulk-import historical analyses from CSV (auto-detects columns)
- `GET  /api/offenses/export`      — full offenses incl. events + payloads (?client_id=&ids=)
- `POST /api/offenses/import`      — re-import offenses (with events/payloads) from exported JSON
- `GET  /api/kb?client_id=ALL`     — global KB entries
- `POST /api/offenses/{id}/investigate` — now returns fast with `ai_analysis.llm_status="pending"`
  in LLM mode; the report is refined in the background and the UI polls for it.

## Also fixed
- Events tab: each event row is now click-to-expand to show ALL fields + full payload; supports
  QRadar field names (`sourceip`/`starttime`/`log_source`/`category_name`).
- `_asset_criticality` now coerces `network` to string (real QRadar exports send it as a boolean,
  which previously caused a 500 on investigate).
