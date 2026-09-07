## 2026-06 — Lost edits incident
- `backend/tests/test_llm_mssp.py` used to swap `llm_engine.py` with a stub on disk; an interrupted pytest run left the stub and wiped uncommitted edits. Test is now module-skipped. NEVER run the tests folder in a command that may time out; never delete `llm_engine_orig.py` without diffing first.
