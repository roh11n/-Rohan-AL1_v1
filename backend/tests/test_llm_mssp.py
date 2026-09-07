"""
Backend tests for the LLM-driven MSSP report feature.

Coverage (per iteration_3 review request):
  1. LLM OFF (default)               — investigate returns rule-engine mssp_report (no llm: prefix).
  2. LLM ON + SUCCESS (mocked)       — mssp_report replaced, source==llm, rule-engine fields preserved.
  3. LLM ON + FAILURE (mocked)       — silent fallback, generated_by starts with 'rule-engine (LLM fallback:'.
  4. SCHEMA / REGRESSION             — risk_score / mitre / iocs / etc. unchanged by LLM branch.
  5. Unit: _weighted_kb_context       — analyst_feedback entries weighted 2x.
  6. Regression: analyst_feedback KB — light re-check (a meaningful mssp-report edit still creates KB row).

To exercise the HTTP path without downloading the real 3B LLM, we swap in a mock
llm_engine module driven by a file flag `/tmp/llm_mock_mode` (values: success | fail | off).
Original module is preserved as llm_engine_orig.py and restored in teardown.
"""
import os
import json
import shutil
import time
from pathlib import Path

import pytest
import requests

def _load_frontend_env_url():
    try:
        for line in open("/app/frontend/.env"):
            if line.startswith("REACT_APP_BACKEND_URL="):
                return line.split("=", 1)[1].strip().rstrip("/")
    except Exception:
        pass
    return ""


BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or _load_frontend_env_url()
assert BASE_URL, "REACT_APP_BACKEND_URL must be set"

ADMIN_EMAIL = "admin@socpilot.ai"
ADMIN_PASS = "Admin@SOCPilot2026"

BACKEND_DIR = Path("/app/backend")
LLM_ENGINE = BACKEND_DIR / "llm_engine.py"
LLM_ENGINE_ORIG = BACKEND_DIR / "llm_engine_orig.py"
MOCK_FLAG = Path("/tmp/llm_mock_mode")

MOCK_MODULE_SRC = '''"""TEST MOCK — swapped in by test_llm_mssp.py to avoid downloading the real 3B LLM."""
from llm_engine_orig import *  # noqa: F401,F403
import llm_engine_orig as _orig
import os

def build_llm_mssp_report(offense, events, kb_matches, rule_engine_mssp,
                          model_name="Qwen/Qwen2.5-3B-Instruct",
                          temperature=0.3, step_timeout_seconds=180):
    mode = "off"
    try:
        mode = open("/tmp/llm_mock_mode").read().strip()
    except Exception:
        pass
    if mode == "success":
        return {
            "generated_by": "llm:mock",
            "verdict": "TP",
            "verdict_reason": "mock",
            "analysis_lines": [{"n": 1, "text": "mock line"}],
            "recommendations": ["mock rec"],
            "llm_used_kb": True,
            "mssp_report_source": "llm",
        }
    if mode == "fail":
        return None
    return None

def load_error():
    try:
        if open("/tmp/llm_mock_mode").read().strip() == "fail":
            return "mocked_failure_for_test"
    except Exception:
        pass
    return _orig.load_error()
'''


# --------------------------------------------------------------------------- #
# Mock swap helpers                                                            #
# --------------------------------------------------------------------------- #
def _swap_in_mock():
    if not LLM_ENGINE_ORIG.exists():
        shutil.copy2(LLM_ENGINE, LLM_ENGINE_ORIG)
    LLM_ENGINE.write_text(MOCK_MODULE_SRC)


def _restore_original():
    if LLM_ENGINE_ORIG.exists():
        shutil.copy2(LLM_ENGINE_ORIG, LLM_ENGINE)
        LLM_ENGINE_ORIG.unlink()
    if MOCK_FLAG.exists():
        MOCK_FLAG.unlink()


def _wait_for_backend():
    for _ in range(30):
        try:
            r = requests.get(f"{BASE_URL}/api/clients", timeout=5)
            if r.status_code in (200, 401):
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASS}, timeout=15)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture(scope="module")
def acme_client_id(headers):
    r = requests.get(f"{BASE_URL}/api/clients", headers=headers, timeout=15)
    r.raise_for_status()
    for c in r.json():
        if c.get("code", "").upper() == "ACME":
            return c["id"]
    pytest.skip("ACME client not seeded")


def _fresh_offense(headers, client_id, exclude_ids=None):
    exclude_ids = set(exclude_ids or [])
    r = requests.get(f"{BASE_URL}/api/offenses?client_id={client_id}",
                     headers=headers, timeout=15)
    r.raise_for_status()
    for o in r.json():
        if o["id"] not in exclude_ids:
            return o
    pytest.skip("No offense available")


def _set_llm(headers, enable, model_name="Qwen/Qwen2.5-3B-Instruct", timeout_seconds=30):
    cur = requests.get(f"{BASE_URL}/api/settings", headers=headers, timeout=15)
    assert cur.status_code == 200, f"GET /api/settings failed: {cur.status_code} {cur.text}"
    body = cur.json() or {}
    body["llm"] = {
        "provider": "local",
        "enable_llm": enable,
        "model_name": model_name,
        "endpoint_url": (body.get("llm") or {}).get("endpoint_url", ""),
        "api_token": (body.get("llm") or {}).get("api_token", ""),
        "max_tokens": (body.get("llm") or {}).get("max_tokens", 512),
        "temperature": 0.3,
        "llm_step_timeout_seconds": timeout_seconds,
    }
    r = requests.put(f"{BASE_URL}/api/settings", headers=headers, json=body, timeout=15)
    assert r.status_code == 200, f"settings PUT failed: {r.status_code} {r.text}"


# --------------------------------------------------------------------------- #
# Module-scoped setup: swap mock in ONCE, restore at the end.                 #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module", autouse=True)
def _mock_llm_engine():
    _swap_in_mock()
    MOCK_FLAG.write_text("off")
    time.sleep(4)  # let uvicorn hot-reload
    assert _wait_for_backend(), "backend did not come back after llm_engine swap"
    yield
    _restore_original()
    time.sleep(3)
    _wait_for_backend()


# --------------------------------------------------------------------------- #
# Tests                                                                        #
# --------------------------------------------------------------------------- #

# Test 1: LLM OFF — default rule-engine behaviour.
def test_llm_off_investigate(headers, acme_client_id):
    _set_llm(headers, enable=False)
    MOCK_FLAG.write_text("off")
    off = _fresh_offense(headers, acme_client_id)
    r = requests.post(f"{BASE_URL}/api/offenses/{off['id']}/investigate",
                      headers=headers, timeout=60)
    assert r.status_code == 200, f"investigate failed: {r.status_code} {r.text}"
    body = r.json()
    ai = body.get("ai_analysis") or {}
    mssp = ai.get("mssp_report") or {}
    assert mssp, "mssp_report should be present with LLM off"
    gen = str(mssp.get("generated_by") or "")
    assert not gen.startswith("llm:"), f"unexpected llm-generated report with LLM off: {gen}"
    # Save baseline for regression comparison in test 4.
    pytest.baseline = {
        "offense_id": off["id"],
        "risk_score": body.get("risk_score"),
        "mitre_techniques": body.get("mitre_techniques"),
        "iocs": body.get("iocs"),
        "recommendation": body.get("recommendation"),
        "confidence": body.get("confidence"),
        "kb_matches": body.get("kb_matches"),
        "similar_incidents": body.get("similar_incidents"),
    }


# Test 2 + 4: LLM ON + SUCCESS + schema regression against baseline.
def test_llm_on_success_and_schema_regression(headers, acme_client_id):
    baseline = getattr(pytest, "baseline", None)
    assert baseline is not None, "test_llm_off_investigate must run first"
    MOCK_FLAG.write_text("success")
    _set_llm(headers, enable=True)
    off_id = baseline["offense_id"]
    r = requests.post(f"{BASE_URL}/api/offenses/{off_id}/investigate",
                      headers=headers, timeout=60)
    assert r.status_code == 200, f"investigate failed: {r.status_code} {r.text}"
    body = r.json()
    ai = body.get("ai_analysis") or {}
    mssp = ai.get("mssp_report") or {}
    assert str(mssp.get("generated_by") or "").startswith("llm:"), \
        f"expected llm: prefix, got {mssp.get('generated_by')}"
    assert ai.get("mssp_report_source") == "llm", \
        f"expected mssp_report_source=='llm', got {ai.get('mssp_report_source')}"
    assert mssp.get("verdict") == "TP", f"verdict not carried through: {mssp.get('verdict')}"

    # Schema regression — non-mssp fields must still come from rule engine (unchanged).
    for k in ("risk_score", "mitre_techniques", "iocs", "recommendation",
              "confidence", "kb_matches", "similar_incidents"):
        assert body.get(k) == baseline[k], (
            f"regression: '{k}' changed between rule-engine and LLM branches\n"
            f"  before={baseline[k]!r}\n  after ={body.get(k)!r}"
        )


# Test 3: LLM ON + failure -> silent fallback.
def test_llm_on_failure_fallback(headers, acme_client_id):
    MOCK_FLAG.write_text("fail")
    _set_llm(headers, enable=True)
    # Use a different offense so status transitions don't lock us.
    prev = getattr(pytest, "baseline", {}).get("offense_id")
    off = _fresh_offense(headers, acme_client_id, exclude_ids={prev} if prev else None)
    r = requests.post(f"{BASE_URL}/api/offenses/{off['id']}/investigate",
                      headers=headers, timeout=60)
    assert r.status_code == 200, f"expected 200 on fallback, got {r.status_code}: {r.text}"
    body = r.json()
    ai = body.get("ai_analysis") or {}
    mssp = ai.get("mssp_report") or {}
    assert mssp, "mssp_report must be present in fallback branch"
    gen = str(mssp.get("generated_by") or "")
    assert gen.startswith("rule-engine (LLM fallback:"), \
        f"expected fallback stamp, got {gen!r}"
    assert ai.get("mssp_report_source") == "rule-engine-fallback", \
        f"expected mssp_report_source=='rule-engine-fallback', got {ai.get('mssp_report_source')}"


# Test 5: Unit — analyst_feedback weighting is 2x.
def test_weighted_kb_context_prefers_analyst_feedback():
    import sys, importlib
    sys.path.insert(0, str(BACKEND_DIR))
    # Import the ORIGINAL module (preserved as llm_engine_orig by the fixture).
    orig = importlib.import_module("llm_engine_orig")
    matches = [
        {"kb_type": "historical_incident", "similarity": 0.4,
         "source": "hist-1", "text": "historical incident content"},
        {"kb_type": "analyst_feedback", "similarity": 0.3,
         "source": "fb-1", "text": "analyst feedback content"},
    ]
    result = orig._weighted_kb_context(matches)
    idx_fb = result.find("analyst feedback content")
    idx_hist = result.find("historical incident content")
    assert idx_fb != -1 and idx_hist != -1, f"both entries should appear: {result}"
    assert idx_fb < idx_hist, (
        "analyst_feedback (sim 0.3 * 2 = 0.6) must rank above historical_incident (0.4)\n"
        f"got:\n{result}"
    )


# Test 6: Regression — LLM OFF + meaningful mssp-report edit still creates analyst_feedback KB row.
def test_analyst_feedback_kb_regression(headers, acme_client_id):
    _set_llm(headers, enable=False)
    prev_ids = {getattr(pytest, "baseline", {}).get("offense_id")}
    off = _fresh_offense(headers, acme_client_id, exclude_ids=prev_ids)
    r = requests.post(f"{BASE_URL}/api/offenses/{off['id']}/investigate",
                      headers=headers, timeout=60)
    assert r.status_code == 200

    # Snapshot KB count for this tenant
    kb_before = requests.get(f"{BASE_URL}/api/kb?client_id={acme_client_id}",
                             headers=headers, timeout=15).json()
    fb_before = [k for k in kb_before if k.get("kb_type") == "analyst_feedback"]

    # Meaningful edit — change verdict + notes
    patch = {
        "verdict": "FP",
        "verdict_reason": "Confirmed benign after L1 review — automated backup job.",
        "analyst_notes": "Backup job runs nightly on this host, matches vendor pattern.",
        "recommendations": ["Add allowlist rule for this backup job schedule."],
    }
    pr = requests.patch(f"{BASE_URL}/api/offenses/{off['id']}/mssp-report",
                        headers=headers, json=patch, timeout=15)
    assert pr.status_code == 200, f"mssp-report PATCH failed: {pr.status_code} {pr.text}"

    # Give the fire-and-forget ingest a moment.
    time.sleep(4)
    kb_after = requests.get(f"{BASE_URL}/api/kb?client_id={acme_client_id}",
                            headers=headers, timeout=15).json()
    fb_after = [k for k in kb_after if k.get("kb_type") == "analyst_feedback"]
    assert len(fb_after) > len(fb_before), (
        f"expected a new analyst_feedback KB row, "
        f"before={len(fb_before)} after={len(fb_after)}"
    )
