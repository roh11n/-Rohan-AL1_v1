"""Iteration 11: KB manual add, All-Tenants scope, settings analysis_mode, KB vs LLM investigate paths."""
import os
import time
import requests
import pytest

def _read_frontend_env():
    for line in open("/app/frontend/.env"):
        if line.startswith("REACT_APP_BACKEND_URL="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError("REACT_APP_BACKEND_URL missing")

BASE = os.environ.get("REACT_APP_BACKEND_URL", _read_frontend_env()).rstrip("/")


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{BASE}/api/auth/login",
                      json={"email": "admin@socpilot.ai", "password": "Admin@12345"}, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def h(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def _get_settings(h):
    r = requests.get(f"{BASE}/api/settings", headers=h, timeout=15)
    assert r.status_code == 200
    return r.json()


def _set_mode(h, mode):
    s = _get_settings(h)
    p = {**s, "llm": {**(s.get("llm") or {}), "analysis_mode": mode}}
    r = requests.put(f"{BASE}/api/settings", headers=h, json=p, timeout=15)
    assert r.status_code == 200
    return _get_settings(h)["llm"]["analysis_mode"]


def test_settings_analysis_mode_roundtrip(h):
    assert _set_mode(h, "llm") == "llm"
    assert _set_mode(h, "kb") == "kb"


def test_kb_manual_add_all_tenants(h):
    payload = {
        "client_id": "ALL",
        "alert_name": "Multiple Login Failures for Single Username",
        "analysis": "TEST_ITER11 global manual entry — reused as template.",
        "verdict": "Suspicious",
        "recommendations": ["Enable MFA", "Lock account after N failures"],
    }
    r = requests.post(f"{BASE}/api/kb/manual", headers=h, json=payload, timeout=30)
    assert r.status_code == 200, r.text
    e = r.json()
    assert e["client_id"] == "ALL"
    assert e["entry_kind"] == "manual"
    assert e["alert_name"] == payload["alert_name"]
    r2 = requests.get(f"{BASE}/api/kb", headers=h, params={"client_id": "ALL"}, timeout=15)
    assert r2.status_code == 200
    assert e["id"] in [x["id"] for x in r2.json()]


def test_kb_mode_investigate(h):
    _set_mode(h, "kb")
    offs = requests.get(f"{BASE}/api/offenses", headers=h, timeout=15).json()
    target = None
    for o in offs:
        blob = f"{o.get('description','')} {o.get('rule_name','')} {o.get('name','')}"
        if "Multiple Login Failures" in blob:
            target = o
            break
    target = target or offs[0]
    r = requests.post(f"{BASE}/api/offenses/{target['id']}/investigate", headers=h, timeout=60)
    assert r.status_code == 200, r.text
    body = r.json()
    mssp = body.get("mssp_report") or body.get("ai_analysis", {}).get("mssp_report") or {}
    src = (mssp.get("generated_by") or "").lower()
    assert src.startswith("kb-template") or src == "rule-engine", f"unexpected source: {src}"
    print(f"KB mode source={src} matched='{target.get('description') or target.get('rule_name')}'")


def test_llm_mode_investigate_fast_then_poll(h):
    _set_mode(h, "llm")
    offs = requests.get(f"{BASE}/api/offenses", headers=h, timeout=15).json()
    oid = offs[0]["id"]
    t0 = time.time()
    r = requests.post(f"{BASE}/api/offenses/{oid}/investigate", headers=h, timeout=30)
    dt = time.time() - t0
    assert r.status_code == 200
    assert dt < 20, f"investigate too slow: {dt:.1f}s"
    body = r.json()
    ai = body.get("ai_analysis") or body
    status = (ai.get("llm_status") or "").lower()
    print(f"LLM investigate returned in {dt:.1f}s status={status}")
    final_src = None
    final_status = None
    for _ in range(30):
        time.sleep(2)
        d = requests.get(f"{BASE}/api/offenses/{oid}", headers=h, timeout=15).json()
        ai = d.get("ai_analysis") or {}
        final_status = (ai.get("llm_status") or "").lower()
        final_src = (ai.get("mssp_report", {}).get("generated_by") or "").lower()
        if final_status in ("done", "failed"):
            break
    print(f"LLM final: status={final_status} source={final_src}")
    # Reset default
    _set_mode(h, "kb")
