"""Smoke test for SOCPilot AI run-as-is deployment."""
import os
import pytest
import requests

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") if os.environ.get("REACT_APP_BACKEND_URL") else "https://rohan-scan-test.preview.emergentagent.com"
API = f"{BASE}/api"

ADMIN = {"email": "admin@socpilot.ai", "password": "Admin@12345"}
ANALYST = {"email": "analyst@socpilot.ai", "password": "Analyst@123"}


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{API}/auth/login", json=ADMIN, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def analyst_token():
    r = requests.post(f"{API}/auth/login", json=ANALYST, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def admin_hdr(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def test_root_health():
    r = requests.get(f"{API}/", timeout=10)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_admin_login():
    r = requests.post(f"{API}/auth/login", json=ADMIN, timeout=15)
    assert r.status_code == 200
    j = r.json()
    assert j["user"]["role"] == "Admin"
    assert j["access_token"]


def test_analyst_login():
    r = requests.post(f"{API}/auth/login", json=ANALYST, timeout=15)
    assert r.status_code == 200
    j = r.json()
    assert j["user"]["email"] == "analyst@socpilot.ai"


def test_invalid_login():
    r = requests.post(f"{API}/auth/login", json={"email": "admin@socpilot.ai", "password": "wrong"}, timeout=10)
    assert r.status_code in (400, 401, 403)


def test_clients_list(admin_hdr):
    r = requests.get(f"{API}/clients", headers=admin_hdr, timeout=15)
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list)
    names = [c.get("name", "").upper() for c in data]
    # Expect ACME, NOVA, ORION
    assert len(data) >= 3, f"Expected >=3 clients, got {len(data)}: {names}"
    for expected in ["ACME", "NOVA", "ORION"]:
        assert any(expected in n for n in names), f"Missing seeded client {expected}: {names}"


def test_offenses_list(admin_hdr):
    r = requests.get(f"{API}/offenses", headers=admin_hdr, timeout=20)
    assert r.status_code == 200, r.text
    data = r.json()
    # could be list or dict wrapper
    items = data if isinstance(data, list) else data.get("items") or data.get("offenses") or []
    assert len(items) >= 10, f"Expected many seeded offenses, got {len(items)}"


def test_offense_detail(admin_hdr):
    r = requests.get(f"{API}/offenses", headers=admin_hdr, timeout=20)
    items = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
    assert items
    oid = items[0].get("id") or items[0].get("_id")
    d = requests.get(f"{API}/offenses/{oid}", headers=admin_hdr, timeout=20)
    assert d.status_code == 200, d.text
    assert d.json().get("id") == oid or d.json().get("_id") == oid


def test_tickets_list(admin_hdr):
    r = requests.get(f"{API}/tickets", headers=admin_hdr, timeout=15)
    assert r.status_code == 200, r.text


def test_users_list(admin_hdr):
    r = requests.get(f"{API}/users", headers=admin_hdr, timeout=15)
    assert r.status_code == 200, r.text
    assert isinstance(r.json(), list)


def test_audit_list(admin_hdr):
    r = requests.get(f"{API}/audit", headers=admin_hdr, timeout=15)
    assert r.status_code == 200, r.text


def test_knowledge_base(admin_hdr):
    # KB requires client_id query param
    clients = requests.get(f"{API}/clients", headers=admin_hdr, timeout=15).json()
    cid = clients[0]["id"]
    r = requests.get(f"{API}/kb", headers=admin_hdr, params={"client_id": cid}, timeout=15)
    assert r.status_code == 200, r.text
    assert isinstance(r.json(), list)
    # KB status
    s = requests.get(f"{API}/kb/status", headers=admin_hdr, timeout=15)
    assert s.status_code == 200, s.text


def test_settings_get(admin_hdr):
    r = requests.get(f"{API}/settings", headers=admin_hdr, timeout=15)
    assert r.status_code == 200, r.text
    j = r.json()
    # Threat intel section should exist
    ti = j.get("threat_intel") or j.get("threatIntel") or {}
    assert ti or "virus_total" in str(j).lower() or "virustotal" in str(j).lower()


def test_vt_health(admin_hdr):
    r = requests.get(f"{API}/threat-intel/vt-health", headers=admin_hdr, timeout=20)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get("enabled") is True
    assert j.get("total", 0) >= 1
    # healthy may vary but should not error
    assert "healthy" in j


def test_vt_enrich_ip(admin_hdr):
    # Real VT lookup path is /offenses/{id}/vt-lookup with artifact_type/value
    r = requests.get(f"{API}/offenses", headers=admin_hdr, timeout=20)
    items = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
    assert items
    oid = items[0]["id"]
    body = {"artifact_type": "ip", "value": "8.8.8.8"}
    resp = requests.post(f"{API}/offenses/{oid}/vt-lookup", headers=admin_hdr, json=body, timeout=45)
    # Accept 200 (VT returned) or 502/503/504 (VT upstream degraded) - never a 5xx crash
    assert resp.status_code != 500, f"Hard 500 from VT lookup: {resp.text[:400]}"
    assert resp.status_code in (200, 400, 429, 502, 503, 504), f"Unexpected: {resp.status_code} {resp.text[:300]}"


def test_offense_investigate(admin_hdr):
    r = requests.get(f"{API}/offenses", headers=admin_hdr, timeout=20)
    items = r.json() if isinstance(r.json(), list) else r.json().get("items", [])
    oid = items[0]["id"]
    resp = requests.post(f"{API}/offenses/{oid}/investigate", headers=admin_hdr, json={}, timeout=120)
    assert resp.status_code == 200, f"Investigate failed: {resp.status_code} {resp.text[:400]}"
    j = resp.json()
    # Should return some analysis structure
    assert isinstance(j, dict) and (j.get("ai_analysis") or j.get("mssp_report") or "risk_score" in str(j))


def test_dashboard_metrics(admin_hdr):
    r = requests.get(f"{API}/dashboard/metrics", headers=admin_hdr, timeout=15)
    assert r.status_code == 200, r.text


def test_mongo_write_via_settings(admin_hdr):
    # GET-then-PUT idempotent write to prove Mongo writes
    r = requests.get(f"{API}/settings", headers=admin_hdr, timeout=15)
    assert r.status_code == 200
    body = r.json()
    put = requests.put(f"{API}/settings", headers=admin_hdr, json=body, timeout=20)
    assert put.status_code in (200, 204), put.text
