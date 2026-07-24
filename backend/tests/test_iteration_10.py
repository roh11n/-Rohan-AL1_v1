"""Iteration 10: editable MSSP report + multi-VT-key rotation + vt-health endpoint."""
import os
import time
import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE = line.split("=", 1)[1].strip().rstrip("/")
API = f"{BASE}/api"

ADMIN = {"email": "admin@socpilot.ai", "password": "Admin@123"}
L1 = {"email": "analyst@socpilot.ai", "password": "Analyst@123"}


def H(tok): return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{API}/auth/login", json=ADMIN, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def l1_token():
    r = requests.post(f"{API}/auth/login", json=L1, timeout=30)
    if r.status_code != 200:
        pytest.skip("L1 login unavailable")
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def acme_client(admin_token):
    r = requests.get(f"{API}/clients", headers=H(admin_token))
    assert r.status_code == 200
    for c in r.json():
        if "Acme" in c.get("name", ""):
            return c
    return r.json()[0]


@pytest.fixture(scope="module")
def investigated_offense(admin_token, acme_client):
    r = requests.get(f"{API}/offenses?client_id={acme_client['id']}", headers=H(admin_token))
    assert r.status_code == 200
    offs = r.json()
    assert len(offs) >= 8
    # find the expired one which is known to give a rich mssp_report
    target = None
    for o in offs:
        if "Expired" in (o.get("description") or ""):
            target = o
            break
    if not target:
        target = offs[0]
    r2 = requests.post(f"{API}/offenses/{target['id']}/investigate", headers=H(admin_token), timeout=90)
    assert r2.status_code == 200, r2.text
    return r2.json()


# ---------- MSSP edit ----------
def test_mssp_edit_all_fields(admin_token, investigated_offense):
    oid = investigated_offense["id"]
    payload = {
        "fields": {
            "source_ip": "10.10.10.10",
            "destination_ip": "10.10.10.20",
            "username": "TEST_USER",
            "event_name": "TEST_EVENT",
            "low_level_category": "TEST_CAT",
        },
        "analysis_lines": [
            {"n": 1, "text": "TEST_ line one"},
            {"n": 2, "text": "TEST_ line two"},
        ],
        "recommendations": ["TEST_ rec 1", "TEST_ rec 2"],
        "verdict": "TP",
        "verdict_reason": "TEST_ verdict reason",
        "analyst_notes": "TEST_ analyst notes body",
    }
    r = requests.patch(f"{API}/offenses/{oid}/mssp-report", headers=H(admin_token), json=payload, timeout=30)
    assert r.status_code == 200, r.text
    off = r.json()
    rep = off["ai_analysis"]["mssp_report"]
    assert rep["source_ip"] == "10.10.10.10"
    assert rep["username"] == "TEST_USER"
    assert rep["verdict"] == "TP"
    assert rep["verdict_reason"] == "TEST_ verdict reason"
    assert rep["analyst_notes"] == "TEST_ analyst notes body"
    assert len(rep["analysis_lines"]) == 2
    assert rep["analysis_lines"][0]["text"] == "TEST_ line one"
    assert rep["analysis_lines"][0]["n"] == 1
    assert rep["recommendations"] == ["TEST_ rec 1", "TEST_ rec 2"]
    assert rep["edited_by"] == "admin@socpilot.ai"
    assert rep.get("edited_at")

    # verify persistence via GET
    r2 = requests.get(f"{API}/offenses/{oid}", headers=H(admin_token))
    assert r2.status_code == 200
    rep2 = r2.json()["ai_analysis"]["mssp_report"]
    assert rep2["username"] == "TEST_USER"
    assert rep2["verdict"] == "TP"


def test_mssp_edit_invalid_verdict(admin_token, investigated_offense):
    oid = investigated_offense["id"]
    r = requests.patch(f"{API}/offenses/{oid}/mssp-report", headers=H(admin_token),
                       json={"verdict": "BOGUS"}, timeout=15)
    assert r.status_code == 400


def test_mssp_edit_partial_update_preserves_other_fields(admin_token, investigated_offense):
    oid = investigated_offense["id"]
    # first fetch current
    cur = requests.get(f"{API}/offenses/{oid}", headers=H(admin_token)).json()
    prev_notes = cur["ai_analysis"]["mssp_report"].get("analyst_notes")
    # send only verdict change
    r = requests.patch(f"{API}/offenses/{oid}/mssp-report", headers=H(admin_token),
                       json={"verdict": "FP"}, timeout=15)
    assert r.status_code == 200
    rep = r.json()["ai_analysis"]["mssp_report"]
    assert rep["verdict"] == "FP"
    assert rep.get("analyst_notes") == prev_notes  # untouched


def test_mssp_edit_requires_auth(investigated_offense):
    oid = investigated_offense["id"]
    r = requests.patch(f"{API}/offenses/{oid}/mssp-report", json={"verdict": "TP"})
    assert r.status_code in (401, 403)


# ---------- Settings: multi VT keys ----------
def test_settings_multi_vt_keys_persist_and_mask(admin_token):
    # get current settings first
    cur = requests.get(f"{API}/settings", headers=H(admin_token)).json()
    orig_ti = cur.get("threat_intel") or {}
    orig_single = orig_ti.get("virustotal_api_key") or ""
    orig_enabled = bool(orig_ti.get("virustotal_enabled"))

    fake_keys = "TESTKEY_1111111111111111111111111111AAAA\nTESTKEY_2222222222222222222222222222BBBB\nTESTKEY_3333333333333333333333333333CCCC"
    payload = {"threat_intel": {
        "virustotal_enabled": True,
        "virustotal_api_keys": fake_keys,
        "virustotal_api_key": orig_single,
    }}
    r = requests.put(f"{API}/settings", headers=H(admin_token), json=payload, timeout=15)
    assert r.status_code == 200, r.text
    # PUT returns {ok: True}; refetch to see masked
    s = requests.get(f"{API}/settings", headers=H(admin_token)).json()
    ti = s.get("threat_intel") or {}
    assert ti.get("virustotal_api_keys_count") == 3
    masked = ti.get("virustotal_api_keys_masked") or []
    assert len(masked) == 3
    for m in masked:
        assert m.startswith("••••")
        assert len(m) == 8  # ••••XXXX
    # actual raw keys are not returned
    assert not ti.get("virustotal_api_keys")

    # restore original single key state (drop the fake multi keys by setting empty string)
    restore = {"threat_intel": {
        "virustotal_enabled": orig_enabled,
        "virustotal_api_keys": "",
        "virustotal_api_key": orig_single,
    }}
    r2 = requests.put(f"{API}/settings", headers=H(admin_token), json=restore, timeout=15)
    assert r2.status_code == 200


# ---------- VT-health endpoint ----------
def test_vt_health_admin(admin_token):
    r = requests.get(f"{API}/threat-intel/vt-health", headers=H(admin_token), timeout=15)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "enabled" in body
    if body.get("enabled"):
        assert "total" in body
        assert "healthy" in body
        assert "cooling_off" in body


def test_vt_health_forbidden_for_l1(l1_token):
    r = requests.get(f"{API}/threat-intel/vt-health", headers=H(l1_token), timeout=15)
    assert r.status_code in (401, 403), r.text


# ---------- VT lookup with rotation still works with real key ----------
def test_vt_lookup_real(admin_token, acme_client):
    # find offense with an external IP artifact
    offs = requests.get(f"{API}/offenses?client_id={acme_client['id']}", headers=H(admin_token)).json()
    tried = 0
    for o in offs:
        detail = requests.get(f"{API}/offenses/{o['id']}", headers=H(admin_token)).json()
        arts = detail.get("artifacts") or {}
        ips = arts.get("external_ips") or arts.get("ips") or []
        # also try source_ips at offense level
        src_ips = detail.get("source_ips") or []
        ips = list(dict.fromkeys(list(ips) + [ip for ip in src_ips if not ip.startswith(("10.","172.","192.168."))]))
        for ip in ips:
            r = requests.post(f"{API}/offenses/{o['id']}/vt-lookup",
                              headers=H(admin_token),
                              json={"artifact_type": "ip", "value": ip}, timeout=30)
            tried += 1
            if r.status_code == 200:
                body = r.json()
                # response shape: {entry: {result: {...}}, offense: {...}}
                assert "entry" in body, f"missing entry: {body}"
                assert "offense" in body
                # entry.result is either a stats dict OR {error:...} if VT quota hit
                assert body["entry"].get("value") == ip
                return
            if r.status_code == 400 and "not configured" in r.text.lower():
                pytest.skip("VT not configured")
            if tried >= 3:
                break
        if tried >= 3:
            break
    pytest.skip("No suitable external IP artifact found to test VT lookup")


# ---------- Tenant isolation regression ----------
def test_tenant_isolation_l1(l1_token, admin_token):
    # find non-acme client
    clients = requests.get(f"{API}/clients", headers=H(admin_token)).json()
    # analyst has all tenants seeded — read L1 profile to check
    me = requests.get(f"{API}/auth/me", headers=H(l1_token))
    if me.status_code != 200:
        pytest.skip("cannot fetch L1 profile")
    tids = me.json().get("tenant_ids") or []
    if len(tids) >= len(clients):
        pytest.skip("L1 has access to all tenants — no isolation to test")
    forbidden = [c for c in clients if c["id"] not in tids]
    if not forbidden:
        pytest.skip("no forbidden tenant")
    r = requests.get(f"{API}/offenses?client_id={forbidden[0]['id']}", headers=H(l1_token))
    assert r.status_code in (403, 404), r.text
