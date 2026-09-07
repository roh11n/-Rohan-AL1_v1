"""Backend tests for the Offenses workflow iteration: per-row status change,
bulk status change, close-with-comments requirement, VT lookup, and the
QRadar sample_data seeding (events array present)."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN = {"email": "admin@socpilot.ai", "password": "Admin@123"}


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{API}/auth/login", json=ADMIN, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def acme_client_id(headers):
    r = requests.get(f"{API}/clients", headers=headers, timeout=30)
    assert r.status_code == 200
    for c in r.json():
        if c["code"] == "ACME":
            return c["id"]
    pytest.skip("Acme Financial client not seeded")


@pytest.fixture(scope="module")
def offenses(headers, acme_client_id):
    r = requests.get(f"{API}/offenses?client_id={acme_client_id}", headers=headers, timeout=30)
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 1
    return data


# ---------- Health / login ----------

def test_login_ok(token):
    assert token and isinstance(token, str)


def test_acme_has_12_offenses(offenses):
    assert len(offenses) == 12, f"Expected 12 seeded offenses, got {len(offenses)}"


# ---------- QRadar mock (sample_data) - events present in offense detail ----------

def test_offense_detail_has_events_array(headers, offenses):
    off = offenses[0]
    r = requests.get(f"{API}/offenses/{off['id']}", headers=headers, timeout=30)
    assert r.status_code == 200
    doc = r.json()
    assert "events" in doc
    assert isinstance(doc["events"], list)
    assert len(doc["events"]) > 0, "sample_data should seed non-empty events array"


# ---------- Per-row status change ----------

def test_status_change_to_investigating(headers, offenses):
    off = offenses[1]
    r = requests.post(f"{API}/offenses/{off['id']}/status",
                      headers=headers, json={"status": "INVESTIGATING"}, timeout=30)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "INVESTIGATING"

    # GET verifies persistence
    g = requests.get(f"{API}/offenses/{off['id']}", headers=headers, timeout=30)
    assert g.json()["status"] == "INVESTIGATING"


def test_status_change_closed_requires_comments(headers, offenses):
    off = offenses[2]
    r = requests.post(f"{API}/offenses/{off['id']}/status",
                      headers=headers, json={"status": "CLOSED"}, timeout=30)
    assert r.status_code == 400, f"expected 400 when closing without comments, got {r.status_code}"


def test_status_change_closed_with_comments(headers, offenses):
    off = offenses[3]
    r = requests.post(f"{API}/offenses/{off['id']}/status",
                      headers=headers,
                      json={"status": "CLOSED",
                            "closure_comments": "TEST_close: legit activity confirmed by client",
                            "closure_source": "analyst"}, timeout=30)
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["status"] == "CLOSED"
    assert "legit activity" in (doc.get("closure_comments") or "")

    g = requests.get(f"{API}/offenses/{off['id']}", headers=headers, timeout=30)
    assert g.json()["status"] == "CLOSED"
    assert g.json().get("closure_comments")


def test_invalid_status_rejected(headers, offenses):
    off = offenses[4]
    r = requests.post(f"{API}/offenses/{off['id']}/status",
                      headers=headers, json={"status": "BOGUS"}, timeout=30)
    assert r.status_code == 400


# ---------- Bulk status change ----------

def test_bulk_status_change(headers, offenses):
    ids = [offenses[5]["id"], offenses[6]["id"]]
    r = requests.post(f"{API}/offenses/bulk-status", headers=headers,
                      json={"offense_ids": ids, "status": "INVESTIGATING"}, timeout=30)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["updated"] == 2
    assert set(body["offense_ids"]) == set(ids)

    for oid in ids:
        g = requests.get(f"{API}/offenses/{oid}", headers=headers, timeout=30)
        assert g.json()["status"] == "INVESTIGATING"


def test_bulk_close_requires_comments(headers, offenses):
    ids = [offenses[7]["id"], offenses[8]["id"]]
    r = requests.post(f"{API}/offenses/bulk-status", headers=headers,
                      json={"offense_ids": ids, "status": "CLOSED"}, timeout=30)
    assert r.status_code == 400


def test_bulk_close_with_comments(headers, offenses):
    ids = [offenses[7]["id"], offenses[8]["id"]]
    r = requests.post(f"{API}/offenses/bulk-status", headers=headers,
                      json={"offense_ids": ids, "status": "CLOSED",
                            "closure_comments": "TEST_bulk close by analyst",
                            "closure_source": "analyst"}, timeout=30)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["updated"] == 2

    for oid in ids:
        g = requests.get(f"{API}/offenses/{oid}", headers=headers, timeout=30)
        assert g.json()["status"] == "CLOSED"
        assert g.json().get("closure_comments")


# ---------- VirusTotal lookup ----------

def test_vt_lookup_ip(headers, offenses):
    """Uses a known-flagged IP (45.79.181.223) to verify VT integration returns real data
    and result gets persisted into offense.vt_lookups and mssp_report."""
    off_id = offenses[9]["id"]
    r = requests.post(f"{API}/offenses/{off_id}/vt-lookup", headers=headers,
                      json={"artifact_type": "ip", "value": "45.79.181.223"},
                      timeout=60)
    if r.status_code == 400 and "not configured" in r.text.lower():
        pytest.skip("VirusTotal not configured in this environment")
    assert r.status_code == 200, r.text
    body = r.json()
    entry = body["entry"]
    assert entry["artifact_type"] == "ip"
    assert entry["value"] == "45.79.181.223"
    # persisted on offense
    off = body["offense"]
    key = "ip:45.79.181.223"
    assert key in (off.get("vt_lookups") or {})

    # After investigate, MSSP report should also contain vt_lookups if ai_analysis exists.
    # Trigger investigate then re-check MSSP.
    inv = requests.post(f"{API}/offenses/{off_id}/investigate", headers=headers, timeout=90)
    if inv.status_code == 200:
        # Re-lookup so VT gets injected into fresh mssp_report
        r2 = requests.post(f"{API}/offenses/{off_id}/vt-lookup", headers=headers,
                           json={"artifact_type": "ip", "value": "45.79.181.223"}, timeout=60)
        assert r2.status_code == 200
        mssp = (r2.json()["offense"].get("ai_analysis") or {}).get("mssp_report") or {}
        vt_list = mssp.get("vt_lookups") or []
        assert any(v.get("value") == "45.79.181.223" for v in vt_list), \
            "VT lookup should be injected into mssp_report.vt_lookups"
