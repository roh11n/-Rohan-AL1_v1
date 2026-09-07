"""SOCPilot AI - Iteration 4 tests: 12-offense seed, verdict/reason, KB search, KB retry."""
import os
import io
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
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def l1_token():
    r = requests.post(f"{API}/auth/login", json=L1, timeout=30)
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def clients(admin_token):
    r = requests.get(f"{API}/clients", headers=H(admin_token), timeout=15)
    assert r.status_code == 200
    return r.json()


# ---------- Seeding: 12 offenses per client with new DLB templates ----------
def test_seed_12_offenses_per_client(admin_token, clients):
    for c in clients[:3]:
        r = requests.get(f"{API}/offenses?client_id={c['id']}", headers=H(admin_token))
        assert r.status_code == 200
        offs = r.json()
        assert len(offs) >= 12, f"Client {c['code']} only has {len(offs)} offenses"
        descs = {o["description"] for o in offs}
        # 3 new DLB templates present
        assert any("DLB - Sensitive File Upload" in d for d in descs), descs
        assert any("DLB - Bulk Email" in d for d in descs), descs
        assert any("DLB - USB Mass Storage" in d for d in descs), descs
        # existing templates that must be represented
        assert any("Ransomware Signature" in d for d in descs), descs
        assert any("Login Failure to Expired Account" in d for d in descs), descs
        # verify severity label / ips / usernames present in list
        sample = offs[0]
        assert str(sample.get("severity_label", "")).lower() in ("low", "medium", "high", "critical")
        assert isinstance(sample.get("source_ips"), list)
        assert isinstance(sample.get("destination_ips"), list)
        assert isinstance(sample.get("usernames"), list)
        # events populated on detail
        det = requests.get(f"{API}/offenses/{sample['id']}", headers=H(admin_token)).json()
        assert isinstance(det.get("events"), list) and len(det["events"]) >= 1


# ---------- Verdicts on investigate ----------
def _find_offense(admin_token, client_id, needle):
    offs = requests.get(f"{API}/offenses?client_id={client_id}", headers=H(admin_token)).json()
    for o in offs:
        if needle.lower() in o["description"].lower():
            return o
    pytest.skip(f"No offense matching {needle}")


def test_investigate_ransomware_verdict_TP(admin_token, clients):
    off = _find_offense(admin_token, clients[0]["id"], "Ransomware Signature")
    r = requests.post(f"{API}/offenses/{off['id']}/investigate", headers=H(admin_token), timeout=90)
    assert r.status_code == 200
    mssp = r.json()["ai_analysis"]["mssp_report"]
    assert mssp["verdict"] == "TP", f"Verdict={mssp.get('verdict')} reason={mssp.get('verdict_reason')}"
    reason = (mssp.get("verdict_reason") or "").lower()
    assert ("ransom" in reason) or ("high-risk" in reason) or ("high risk" in reason), reason
    assert mssp.get("recommendation_text"), "Empty recommendation_text"


def test_investigate_dlb_bulk_email_suspicious(admin_token, clients):
    off = _find_offense(admin_token, clients[0]["id"], "DLB - Bulk Email")
    r = requests.post(f"{API}/offenses/{off['id']}/investigate", headers=H(admin_token), timeout=90)
    assert r.status_code == 200
    mssp = r.json()["ai_analysis"]["mssp_report"]
    assert mssp["verdict"] in ("Suspicious", "TP"), f"Got {mssp['verdict']} / {mssp.get('verdict_reason')}"
    assert mssp.get("verdict_reason"), "Empty verdict_reason"
    assert mssp.get("recommendation_text")


def test_investigate_login_expired_verdict_present(admin_token, clients):
    """Verdict may be FP if historical KB is uploaded, otherwise Suspicious. Both acceptable."""
    off = _find_offense(admin_token, clients[0]["id"], "Login Failure to Expired Account")
    r = requests.post(f"{API}/offenses/{off['id']}/investigate", headers=H(admin_token), timeout=90)
    assert r.status_code == 200
    mssp = r.json()["ai_analysis"]["mssp_report"]
    assert mssp["verdict"] in ("FP", "Suspicious", "TP")
    assert mssp.get("verdict_reason")
    assert mssp.get("recommendation_text")
    # analysis_lines must remain — check 4 numbered lines present in body
    body = mssp.get("body") or ""
    if body:
        # 4 numbered lines "1." "2." "3." "4."
        for n in ("1.", "2.", "3.", "4."):
            assert n in body, f"Missing numbered line {n} in mssp body"


# ---------- KB Search endpoint ----------
def test_kb_search_admin_ok(admin_token, clients):
    payload = {"client_id": clients[0]["id"], "query": "expired password login failure", "n_results": 5}
    r = requests.post(f"{API}/kb/search", headers=H(admin_token), json=payload, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert "matches" in d and "count" in d
    assert isinstance(d["matches"], list)


def test_kb_search_l1_allowed(l1_token, clients):
    payload = {"client_id": clients[0]["id"], "query": "expired password login failure", "n_results": 5}
    r = requests.post(f"{API}/kb/search", headers=H(l1_token), json=payload, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert "matches" in d


def test_kb_search_empty_query(admin_token, clients):
    payload = {"client_id": clients[0]["id"], "query": "", "n_results": 5}
    r = requests.post(f"{API}/kb/search", headers=H(admin_token), json=payload, timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert d["count"] == 0
    assert d["matches"] == []


# ---------- KB retry ----------
def test_kb_retry_admin_deletes(admin_token, clients):
    c0 = clients[0]["id"]
    # Create an entry, then call retry (regardless of status).
    csv = b"a,b\n1,2\n"
    files = {"file": ("TEST_retry.csv", io.BytesIO(csv), "text/csv")}
    data = {"client_id": c0, "kb_type": "asset"}
    r = requests.post(f"{API}/kb/upload", headers=H(admin_token), files=files, data=data, timeout=15)
    assert r.status_code == 200
    eid = r.json()["id"]
    time.sleep(1)
    r2 = requests.post(f"{API}/kb/{eid}/retry", headers=H(admin_token), timeout=15)
    assert r2.status_code == 200
    body = r2.json()
    assert body.get("deleted") is True
    assert "message" in body and "upload" in body["message"].lower()
    # verify gone
    entries = requests.get(f"{API}/kb?client_id={c0}", headers=H(admin_token)).json()
    assert not any(e["id"] == eid for e in entries)


def test_kb_retry_l1_forbidden(admin_token, l1_token, clients):
    c0 = clients[0]["id"]
    # create a throwaway entry as admin
    csv = b"a,b\n1,2\n"
    files = {"file": ("TEST_retry2.csv", io.BytesIO(csv), "text/csv")}
    data = {"client_id": c0, "kb_type": "asset"}
    r = requests.post(f"{API}/kb/upload", headers=H(admin_token), files=files, data=data, timeout=15)
    assert r.status_code == 200
    eid = r.json()["id"]
    # L1 attempt
    r2 = requests.post(f"{API}/kb/{eid}/retry", headers=H(l1_token), timeout=15)
    assert r2.status_code == 403, f"Expected 403, got {r2.status_code}"
    # cleanup as admin
    requests.post(f"{API}/kb/{eid}/retry", headers=H(admin_token), timeout=15)


# ---------- Regression touch-points ----------
def test_settings_has_threat_intel(admin_token):
    r = requests.get(f"{API}/settings", headers=H(admin_token))
    assert r.status_code == 200
    s = r.json()
    assert "threat_intel" in s, f"threat_intel missing from settings: keys={list(s.keys())}"


def test_ticket_has_verdict_in_mssp(admin_token, clients):
    off = _find_offense(admin_token, clients[0]["id"], "Ransomware Signature")
    requests.post(f"{API}/offenses/{off['id']}/investigate", headers=H(admin_token), timeout=90)
    r = requests.post(f"{API}/tickets", headers=H(admin_token),
                      json={"offense_id": off["id"], "destination": "internal"})
    assert r.status_code == 200
    t = r.json()
    mssp = t.get("mssp_report") or {}
    assert mssp.get("verdict") in ("TP", "FP", "Suspicious"), f"verdict missing: {mssp}"
    assert mssp.get("verdict_reason")


def test_coach_insights(admin_token):
    r = requests.get(f"{API}/coach/insights", headers=H(admin_token), timeout=30)
    assert r.status_code == 200
