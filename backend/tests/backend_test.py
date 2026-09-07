"""SOCPilot AI - Backend regression tests (pytest)."""
import os
import io
import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE:
    # Fallback to reading frontend env
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE = line.split("=", 1)[1].strip().rstrip("/")

API = f"{BASE}/api"

ADMIN = {"email": "admin@socpilot.ai", "password": "Admin@123"}
L1 = {"email": "analyst@socpilot.ai", "password": "Analyst@123"}


@pytest.fixture(scope="session")
def admin_token():
    r = requests.post(f"{API}/auth/login", json=ADMIN, timeout=30)
    assert r.status_code == 200, f"Admin login failed: {r.status_code} {r.text}"
    data = r.json()
    assert "access_token" in data and data["user"]["email"] == ADMIN["email"]
    return data["access_token"]


@pytest.fixture(scope="session")
def l1_token():
    r = requests.post(f"{API}/auth/login", json=L1, timeout=30)
    assert r.status_code == 200, f"L1 login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


def H(tok): return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(scope="session")
def clients(admin_token):
    r = requests.get(f"{API}/clients", headers=H(admin_token), timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 3
    return data


# ---------- Auth ----------
def test_auth_me(admin_token):
    r = requests.get(f"{API}/auth/me", headers=H(admin_token))
    assert r.status_code == 200
    assert r.json()["email"] == ADMIN["email"]


def test_login_invalid():
    r = requests.post(f"{API}/auth/login", json={"email": "x@y.z", "password": "bad"})
    assert r.status_code == 401


# ---------- Clients ----------
def test_clients_list(clients):
    codes = {c["code"] for c in clients}
    assert {"ACME", "NOVA", "ORION"}.issubset(codes)


def test_create_client_admin(admin_token):
    payload = {"name": "TEST_Client", "code": "TESTX", "industry": "Test",
               "contact_email": "t@t.io", "description": "test"}
    r = requests.post(f"{API}/clients", headers=H(admin_token), json=payload)
    assert r.status_code == 200
    cid = r.json()["id"]
    # cleanup
    requests.delete(f"{API}/clients/{cid}", headers=H(admin_token))


def test_create_client_rbac_l1(l1_token):
    payload = {"name": "TEST_x", "code": "TESTY"}
    r = requests.post(f"{API}/clients", headers=H(l1_token), json=payload)
    assert r.status_code == 403


# ---------- Offenses ----------
def test_offenses_list_and_isolation(admin_token, clients):
    c0 = clients[0]["id"]
    r = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token))
    assert r.status_code == 200
    offs = r.json()
    assert len(offs) >= 6
    assert all(o["client_id"] == c0 for o in offs)
    # multi-tenant isolation - other clients don't leak
    c1 = clients[1]["id"]
    r2 = requests.get(f"{API}/offenses?client_id={c1}", headers=H(admin_token))
    ids0 = {o["id"] for o in offs}
    ids1 = {o["id"] for o in r2.json()}
    assert ids0.isdisjoint(ids1)


def test_offense_detail(admin_token, clients):
    c0 = clients[0]["id"]
    offs = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token)).json()
    oid = offs[0]["id"]
    r = requests.get(f"{API}/offenses/{oid}", headers=H(admin_token))
    assert r.status_code == 200
    doc = r.json()
    assert doc["id"] == oid
    assert "events" in doc


def test_investigate_offense(admin_token, clients):
    c0 = clients[0]["id"]
    offs = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token)).json()
    oid = offs[0]["id"]
    r = requests.post(f"{API}/offenses/{oid}/investigate", headers=H(admin_token), timeout=60)
    assert r.status_code == 200
    doc = r.json()
    a = doc.get("ai_analysis")
    assert a and a["risk_score"] > 0
    assert isinstance(a.get("mitre"), list)
    assert isinstance(a.get("iocs"), dict)
    assert a.get("recommended_action")
    assert a.get("executive_summary")


def test_offense_action_approve(admin_token, clients):
    c0 = clients[0]["id"]
    offs = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token)).json()
    oid = offs[1]["id"]
    r = requests.post(f"{API}/offenses/{oid}/action", headers=H(admin_token),
                      json={"action": "approve"})
    assert r.status_code == 200
    assert r.json()["status"] == "RESOLVED"


# ---------- Dashboard ----------
def test_dashboard_metrics(admin_token, clients):
    c0 = clients[0]["id"]
    r = requests.get(f"{API}/dashboard/metrics?client_id={c0}", headers=H(admin_token))
    assert r.status_code == 200
    d = r.json()
    for k in ("by_severity", "by_status", "trend_7d", "automation_rate", "false_positive_rate"):
        assert k in d


# ---------- Settings / QRadar ----------
def test_settings_admin(admin_token):
    r = requests.get(f"{API}/settings", headers=H(admin_token))
    assert r.status_code == 200
    s = r.json()
    for k in ("qradar", "llm", "xsoar", "servicenow"):
        assert k in s


def test_settings_rbac_l1(l1_token):
    r = requests.get(f"{API}/settings", headers=H(l1_token))
    assert r.status_code == 403


def test_settings_put(admin_token):
    payload = {
        "id": "global",
        "qradar": {"host": "", "api_token": "", "api_version": "12.0", "verify_ssl": False},
        "llm": {"provider": "local", "model_name": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
                "endpoint_url": "", "api_token": "", "max_tokens": 512, "temperature": 0.3,
                "enable_llm": False},
        "xsoar": {"enabled": False, "url": "", "token": "", "username": "", "project_key": "", "webhook_url": ""},
        "servicenow": {"enabled": False, "url": "", "token": "", "username": "", "project_key": "", "webhook_url": ""},
        "jira": {"enabled": False, "url": "", "token": "", "username": "", "project_key": "", "webhook_url": ""},
        "freshservice": {"enabled": False, "url": "", "token": "", "username": "", "project_key": "", "webhook_url": ""},
        "slack": {"enabled": False, "url": "", "token": "", "username": "", "project_key": "", "webhook_url": ""},
        "teams": {"enabled": False, "url": "", "token": "", "username": "", "project_key": "", "webhook_url": ""},
        "email": {"enabled": False, "url": "", "token": "", "username": "", "project_key": "", "webhook_url": ""},
    }
    r = requests.put(f"{API}/settings", headers=H(admin_token), json=payload)
    assert r.status_code == 200


def test_qradar_test_empty(admin_token):
    r = requests.post(f"{API}/qradar/test", headers=H(admin_token))
    assert r.status_code == 200
    data = r.json()
    assert data.get("ok") is False
    assert "error" in data or "message" in data or "detail" in data


# ---------- KB ----------
def test_kb_upload_returns_processing_quickly(admin_token, clients):
    import time
    c0 = clients[0]["id"]
    csv = b"asset,ip,owner\nweb-01,10.0.0.5,ops\ndb-01,10.0.0.6,dba\n"
    files = {"file": ("assets_small.csv", io.BytesIO(csv), "text/csv")}
    data = {"client_id": c0, "kb_type": "asset"}
    t0 = time.time()
    r = requests.post(f"{API}/kb/upload", headers=H(admin_token), files=files, data=data, timeout=15)
    elapsed = time.time() - t0
    assert r.status_code == 200, r.text
    entry = r.json()
    assert entry["status"] == "PROCESSING"
    assert entry["document_count"] == 0
    assert entry["content_summary"] == "(processing...)"
    assert entry["file_size_bytes"] == len(csv)
    assert elapsed < 5.0, f"Upload took {elapsed:.2f}s, expected <5s"
    # list should show it as processing immediately
    r2 = requests.get(f"{API}/kb?client_id={c0}", headers=H(admin_token))
    assert r2.status_code == 200
    match = [e for e in r2.json() if e["id"] == entry["id"]]
    assert match and match[0]["status"] in ("PROCESSING", "READY")
    # poll for READY
    deadline = time.time() + 90
    final_status = None
    while time.time() < deadline:
        time.sleep(2)
        r3 = requests.get(f"{API}/kb?client_id={c0}", headers=H(admin_token))
        m = [e for e in r3.json() if e["id"] == entry["id"]]
        if m and m[0]["status"] == "READY":
            final_status = m[0]
            break
        if m and m[0]["status"] == "FAILED":
            final_status = m[0]
            break
    assert final_status is not None, "Entry never reached terminal status"
    assert final_status["status"] == "READY", f"Ended as {final_status['status']}: {final_status.get('error')}"
    assert final_status["document_count"] > 0
    assert final_status["content_summary"] != "(processing...)"


def test_kb_upload_large_csv_fast_response(admin_token, clients):
    """Simulate 30-day alert history CSV (~300-500 KB)."""
    import time, random
    c0 = clients[0]["id"]
    rows = ["timestamp,user,source_ip,event,category,severity,analysis"]
    cats = ["auth", "malware", "recon", "exfil", "policy"]
    sevs = ["low", "medium", "high", "critical"]
    for i in range(2000):
        rows.append(
            f"2025-12-{(i%30)+1:02d}T10:00:00Z,user{i%50},10.0.{i%255}.{(i*3)%255},"
            f"event_{i},{random.choice(cats)},{random.choice(sevs)},"
            f"analysis text line {i} showing potential threat behaviour pattern observed"
        )
    csv_bytes = ("\n".join(rows)).encode()
    size = len(csv_bytes)
    assert 200_000 < size < 800_000, f"CSV size {size} out of range"
    files = {"file": ("history_30d.csv", io.BytesIO(csv_bytes), "text/csv")}
    data = {"client_id": c0, "kb_type": "historical"}
    t0 = time.time()
    r = requests.post(f"{API}/kb/upload", headers=H(admin_token), files=files, data=data, timeout=15)
    elapsed = time.time() - t0
    assert r.status_code == 200, r.text
    entry = r.json()
    assert entry["status"] == "PROCESSING"
    assert entry["file_size_bytes"] == size
    assert elapsed < 5.0, f"Large-CSV upload took {elapsed:.2f}s (must be <5s to avoid Cloudflare timeout)"
    # Poll for READY (up to 120s - first Chroma init can be slow)
    deadline = time.time() + 120
    final = None
    while time.time() < deadline:
        time.sleep(3)
        r3 = requests.get(f"{API}/kb?client_id={c0}", headers=H(admin_token))
        m = [e for e in r3.json() if e["id"] == entry["id"]]
        if m and m[0]["status"] in ("READY", "FAILED"):
            final = m[0]; break
    assert final is not None, "Large CSV never finished processing"
    assert final["status"] == "READY", f"Failed: {final.get('error')}"
    assert final["document_count"] > 0


def test_kb_upload_concurrent(admin_token, clients):
    """Upload 3 files back-to-back - all should return quickly."""
    import time
    c0 = clients[0]["id"]
    ids = []
    for i in range(3):
        csv = f"col1,col2\nrow{i}a,row{i}b\nrow{i}c,row{i}d\n".encode()
        files = {"file": (f"concur_{i}.csv", io.BytesIO(csv), "text/csv")}
        data = {"client_id": c0, "kb_type": "asset"}
        t0 = time.time()
        r = requests.post(f"{API}/kb/upload", headers=H(admin_token), files=files, data=data, timeout=15)
        assert r.status_code == 200
        assert time.time() - t0 < 5.0
        assert r.json()["status"] == "PROCESSING"
        ids.append(r.json()["id"])
    # All eventually READY
    deadline = time.time() + 120
    ready = set()
    while time.time() < deadline and len(ready) < 3:
        time.sleep(3)
        entries = requests.get(f"{API}/kb?client_id={c0}", headers=H(admin_token)).json()
        for e in entries:
            if e["id"] in ids and e["status"] == "READY":
                ready.add(e["id"])
    assert ready == set(ids), f"Only {len(ready)}/3 reached READY"


def test_kb_upload_oversized_rejects_413(admin_token, clients):
    c0 = clients[0]["id"]
    # 51 MB
    big = b"x" * (51 * 1024 * 1024)
    files = {"file": ("big.csv", io.BytesIO(big), "text/csv")}
    data = {"client_id": c0, "kb_type": "asset"}
    r = requests.post(f"{API}/kb/upload", headers=H(admin_token), files=files, data=data, timeout=60)
    assert r.status_code == 413, f"Expected 413, got {r.status_code}: {r.text[:200]}"


def test_kb_delete(admin_token, clients):
    c0 = clients[0]["id"]
    csv = b"a,b\n1,2\n"
    files = {"file": ("todelete.csv", io.BytesIO(csv), "text/csv")}
    data = {"client_id": c0, "kb_type": "asset"}
    r = requests.post(f"{API}/kb/upload", headers=H(admin_token), files=files, data=data, timeout=15)
    assert r.status_code == 200
    eid = r.json()["id"]
    d = requests.delete(f"{API}/kb/{eid}", headers=H(admin_token))
    assert d.status_code == 200
    # verify gone
    entries = requests.get(f"{API}/kb?client_id={c0}", headers=H(admin_token)).json()
    assert not any(e["id"] == eid for e in entries)


# ---------- Tickets ----------
@pytest.fixture(scope="session")
def two_tickets(admin_token, clients):
    c0 = clients[0]["id"]
    offs = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token)).json()
    ticket_ids = []
    for o in offs[2:4]:
        # ensure investigated
        requests.post(f"{API}/offenses/{o['id']}/investigate", headers=H(admin_token), timeout=60)
        r = requests.post(f"{API}/tickets", headers=H(admin_token),
                          json={"offense_id": o["id"], "destination": "internal"})
        assert r.status_code == 200, r.text
        t = r.json()
        assert t["status"] == "PENDING_APPROVAL"
        ticket_ids.append(t["id"])
    return ticket_ids


def test_ticket_created(two_tickets):
    assert len(two_tickets) == 2


def test_ticket_approve(admin_token, two_tickets):
    tid = two_tickets[0]
    r = requests.post(f"{API}/tickets/{tid}/approve", headers=H(admin_token),
                      json={"approved": True})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "PUSHED"
    assert d.get("external_ref", "").startswith("MOCK-")


def test_ticket_merge(admin_token, clients):
    # Create 2 fresh tickets from other offenses to merge
    c0 = clients[0]["id"]
    offs = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token)).json()
    tids = []
    for o in offs[4:6]:
        r = requests.post(f"{API}/tickets", headers=H(admin_token),
                          json={"offense_id": o["id"], "destination": "internal"})
        assert r.status_code == 200
        tids.append(r.json()["id"])
    r = requests.post(f"{API}/tickets/merge", headers=H(admin_token),
                     json={"ticket_ids": tids, "title": "TEST_merged"})
    assert r.status_code == 200
    parent = r.json()
    assert parent["status"] == "PENDING_APPROVAL"
    # verify originals are MERGED
    tlist = requests.get(f"{API}/tickets?client_id={c0}", headers=H(admin_token)).json()
    for t in tlist:
        if t["id"] in tids:
            assert t["status"] == "MERGED"


# ---------- Audit ----------
def test_audit_list(admin_token):
    r = requests.get(f"{API}/audit", headers=H(admin_token))
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ---------- Users ----------
def test_user_crud(admin_token):
    payload = {"email": "TEST_user@socpilot.ai", "name": "Test", "password": "Pass@123", "role": "L1"}
    r = requests.post(f"{API}/users", headers=H(admin_token), json=payload)
    if r.status_code == 400 and "exists" in r.text.lower():
        # find & delete first
        users = requests.get(f"{API}/users", headers=H(admin_token)).json()
        for u in users:
            if u["email"] == payload["email"]:
                requests.delete(f"{API}/users/{u['id']}", headers=H(admin_token))
        r = requests.post(f"{API}/users", headers=H(admin_token), json=payload)
    assert r.status_code == 200
    uid = r.json()["id"]
    # duplicate
    r2 = requests.post(f"{API}/users", headers=H(admin_token), json=payload)
    assert r2.status_code == 400
    # cleanup
    requests.delete(f"{API}/users/{uid}", headers=H(admin_token))


# ---------- RBAC: L1 investigate is allowed ----------
def test_l1_can_investigate(l1_token, admin_token, clients):
    c0 = clients[0]["id"]
    offs = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token)).json()
    oid = offs[0]["id"]
    r = requests.post(f"{API}/offenses/{oid}/investigate", headers=H(l1_token), timeout=60)
    assert r.status_code == 200
