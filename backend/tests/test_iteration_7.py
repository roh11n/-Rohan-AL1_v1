"""Iteration 7 tests: lifecycle endpoints (escalate/close/duplicates), theme is FE-only."""
import os
import uuid
import pytest
import requests
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv("/app/backend/.env")

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or \
    open("/app/frontend/.env").read().split("REACT_APP_BACKEND_URL=")[1].split("\n")[0].strip()
API = f"{BASE_URL}/api"

ADMIN = {"email": "admin@socpilot.ai", "password": "Admin@123"}
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


def _hdr(tok):
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(scope="module")
def sample_offenses(admin_token):
    r = requests.get(f"{API}/offenses", headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 200
    data = r.json()
    offs = data if isinstance(data, list) else data.get("offenses", [])
    assert len(offs) >= 3
    return offs


# ---------- ESCALATE ----------
def test_escalate_offense(admin_token, sample_offenses):
    off = sample_offenses[0]
    oid = off["id"]
    payload = {"client_contact": "soc@client.example", "notes": "Please review credentials leak"}
    r = requests.post(f"{API}/offenses/{oid}/escalate", json=payload,
                      headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "ESCALATED"
    assert d["escalated_by"] == ADMIN["email"]
    assert d.get("escalation_client_contact") == payload["client_contact"]
    assert d.get("escalation_notes") == payload["notes"]
    assert d.get("escalated_at")


def test_escalate_analyst_allowed(analyst_token, sample_offenses):
    off = sample_offenses[1]
    r = requests.post(f"{API}/offenses/{off['id']}/escalate",
                      json={"client_contact": "x@y", "notes": "n"},
                      headers=_hdr(analyst_token), timeout=15)
    assert r.status_code == 200, r.text


def test_escalate_404(admin_token):
    r = requests.post(f"{API}/offenses/does-not-exist/escalate",
                      json={"client_contact": "", "notes": ""},
                      headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 404


# ---------- CLOSE ----------
def test_close_offense_analyst_source(admin_token, sample_offenses):
    off = sample_offenses[2]
    oid = off["id"]
    payload = {"closure_comments": "Confirmed benign - internal scan by IT team.",
               "closure_source": "analyst"}
    r = requests.post(f"{API}/offenses/{oid}/close", json=payload,
                      headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "CLOSED"
    assert d["closure_source"] == "analyst"
    assert d["closure_comments"] == payload["closure_comments"]
    assert d["closed_by"] == ADMIN["email"]
    assert d.get("closed_at")

    # feedback record should exist
    mongo = MongoClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
    dbname = os.environ.get("DB_NAME", "socpilot_ai")
    fb = list(mongo[dbname].feedback.find({"offense_id": oid, "action": "close"}))
    assert len(fb) >= 1
    assert fb[-1].get("closure_source") == "analyst"


def test_close_offense_xsoar_source(admin_token, sample_offenses):
    off = sample_offenses[3]
    oid = off["id"]
    payload = {"closure_comments": "XSOAR playbook auto-closed after enrichment.",
               "closure_source": "xsoar"}
    r = requests.post(f"{API}/offenses/{oid}/close", json=payload,
                      headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 200
    assert r.json()["closure_source"] == "xsoar"


def test_close_404(admin_token):
    r = requests.post(f"{API}/offenses/no-such-id/close",
                      json={"closure_comments": "x", "closure_source": "analyst"},
                      headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 404


# ---------- DUPLICATES ----------
def test_duplicates_schema_when_none(admin_token, sample_offenses):
    off = sample_offenses[4]
    r = requests.get(f"{API}/offenses/{off['id']}/duplicates",
                     headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert "duplicates" in d
    assert isinstance(d["duplicates"], list)


def test_duplicates_synthesised(admin_token, sample_offenses):
    """Force a duplicate scenario via pymongo, then check the endpoint returns it."""
    mongo = MongoClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
    dbname = os.environ.get("DB_NAME", "socpilot_ai")
    coll = mongo[dbname].offenses

    # pick an OPEN offense to be the "current" one
    current = coll.find_one({"status": {"$nin": ["CLOSED"]}}, {"_id": 0})
    assert current is not None

    # inject rule/ip/user we control
    marker_rule = f"TEST_RULE_{uuid.uuid4().hex[:8]}"
    marker_ip = "10.99.88.77"
    marker_user = "TEST_dup_user"
    coll.update_one({"id": current["id"]},
                    {"$set": {"rules": [marker_rule], "source_ips": [marker_ip],
                              "usernames": [marker_user], "status": "OPEN"}})

    # create a CLOSED duplicate in same client
    dup_id = f"TEST_dup_{uuid.uuid4().hex[:8]}"
    coll.insert_one({
        "id": dup_id,
        "client_id": current["client_id"],
        "qradar_offense_id": 99999,
        "description": "TEST duplicate seed",
        "status": "CLOSED",
        "closed_at": "2026-01-01T00:00:00Z",
        "closed_by": "seed@test",
        "closure_comments": "seeded",
        "closure_source": "analyst",
        "recommendation": "close",
        "rules": [marker_rule],
        "source_ips": [marker_ip],
        "usernames": [marker_user],
    })
    try:
        r = requests.get(f"{API}/offenses/{current['id']}/duplicates",
                         headers=_hdr(admin_token), timeout=15)
        assert r.status_code == 200
        dupes = r.json()["duplicates"]
        assert any(x["id"] == dup_id for x in dupes), f"seeded dup missing: {dupes}"
        seed = next(x for x in dupes if x["id"] == dup_id)
        # schema
        for key in ("qradar_offense_id", "description", "closed_at", "closed_by",
                    "closure_comments", "closure_source", "recommendation", "overlap"):
            assert key in seed, f"missing key {key}"
        assert marker_rule in seed["overlap"]["rules"]
        assert marker_ip in seed["overlap"]["source_ips"]
        assert marker_user in seed["overlap"]["usernames"]

        # now close current with source=duplicate
        r2 = requests.post(f"{API}/offenses/{current['id']}/close",
                           json={"closure_comments": f"Duplicate of {dup_id}",
                                 "closure_source": "duplicate"},
                           headers=_hdr(admin_token), timeout=15)
        assert r2.status_code == 200
        assert r2.json()["closure_source"] == "duplicate"
        assert r2.json()["status"] == "CLOSED"
    finally:
        coll.delete_one({"id": dup_id})


def test_duplicates_404(admin_token):
    r = requests.get(f"{API}/offenses/nope/duplicates",
                     headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 404


# ---------- REGRESSION ----------
def test_dashboard_metrics(admin_token):
    r = requests.get(f"{API}/dashboard/metrics", headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 200


def test_kb_search_still_works(admin_token):
    # need a client_id
    r = requests.get(f"{API}/clients", headers=_hdr(admin_token), timeout=15)
    assert r.status_code == 200
    clients = r.json()
    if isinstance(clients, dict):
        clients = clients.get("clients", [])
    if not clients:
        pytest.skip("no clients")
    cid = clients[0]["id"]
    r = requests.post(f"{API}/kb/search",
                      json={"client_id": cid, "query": "ssh brute force"},
                      headers=_hdr(admin_token), timeout=20)
    assert r.status_code == 200


def test_offense_action_legacy_still_works(admin_token, sample_offenses):
    # ensure legacy /action endpoint still exists
    off = sample_offenses[5] if len(sample_offenses) > 5 else sample_offenses[-1]
    r = requests.post(f"{API}/offenses/{off['id']}/action",
                      json={"action": "modify", "reason": "test", "modified_recommendation": "monitor"},
                      headers=_hdr(admin_token), timeout=15)
    assert r.status_code in (200, 400)  # some actions may require specific inputs, but endpoint exists
