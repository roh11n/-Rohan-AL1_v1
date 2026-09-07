"""Tests for L1 Analyst mssp_report format on offenses and tickets."""
import os
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


def H(tok): return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{API}/auth/login", json=ADMIN, timeout=30)
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def clients(admin_token):
    r = requests.get(f"{API}/clients", headers=H(admin_token), timeout=15)
    assert r.status_code == 200
    return r.json()


@pytest.fixture(scope="module")
def expired_offense(admin_token, clients):
    """Find the 'Login Failure to Expired Account' offense in first client."""
    c0 = clients[0]["id"]
    r = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token))
    assert r.status_code == 200
    offs = r.json()
    match = [o for o in offs if "Expired" in (o.get("description") or "")]
    assert match, f"No expired-account offense found in client {c0}. Found: {[o.get('description') for o in offs]}"
    return match[0]


# ------- Sample offense seeding -------
def test_expired_offense_seeded(expired_offense):
    o = expired_offense
    assert o["source_ips"] == ["172.17.51.168"], f"src_ips={o.get('source_ips')}"
    assert o["destination_ips"] == ["172.17.51.7"], f"dst_ips={o.get('destination_ips')}"
    assert "6936" in (o.get("usernames") or []), f"usernames={o.get('usernames')}"
    assert o.get("severity_label") == "Medium"


def test_offense_count_per_client_is_8(admin_token, clients):
    c0 = clients[0]["id"]
    offs = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token)).json()
    assert len(offs) >= 8, f"Expected >=8 offenses, got {len(offs)}"


# ------- Investigate returns mssp_report -------
@pytest.fixture(scope="module")
def investigated(admin_token, expired_offense):
    oid = expired_offense["id"]
    r = requests.post(f"{API}/offenses/{oid}/investigate", headers=H(admin_token), timeout=90)
    assert r.status_code == 200, r.text
    return r.json()


def test_mssp_report_fields(investigated):
    a = investigated.get("ai_analysis") or {}
    rep = a.get("mssp_report")
    assert rep, f"mssp_report missing. ai_analysis keys={list(a.keys())}"
    assert rep.get("source_ip") == "172.17.51.168"
    assert rep.get("destination_ip") == "172.17.51.7"
    assert rep.get("username") == "6936"
    assert "account failed to log on" in (rep.get("event_name") or "").lower()
    assert rep.get("low_level_category") == "User Login Failure"
    assert rep.get("error_code") == "0xC0000224"
    assert rep.get("event_id") == "4625"
    assert "password has expired" in (rep.get("failure_reason") or "").lower()
    assert rep.get("machine_identifier") == "PRDN-SSOAPP1"
    assert rep.get("log_source") == "PRD-DC-PDCAD @ 172.17.51.7"
    assert rep.get("offense_id")
    assert rep.get("offense_name")
    assert rep.get("severity")
    assert rep.get("date_time")


def test_mssp_analysis_lines(investigated):
    rep = investigated["ai_analysis"]["mssp_report"]
    lines = rep.get("analysis_lines")
    assert isinstance(lines, list) and len(lines) == 4
    for ln in lines:
        assert "n" in ln and "text" in ln
    l1 = lines[0]["text"].lower()
    assert "multiple failed logins" in l1
    assert "6936" in lines[0]["text"]
    assert "172.17.51.168" in lines[0]["text"]
    assert "prd-dc-pdcad" in l1
    assert "password" in lines[1]["text"].lower() and "expired" in lines[1]["text"].lower()
    assert "success" in lines[2]["text"].lower()
    assert "legitimacy" in lines[3]["text"].lower()


def test_mssp_recommendation(investigated):
    rep = investigated["ai_analysis"]["mssp_report"]
    rec = rep.get("recommendation_text")
    assert isinstance(rec, str) and len(rec) > 0


# ------- Tickets carry mssp_report -------
def test_ticket_from_investigated_has_mssp(admin_token, expired_offense, investigated):
    oid = expired_offense["id"]
    r = requests.post(f"{API}/tickets", headers=H(admin_token),
                      json={"offense_id": oid, "destination": "internal"})
    assert r.status_code == 200, r.text
    t = r.json()
    assert t.get("mssp_report"), f"Ticket missing mssp_report keys={list(t.keys())}"
    assert t["mssp_report"]["source_ip"] == "172.17.51.168"
    assert t["mssp_report"]["username"] == "6936"


def test_ticket_from_uninvestigated_falls_back(admin_token, clients):
    """Pick an offense that has not been investigated yet."""
    c0 = clients[0]["id"]
    offs = requests.get(f"{API}/offenses?client_id={c0}", headers=H(admin_token)).json()
    # find one that isn't the expired one and has no ai_analysis
    target = None
    for o in offs:
        detail = requests.get(f"{API}/offenses/{o['id']}", headers=H(admin_token)).json()
        if not detail.get("ai_analysis") and "Expired" not in (o.get("description") or ""):
            target = detail
            break
    if not target:
        pytest.skip("No uninvestigated offense available for fallback test")
    r = requests.post(f"{API}/tickets", headers=H(admin_token),
                      json={"offense_id": target["id"], "destination": "internal"})
    assert r.status_code == 200, r.text
    t = r.json()
    assert t.get("mssp_report"), "Fallback mssp_report missing on ticket"
    rep = t["mssp_report"]
    # Must at least have core structural fields populated
    for k in ("offense_id", "offense_name", "severity", "analysis_lines", "recommendation_text"):
        assert rep.get(k) is not None, f"Missing {k} in fallback mssp_report"


# ------- Regression -------
def test_coach_insights(admin_token, clients):
    c0 = clients[0]["id"]
    r = requests.get(f"{API}/coach/insights?client_id={c0}", headers=H(admin_token))
    assert r.status_code == 200


def test_settings_has_threat_intel(admin_token):
    r = requests.get(f"{API}/settings", headers=H(admin_token))
    assert r.status_code == 200
    s = r.json()
    assert "threat_intel" in s, f"threat_intel missing. keys={list(s.keys())}"
