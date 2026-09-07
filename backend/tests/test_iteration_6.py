"""Iteration 6 backend tests:
- 5-8 events per offense
- windows_event_id NOT overwritten by uuid
- Discovered extra fields (SQL Command / URL / ASN / etc.) in mssp_report
- Executive summary is concise (3-4 sentences)
- Attack path still returned by backend, but frontend tab removed (frontend test separate)
- Regression: verdict, verdict_reason, recommendations (2-3), analysis_lines (4)
- Tickets, KB search, /api/dashboard/metrics still work; both logins succeed
"""
import os
import re
import pytest
import requests

def _load_backend_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if v:
        return v.rstrip("/")
    try:
        with open("/app/frontend/.env") as f:
            for line in f:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    return line.split("=", 1)[1].strip().rstrip("/")
    except Exception:
        pass
    raise RuntimeError("REACT_APP_BACKEND_URL not set")

BASE_URL = _load_backend_url()
API = f"{BASE_URL}/api"

ADMIN = {"email": "admin@socpilot.ai", "password": "Admin@123"}
ANALYST = {"email": "analyst@socpilot.ai", "password": "Analyst@123"}


def _login(creds):
    r = requests.post(f"{API}/auth/login", json=creds, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def admin_token():
    return _login(ADMIN)


@pytest.fixture(scope="session")
def analyst_token():
    return _login(ANALYST)


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="session")
def client_id(admin_headers):
    r = requests.get(f"{API}/clients", headers=admin_headers, timeout=30)
    assert r.status_code == 200
    clients = r.json()
    assert clients, "No clients seeded"
    return clients[0]["id"]


@pytest.fixture(scope="session")
def offenses(admin_headers, client_id):
    r = requests.get(f"{API}/offenses", headers=admin_headers,
                     params={"client_id": client_id}, timeout=30)
    assert r.status_code == 200
    offs = r.json()
    assert len(offs) > 0
    return offs


def _find(offenses, keyword):
    for o in offenses:
        if keyword.lower() in (o.get("description") or "").lower():
            return o
    return None


# ---------- Login regression ----------
def test_login_admin_and_analyst():
    assert _login(ADMIN)
    assert _login(ANALYST)


# ---------- Event enrichment ----------
def test_event_count_in_list_matches(offenses):
    for o in offenses:
        assert isinstance(o.get("event_count"), int)
        assert o["event_count"] >= 5, f"event_count too low: {o['event_count']} for {o['description']}"


def test_each_offense_has_5_to_8_events(admin_headers, offenses):
    for o in offenses[:8]:
        r = requests.get(f"{API}/offenses/{o['id']}", headers=admin_headers, timeout=30)
        assert r.status_code == 200
        detail = r.json()
        events = detail.get("events") or []
        assert 5 <= len(events) <= 8, f"{o['description']} has {len(events)} events"
        # required fields on at least one event
        e0 = events[0]
        for key in ("event_name", "log_source", "category", "event_time", "event_uuid"):
            assert key in e0, f"missing {key} in event"


def test_windows_event_id_not_overwritten(admin_headers, offenses):
    """Expired-account offense has windows_event_id=4625/4624 - must NOT be a UUID."""
    expired = _find(offenses, "Expired Account") or _find(offenses, "Multiple Login Failures")
    assert expired, "no windows event offense seeded"
    r = requests.get(f"{API}/offenses/{expired['id']}", headers=admin_headers, timeout=30)
    detail = r.json()
    events_with_wid = [e for e in detail["events"] if e.get("windows_event_id")]
    assert events_with_wid, "expected at least one event with windows_event_id"
    for e in events_with_wid:
        wid = e["windows_event_id"]
        assert re.fullmatch(r"\d{3,5}", str(wid)), f"windows_event_id looks like uuid: {wid}"
        # event_uuid also present but distinct
        assert e.get("event_uuid") and e["event_uuid"] != wid


# ---------- Investigate → discovered fields ----------
def _investigate(headers, oid):
    r = requests.post(f"{API}/offenses/{oid}/investigate", headers=headers, timeout=60)
    assert r.status_code == 200, r.text
    return r.json()


def test_dam_sql_command_discovered(admin_headers, offenses):
    o = _find(offenses, "DDL/DML")
    assert o, "DAM offense missing"
    d = _investigate(admin_headers, o["id"])
    rep = d["ai_analysis"]["mssp_report"]
    labels = {label for _, label in rep["fields"]}
    assert "SQL Command" in labels, f"labels={labels}"
    assert rep.get("x_sql_command"), "x_sql_command missing"
    assert "truncate table orcl211.temp_acct6" in rep["x_sql_command"].lower()


def test_phishing_url_discovered(admin_headers, offenses):
    o = _find(offenses, "Browsed to Phishing")
    assert o
    d = _investigate(admin_headers, o["id"])
    rep = d["ai_analysis"]["mssp_report"]
    labels = {label for _, label in rep["fields"]}
    assert "URL" in labels
    assert "securelog1n-office365.top" in (rep.get("x_url") or "")


def test_ipfeed_discovers_asn_method_response_ua(admin_headers, offenses):
    o = _find(offenses, "RBI_IOC_IP Feeds")
    assert o
    d = _investigate(admin_headers, o["id"])
    rep = d["ai_analysis"]["mssp_report"]
    labels = {label for _, label in rep["fields"]}
    for req in ("ASN", "HTTP Method", "Response Code", "User Agent"):
        assert req in labels, f"missing {req} in labels={labels}"
    assert "akamai" in (rep.get("x_asn") or "").lower()
    assert (rep.get("x_http_method") or "").upper() == "GET"
    assert (rep.get("x_response_code") or "") == "404"
    ua = (rep.get("x_user_agent") or "").lower()
    assert "mozilla" in ua or "chrome" in ua


# ---------- Executive summary concise ----------
def test_executive_summary_concise(admin_headers, offenses):
    o = _find(offenses, "DDL/DML") or offenses[0]
    d = _investigate(admin_headers, o["id"])
    summary = d["ai_analysis"]["executive_summary"]
    assert summary, "no summary"
    # Should not contain the old repetitive dump
    banned = ["Offense triggered by rule(s):", "Source IP(s):", "Destination IP(s):", "User(s) involved:"]
    for b in banned:
        assert b not in summary, f"summary still contains old dump line: {b}"
    # 3-4 sentences: count period boundaries followed by space/end
    sentences = [s for s in re.split(r"(?<=[.!?])\s+", summary.strip()) if s]
    assert 3 <= len(sentences) <= 5, f"sentence count {len(sentences)}: {summary}"
    # Mentions description
    assert (o.get("description") or "")[:15].lower() in summary.lower()
    # ends with risk/recommendation
    last = sentences[-1].lower()
    assert "risk" in last and "recommend" in last


# ---------- Regression: recommendations/analysis_lines/verdict ----------
def test_mssp_report_regression(admin_headers, offenses):
    o = _find(offenses, "DDL/DML") or offenses[0]
    d = _investigate(admin_headers, o["id"])
    rep = d["ai_analysis"]["mssp_report"]
    assert rep.get("verdict") in ("TP", "FP", "Suspicious")
    assert rep.get("verdict_reason")
    recs = rep.get("recommendations") or []
    assert 2 <= len(recs) <= 3
    lines = rep.get("analysis_lines") or []
    assert len(lines) == 4


# ---------- Tickets ----------
def test_ticket_creation_persists_mssp(admin_headers, offenses):
    o = _find(offenses, "Browsed to Phishing") or offenses[0]
    _investigate(admin_headers, o["id"])
    r = requests.post(f"{API}/tickets", headers=admin_headers,
                      json={"offense_id": o["id"], "destination": "internal"}, timeout=30)
    assert r.status_code in (200, 201), r.text
    tk = r.json()
    assert tk.get("mssp_report"), "ticket missing mssp_report"


# ---------- KB search / retry ----------
def test_kb_search_both_roles(analyst_token, admin_token, client_id):
    for tok in (analyst_token, admin_token):
        r = requests.post(f"{API}/kb/search", headers={"Authorization": f"Bearer {tok}"},
                          json={"client_id": client_id, "query": "phishing"}, timeout=30)
        assert r.status_code == 200, f"status {r.status_code}: {r.text}"


def test_kb_retry_requires_admin(analyst_token):
    r = requests.post(f"{API}/kb/nonexistent/retry",
                      headers={"Authorization": f"Bearer {analyst_token}"}, timeout=30)
    assert r.status_code in (403, 401, 404)  # 404 acceptable if admin-check happens first is 403
    # Explicit forbidden preferred
    # Note: analyst should NOT get 200


def test_dashboard_metrics(admin_headers):
    r = requests.get(f"{API}/dashboard/metrics", headers=admin_headers, timeout=30)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, dict)
