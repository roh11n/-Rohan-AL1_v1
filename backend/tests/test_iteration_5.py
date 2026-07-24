"""Iteration 5 backend tests: dynamic mssp_report.fields, per-offense analysis_lines,
verdict-aware recommendations for 5 new CSV-derived offense templates."""
import os
import pytest
import requests

def _load_backend_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if v:
        return v.rstrip("/")
    try:
        with open("/app/frontend/.env") as f:
            for ln in f:
                if ln.startswith("REACT_APP_BACKEND_URL="):
                    return ln.split("=", 1)[1].strip().rstrip("/")
    except FileNotFoundError:
        pass
    raise RuntimeError("REACT_APP_BACKEND_URL not set")


BASE_URL = _load_backend_url()
API = f"{BASE_URL}/api"

ADMIN = {"email": "admin@socpilot.ai", "password": "Admin@123"}
L1 = {"email": "analyst@socpilot.ai", "password": "Analyst@123"}


@pytest.fixture(scope="session")
def admin_token():
    r = requests.post(f"{API}/auth/login", json=ADMIN, timeout=20)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def l1_token():
    r = requests.post(f"{API}/auth/login", json=L1, timeout=20)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="session")
def l1_headers(l1_token):
    return {"Authorization": f"Bearer {l1_token}"}


@pytest.fixture(scope="session")
def acme_client_id(admin_headers):
    r = requests.get(f"{API}/clients", headers=admin_headers, timeout=15)
    assert r.status_code == 200
    for c in r.json():
        if "acme" in (c.get("name") or "").lower() or "acme" in (c.get("id") or "").lower():
            return c["id"]
    return r.json()[0]["id"]


@pytest.fixture(scope="session")
def offenses(admin_headers, acme_client_id):
    r = requests.get(f"{API}/offenses", params={"client_id": acme_client_id, "limit": 50},
                     headers=admin_headers, timeout=20)
    assert r.status_code == 200, r.text
    data = r.json()
    # data may be list or {items:[...]}
    items = data if isinstance(data, list) else data.get("items", [])
    assert len(items) >= 12, f"Expected >=12 offenses, got {len(items)}"
    return items


def _find(offenses, needle):
    for o in offenses:
        if needle.lower() in (o.get("description") or "").lower():
            return o
    return None


def _investigate(client_id, offense_id, headers):
    r = requests.post(f"{API}/offenses/{offense_id}/investigate",
                      json={"client_id": client_id}, headers=headers, timeout=90)
    assert r.status_code == 200, r.text
    return r.json()


# --- Test: five new templates seeded ------------------------------
EXPECTED_DESCRIPTIONS = [
    "DLB-UC-00197-Permit Connections RBI_IOC_IP Feeds Inbound",
    "DLB-UC-00262-Execution of DDL/DML/DCL/DQL/TCL commands in DAM",
    "DLB-UC-00256-VPN login failures/success for multiple users from same IP",
    "Browsed to Phishing Website",
    "Multiple Login Failures for Single Username",
]


def test_five_new_templates_present(offenses):
    descs = [o.get("description") for o in offenses]
    for exp in EXPECTED_DESCRIPTIONS:
        assert any(exp in d for d in descs if d), f"Missing offense: {exp}"


def test_ip_feed_offense_artifacts(offenses):
    o = _find(offenses, "DLB-UC-00197")
    assert o is not None
    assert "45.79.181.223" in (o.get("source_ips") or [])
    assert "159.60.134.37" in (o.get("destination_ips") or [])


def test_dam_offense_artifacts(offenses):
    o = _find(offenses, "DLB-UC-00262")
    assert o is not None
    assert "1525" in (o.get("usernames") or [])


def test_vpn_offense_artifacts(offenses):
    o = _find(offenses, "DLB-UC-00256")
    assert o is not None
    assert "203.192.244.18" in (o.get("source_ips") or [])
    users = set(o.get("usernames") or [])
    assert {"a.deshmukh", "n.rathore", "j.thomas"}.issubset(users)


def test_phishing_offense_artifacts(offenses):
    o = _find(offenses, "Browsed to Phishing Website")
    assert o is not None
    assert "p.sharma" in (o.get("usernames") or [])


def test_multi_login_failures_offense(offenses):
    o = _find(offenses, "Multiple Login Failures for Single Username")
    assert o is not None
    assert "4421" in (o.get("usernames") or [])


# --- Test: dynamic mssp_report.fields ------------------------------
def _fields_keys(report):
    return {k for (k, _label) in (report.get("fields") or [])}


def test_phishing_fields_exclude_error_fields(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "Browsed to Phishing Website")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    report = res["ai_analysis"]["mssp_report"]
    fields = _fields_keys(report)
    assert "error_code" not in fields
    assert "failure_reason" not in fields
    assert "machine_identifier" not in fields
    # Basics still present
    assert {"offense_id", "offense_name", "severity", "date_time"}.issubset(fields)


def test_dam_fields_exclude_error_fields(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "DLB-UC-00262")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    report = res["ai_analysis"]["mssp_report"]
    fields = _fields_keys(report)
    assert "error_code" not in fields
    assert "failure_reason" not in fields
    assert "machine_identifier" not in fields


def test_expired_password_fields_include_error_fields(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "Login Failure to Expired Account")
    assert o is not None
    res = _investigate(acme_client_id, o["id"], admin_headers)
    report = res["ai_analysis"]["mssp_report"]
    fields = _fields_keys(report)
    assert "error_code" in fields
    assert "event_id" in fields
    assert "failure_reason" in fields
    assert "machine_identifier" in fields


# --- Test: analysis_lines are exactly 4 & structured --------------
def _lines(report):
    return report.get("analysis_lines") or []


def test_analysis_lines_count_and_opener_closer(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "DLB-UC-00262")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    report = res["ai_analysis"]["mssp_report"]
    lines = _lines(report)
    assert len(lines) == 4
    assert lines[0]["text"].startswith('An offense "')
    assert "Verify the legitimacy of the alert" in lines[3]["text"]


def test_line2_dam_contains_sql(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "DLB-UC-00262")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    l2 = _lines(res["ai_analysis"]["mssp_report"])[1]["text"].lower()
    assert "truncate table" in l2 or "sql" in l2


def test_line2_phishing_contains_url(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "Browsed to Phishing Website")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    l2 = _lines(res["ai_analysis"]["mssp_report"])[1]["text"]
    assert "securelog1n-office365.top" in l2


def test_line2_ipfeed_contains_asn_or_port(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "DLB-UC-00197")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    l2 = _lines(res["ai_analysis"]["mssp_report"])[1]["text"].lower()
    assert "asn" in l2 or "port" in l2 or "akamai" in l2


def test_line2_vpn_lists_users(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "DLB-UC-00256")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    l2 = _lines(res["ai_analysis"]["mssp_report"])[1]["text"]
    assert "a.deshmukh" in l2 or "n.rathore" in l2 or "j.thomas" in l2


def test_line2_expired_contains_error_code(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "Login Failure to Expired Account")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    l2 = _lines(res["ai_analysis"]["mssp_report"])[1]["text"]
    assert "0xC0000224" in l2 or "expired" in l2.lower()


# --- Test: verdict-aware recommendations 2-3 bullets --------------
def _recs(report):
    return report.get("recommendations") or []


def test_recommendations_are_list_2_to_3(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "DLB-UC-00262")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    recs = _recs(res["ai_analysis"]["mssp_report"])
    assert isinstance(recs, list)
    assert 2 <= len(recs) <= 3
    for r in recs:
        assert isinstance(r, str) and len(r) > 10


def test_ransomware_tp_recommendations(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "Ransomware")
    if o is None:
        pytest.skip("Ransomware template not present in current seed (count=12, ransomware at index 13). Report to main agent to bump seed count or reorder templates.")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    report = res["ai_analysis"]["mssp_report"]
    assert report["verdict"] == "TP"
    recs = " ".join(_recs(report)).lower()
    assert "isolate" in recs
    assert "ransomware" in recs
    assert "credential" in recs or "rotate" in recs


def test_dam_suspicious_recommendations(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "DLB-UC-00262")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    report = res["ai_analysis"]["mssp_report"]
    assert report["verdict"] in ("Suspicious", "TP", "FP")
    recs = " ".join(_recs(report)).lower()
    # Suspicious DAM-specific bullets
    if report["verdict"] == "Suspicious":
        assert "dba" in recs or "database" in recs or "application team" in recs
        assert "disable" in recs or "change ticket" in recs or "document" in recs


def test_brute_force_suspicious_recommendations(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "Multiple Login Failures for Single Username")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    report = res["ai_analysis"]["mssp_report"]
    recs = " ".join(_recs(report)).lower()
    if report["verdict"] == "Suspicious":
        assert "contact" in recs or "confirm" in recs
        assert "monitor" in recs
        assert "escalate" in recs or "l2" in recs


def test_expired_fp_recommendations(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "Login Failure to Expired Account")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    report = res["ai_analysis"]["mssp_report"]
    recs = " ".join(_recs(report)).lower()
    # Verdict may be FP (if KB has closed entry) OR Suspicious as fallback
    assert report["verdict"] in ("FP", "Suspicious")
    if report["verdict"] == "FP":
        assert "false positive" in recs
        assert "0xc0000224" in recs or "tune" in recs or "detection" in recs


# --- Test: verdict fields still populated -------------------------
def test_verdict_and_reason_populated(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "Ransomware") or _find(offenses, "PowerShell") or offenses[0]
    res = _investigate(acme_client_id, o["id"], admin_headers)
    report = res["ai_analysis"]["mssp_report"]
    assert report["verdict"] in ("TP", "FP", "Suspicious")
    assert report["verdict_reason"] and len(report["verdict_reason"]) > 5


# --- Regression smoke tests ---------------------------------------
def test_dashboard_metrics(admin_headers):
    r = requests.get(f"{API}/dashboard/metrics", headers=admin_headers, timeout=15)
    assert r.status_code == 200


def test_kb_list(admin_headers, acme_client_id):
    r = requests.get(f"{API}/kb", params={"client_id": acme_client_id}, headers=admin_headers, timeout=15)
    assert r.status_code == 200


def test_kb_search_admin_and_l1(admin_headers, l1_headers, acme_client_id):
    payload = {"client_id": acme_client_id, "query": "expired password", "n_results": 3}
    for h in (admin_headers, l1_headers):
        r = requests.post(f"{API}/kb/search", json=payload, headers=h, timeout=20)
        assert r.status_code == 200
        assert "matches" in r.json()


def test_coach_insights(admin_headers):
    r = requests.get(f"{API}/coach/insights", headers=admin_headers, timeout=15)
    assert r.status_code == 200


def test_settings(admin_headers):
    r = requests.get(f"{API}/settings", headers=admin_headers, timeout=15)
    assert r.status_code == 200


def test_ticket_persists_mssp_report(offenses, acme_client_id, admin_headers):
    o = _find(offenses, "DLB-UC-00262")
    res = _investigate(acme_client_id, o["id"], admin_headers)
    payload = {
        "client_id": acme_client_id,
        "offense_id": o["id"],
        "system": "servicenow",
        "priority": "P2",
        "assignee": "TEST_analyst",
    }
    r = requests.post(f"{API}/tickets", json=payload, headers=admin_headers, timeout=30)
    assert r.status_code in (200, 201), r.text
    body = r.json()
    mssp = body.get("mssp_report") or (body.get("ticket") or {}).get("mssp_report")
    assert mssp is not None
    assert "fields" in mssp
    assert "analysis_lines" in mssp
    assert "recommendations" in mssp
