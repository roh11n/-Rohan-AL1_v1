"""Backend regression: verify investigate produces LLM report with new sections."""
import os
import time
import requests
import pytest

def _load_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if v:
        return v.rstrip("/")
    for p in ("/app/frontend/.env",):
        try:
            for line in open(p):
                if line.startswith("REACT_APP_BACKEND_URL="):
                    return line.split("=", 1)[1].strip().rstrip("/")
        except Exception:
            pass
    raise RuntimeError("REACT_APP_BACKEND_URL not set")

BASE_URL = _load_url()
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{API}/auth/login", json={"email": "admin@socpilot.ai", "password": "Admin@123"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def hdr(token):
    return {"Authorization": f"Bearer {token}"}


def test_login(hdr):
    r = requests.get(f"{API}/auth/me", headers=hdr)
    assert r.status_code == 200


def test_offenses_list_and_investigate(hdr):
    # Pick ACME tenant (has KB match imported per context)
    tr = requests.get(f"{API}/clients", headers=hdr)
    assert tr.status_code == 200
    tenants = tr.json()
    acme = next((t for t in tenants if "acme" in (t.get("name","" ) + t.get("slug","")).lower()), tenants[0])
    client_id = acme.get("id") or acme.get("_id")
    r = requests.get(f"{API}/offenses", headers=hdr, params={"client_id": client_id})
    assert r.status_code == 200
    offenses = r.json()
    assert len(offenses) > 0
    # Prefer the CTI offense mentioned in context
    target = next((o for o in offenses if "CTI" in (o.get("offense_name") or o.get("name") or "").upper()
                   or "CTI" in (o.get("rule_name") or "").upper()), offenses[0])
    off_id = target.get("id") or target.get("_id") or target.get("offense_id")
    # Trigger investigate
    inv = requests.post(f"{API}/offenses/{off_id}/investigate",
                        headers=hdr, json={"engine": "llm"})
    assert inv.status_code in (200, 202), inv.text
    # Poll for completion up to 150s
    report = None
    deadline = time.time() + 150
    while time.time() < deadline:
        d = requests.get(f"{API}/offenses/{off_id}", headers=hdr)
        assert d.status_code == 200
        rep = ((d.json().get("ai_analysis") or {}).get("mssp_report")) or {}
        gen = (rep.get("generated_by") or "").lower()
        if gen.startswith("llm") and (rep.get("analysis_lines") or []):
            report = rep
            break
        time.sleep(4)
    assert report is not None, "LLM report did not complete in 150s"
    # Log source must not be CRE
    ls = (report.get("log_source") or "").lower()
    assert "custom rule engine" not in ls and ls.strip() != "cre", f"log_source is CRE: {report.get('log_source')}"
    # Sections
    assert (report.get("analysis_lines") or []), "analysis_lines empty"
    assert (report.get("impact_lines") or []) or (report.get("impact") or ""), "impact missing"
    assert (report.get("recommendations") or []) or (report.get("recommendation_text") or ""), "recs missing"
    ioc = report.get("ioc_enrichment") or {}
    assert (ioc.get("lines") or []) or ioc.get("vt_url"), "IOC enrichment missing"
    assert report.get("verdict"), "verdict missing"
    # Ensure no comparison verbiage
    joined = " ".join([l.get("text","") for l in report.get("analysis_lines") or []]).lower()
    for banned in ["similar incident", "historical", "previous offense", "compared to other"]:
        assert banned not in joined, f"analysis mentions '{banned}'"
    print("REPORT OK:", report.get("generated_by"), report.get("log_source"), report.get("verdict"))
