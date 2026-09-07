"""Iteration 13 retest: bare-marker filter + IOC enrichment for extracted IPs."""
import os, re, time, requests, pytest

BASE = os.environ.get("REACT_APP_BACKEND_URL")
if not BASE:
    for line in open("/app/frontend/.env"):
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE = line.split("=", 1)[1].strip()
BASE = BASE.rstrip("/")
API = f"{BASE}/api"

TARGET_OFFENSE = "5dd6f7e7-b005-43dd-87ca-53f23fa41422"


@pytest.fixture(scope="module")
def hdr():
    r = requests.post(f"{API}/auth/login",
                      json={"email": "admin@socpilot.ai", "password": "Admin@123"},
                      timeout=30)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _wait_llm(hdr, off_id, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        d = requests.get(f"{API}/offenses/{off_id}", headers=hdr, timeout=20)
        assert d.status_code == 200
        rep = ((d.json().get("ai_analysis") or {}).get("mssp_report")) or {}
        gen = (rep.get("generated_by") or "").lower()
        if gen.startswith("llm") and (rep.get("analysis_lines") or []):
            return rep
        time.sleep(4)
    return None


def test_retest_no_bare_marker_and_ioc(hdr):
    inv = requests.post(f"{API}/offenses/{TARGET_OFFENSE}/investigate",
                        headers=hdr, json={"engine": "llm"}, timeout=30)
    assert inv.status_code in (200, 202), inv.text
    rep = _wait_llm(hdr, TARGET_OFFENSE, 180)
    assert rep, "LLM report didn't complete"

    recs = rep.get("recommendations") or []
    rec_texts = [(r.get("text") if isinstance(r, dict) else str(r)) for r in recs]
    rec_texts = [t.strip() for t in rec_texts if t]
    print("recs:", rec_texts)

    # No bare markers (VARIABLES:, NOTES:, etc.)
    bare = re.compile(r"^[A-Z][A-Z0-9 _/&-]{1,40}:?$")
    for t in rec_texts:
        assert not bare.fullmatch(t), f"bare marker leaked: {t!r}"

    # Review-logs pointer present
    assert any(re.search(r"review\s+the\b.*log", t, re.I) for t in rec_texts), \
        "no review-logs pointer"

    # IOC enrichment populated (VT lines) for extracted external IP
    ioc = rep.get("ioc_enrichment") or {}
    lines = ioc.get("lines") or []
    print("ioc lines:", lines, "source_ip:", ioc.get("source_ip"))
    assert lines or ioc.get("source_ip"), "ioc_enrichment empty even though TI verdict claims malicious"
    # If source_ip present, ensure it matches the malicious extracted IP
    if ioc.get("source_ip"):
        assert ioc["source_ip"] == "45.155.204.199", f"unexpected source_ip: {ioc['source_ip']}"

    # Section order via keys presence
    for key in ("analysis_lines", "impact_lines", "recommendations", "verdict"):
        assert key in rep, f"{key} missing"
    print("verdict:", rep.get("verdict"))
