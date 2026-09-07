"""
Iteration 14: KB consolidation / learned-knowledge tests.
Covers:
 - 00316 Outbound => kb-template immediate w/ kb_learning meta (6 tickets, 100%),
   grounded IPs, block/investigate recs, no review-logs pointer, no USB.
 - 00316 Outbound => after LLM completes, source==llm, kb_learning intact,
   grounded bullets, no inbound wording, verdict TP/FP/Suspicious, no auto pointer.
 - 00317 Inbound must NOT match Outbound KB (rule-engine, no kb_learning).
 - PowerShell single-row use case => kb_learning.ticket_count == 1, grounded,
   after LLM: clean impact/recs (no imperative block/isolate in impact, no junk).
"""
import os, re, time
import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "https://socpilot-local.preview.emergentagent.com").rstrip("/")
ADMIN = {"email": "admin@socpilot.ai", "password": "Admin@123"}


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE}/api/auth/login", json=ADMIN, timeout=20)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def acme_id(headers):
    r = requests.get(f"{BASE}/api/clients", headers=headers, timeout=20)
    assert r.status_code == 200
    for c in r.json():
        if str(c.get("id", "")).startswith("faa7fdb9"):
            return c["id"]
    pytest.skip("ACME client not found (faa7fdb9*)")


@pytest.fixture(scope="module")
def offenses(headers, acme_id):
    r = requests.get(f"{BASE}/api/offenses", params={"client_id": acme_id}, headers=headers, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()


def _find(offenses, prefix):
    for o in offenses:
        if str(o.get("description", "")).startswith(prefix):
            return o
    return None


def _find_contains(offenses, needle):
    for o in offenses:
        if needle in str(o.get("description", "")):
            return o
    return None


REVIEW_RE = re.compile(r"Review the .* logs and correlate the surrounding events", re.I)


def _txt(x):
    """Bullet may be str or {'text': ...}."""
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return x.get("text") or ""
    return str(x)


def _texts(lst):
    return _texts(lst or [])


def _investigate(headers, oid):
    r = requests.post(f"{BASE}/api/offenses/{oid}/investigate", headers=headers, timeout=60)
    assert r.status_code == 200, r.text
    return r.json()


def _poll_llm(headers, oid, timeout=240):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        r = requests.get(f"{BASE}/api/offenses/{oid}", headers=headers, timeout=30)
        if r.status_code == 200:
            data = r.json()
            ai = data.get("ai_analysis") or {}
            last = ai
            if ai.get("llm_status") == "done":
                return data
            if ai.get("llm_status") == "error":
                pytest.fail(f"LLM error: {ai.get('llm_error')}")
        time.sleep(6)
    pytest.fail(f"LLM did not complete in {timeout}s. Last llm_status={last.get('llm_status') if last else None}")


# --- Test 1: 00316 Outbound instant kb-template ---

def test_00316_outbound_kb_template_immediate(headers, offenses):
    off = _find(offenses, "IND-UC-00316-Permit Connections CTI_IP Feeds Outbound")
    assert off, "00316 Outbound offense not found in ACME"
    resp = _investigate(headers, off["id"])
    ai = resp.get("ai_analysis") or {}
    assert ai.get("mssp_report_source") == "kb-template", f"source={ai.get('mssp_report_source')}"
    rpt = ai.get("mssp_report") or {}
    kbl = rpt.get("kb_learning") or {}
    assert kbl.get("ticket_count") == 6, kbl
    assert kbl.get("match_score") == 100, kbl
    vc = kbl.get("verdict_counts") or {}
    assert vc.get("TP") == 6, vc
    assert kbl.get("alert_name"), kbl

    analysis_text = " ".join(_txt(b) for b in (rpt.get("analysis_lines") or []))
    assert "10.13.122.218" in analysis_text, f"missing src IP in analysis: {analysis_text[:400]}"
    assert "162.159.134.233" in analysis_text, f"missing dst IP in analysis: {analysis_text[:400]}"

    recs = [ _txt(r) for r in (rpt.get("recommendations") or []) ]
    assert any("Block" in r and "162.159.134.233" in r for r in recs), recs
    assert any("Investigate" in r and "10.13.122.218" in r for r in recs), recs
    assert not any(REVIEW_RE.search(r) for r in recs), f"review-logs pointer present: {recs}"

    all_text = analysis_text + " " + " ".join(recs) + " " + " ".join(_txt(b) for b in (rpt.get("impact_lines") or []))
    assert "USB" not in all_text.upper().split(), None  # loose check; also
    assert " USB " not in " " + all_text + " ", f"USB sentence leaked: {all_text}"


# --- Test 2: 00316 Outbound LLM completion ---

def test_00316_outbound_llm_completes_clean(headers, offenses):
    off = _find(offenses, "IND-UC-00316-Permit Connections CTI_IP Feeds Outbound")
    assert off
    _investigate(headers, off["id"])
    data = _poll_llm(headers, off["id"], timeout=240)
    ai = data.get("ai_analysis") or {}
    assert ai.get("mssp_report_source") == "llm", ai.get("mssp_report_source")
    rpt = ai.get("mssp_report") or {}
    gen_by = ai.get("generated_by") or rpt.get("generated_by") or ""
    assert str(gen_by).startswith("llm:"), gen_by
    kbl = rpt.get("kb_learning") or {}
    assert kbl.get("ticket_count") == 6, kbl
    def _has_ip(t): return "10.13.122.218" in t or "162.159.134.233" in t
    grounded_total = sum(1 for b in (rpt.get("analysis_lines") or []) if _has_ip(_txt(b))) + \
                     sum(1 for r in (rpt.get("recommendations") or []) if _has_ip(_txt(r)))
    assert grounded_total >= 2, f"llm_grounded_bullets(inferred)={grounded_total}"

    an_lines = rpt.get("analysis_lines") or []
    assert an_lines, "no analysis lines"
    first_txt = (an_lines[0].get("text") or "")
    grounded_count = sum(1 for b in an_lines if "10.13.122.218" in _txt(b) or "162.159.134.233" in _txt(b))
    assert first_txt.startswith("The alert 'IND-UC-00316") or grounded_count >= 2, \
        f"first={first_txt!r}, grounded_count={grounded_count}"

    imp = rpt.get("impact_lines") or []
    assert imp, "impact empty"

    _echoed = re.compile(r"^(Port Number|User-Agent|Proxy Server|DNS Server|Source IP|Destination IP|Username|Host|Process|Log Source|Command Line|Protocol|Domain|URL)\s*:\s*", re.I)
    recs = [_txt(r) for r in (rpt.get("recommendations") or [])]
    assert 3 <= len(recs) <= 6, f"rec count {len(recs)}: {recs}"
    for r in recs:
        assert not r.strip().lower().startswith("source ip:"), r
        assert not _echoed.match(r.strip()), f"echoed artifact rec: {r!r}"
        assert "ARTIFACTS OF THIS OFFENSE" not in r.upper(), r
        assert not REVIEW_RE.search(r), r

    for b in an_lines:
        assert "inbound" not in _txt(b).lower(), b

    verdict = (rpt.get("verdict") or ai.get("verdict") or "").upper()
    assert verdict in {"TP", "FP", "SUSPICIOUS"}, verdict
    vreason = rpt.get("verdict_reason") or ai.get("verdict_reason") or ""
    assert not vreason.startswith("*"), f"verdict_reason starts with *: {vreason!r}"


# --- Test 3: 00317 Inbound must not match Outbound KB ---

def test_00317_inbound_does_not_match_outbound_kb(headers, offenses):
    off = _find(offenses, "IND-UC-00317-Permit Connections CTI_IP Feeds Inbound")
    assert off, "00317 Inbound offense not found in ACME"
    resp = _investigate(headers, off["id"])
    ai = resp.get("ai_analysis") or {}
    src = ai.get("mssp_report_source")
    assert src != "kb-template", f"should NOT be kb-template, got {src}"
    rpt = ai.get("mssp_report") or {}
    kbl = rpt.get("kb_learning")
    assert not kbl, f"kb_learning should be absent/null, got {kbl}"


# --- Test 4: PowerShell single-row KB, then LLM ---

def test_powershell_kb_and_llm(headers, offenses):
    off = _find_contains(offenses, "Suspicious PowerShell Encoded Command Execution")
    assert off, "PowerShell offense not found"
    resp = _investigate(headers, off["id"])
    ai = resp.get("ai_analysis") or {}
    assert ai.get("mssp_report_source") == "kb-template", ai.get("mssp_report_source")
    rpt = ai.get("mssp_report") or {}
    kbl = rpt.get("kb_learning") or {}
    assert kbl.get("ticket_count") == 1, kbl
    recs_text = " ".join(_txt(r) for r in (rpt.get("recommendations") or []))
    assert "powershell.exe" in recs_text.lower(), recs_text

    data = _poll_llm(headers, off["id"], timeout=240)
    ai = data.get("ai_analysis") or {}
    rpt = ai.get("mssp_report") or {}
    imp = [_txt(b) for b in (rpt.get("impact_lines") or [])]
    for b in imp:
        low = b.lower()
        assert not re.match(r"^\s*(block|isolate|collect the host)\b", low), f"imperative in impact: {b}"

    all_bul = imp + [_txt(b) for b in (rpt.get("analysis_lines") or [])] + \
              [_txt(r) for r in (rpt.get("recommendations") or [])]
    for b in all_bul:
        s = b.strip()
        assert not s.startswith("Report:"), b
        assert not s.startswith("Type: Critical"), b
        assert "Critical Severity:" not in s, b
