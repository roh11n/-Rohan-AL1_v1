"""
Iteration 15 (retest of iteration_5 fail): LLM grounding for KB-consolidated Outbound offense.

Runs 00316 Outbound investigate twice (non-deterministic LLM), plus 00317 Inbound
regression + PowerShell regression. Rate-limit aware: ~6 investigate calls total.
"""
import os
import re
import time

import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "https://socpilot-local.preview.emergentagent.com").rstrip("/")
ADMIN = {"email": "admin@socpilot.ai", "password": "Admin@123"}

REVIEW_RE = re.compile(r"Review the .* logs and correlate the surrounding events", re.I)
ECHOED_RE = re.compile(
    r"^(Port Number|User-Agent|Proxy Server|DNS Server|Source IP|Destination IP|"
    r"Username|Host|Process|Log Source|Command Line|Protocol|Domain|URL)\s*:\s*",
    re.I,
)


def _txt(x):
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return x.get("text") or ""
    return str(x)


@pytest.fixture(scope="module")
def headers():
    r = requests.post(f"{BASE}/api/auth/login", json=ADMIN, timeout=20)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def acme_id(headers):
    r = requests.get(f"{BASE}/api/clients", headers=headers, timeout=20)
    assert r.status_code == 200
    for c in r.json():
        if str(c.get("id", "")).startswith("faa7fdb9"):
            return c["id"]
    pytest.skip("ACME client not found")


@pytest.fixture(scope="module")
def offenses(headers, acme_id):
    r = requests.get(f"{BASE}/api/offenses", params={"client_id": acme_id}, headers=headers, timeout=30)
    assert r.status_code == 200
    return r.json()


def _find(offs, needle):
    for o in offs:
        if needle in str(o.get("description", "")):
            return o
    return None


def _investigate(headers, oid):
    r = requests.post(f"{BASE}/api/offenses/{oid}/investigate", headers=headers, timeout=60)
    assert r.status_code == 200, r.text
    return r.json()


def _poll_llm(headers, oid, timeout=200):
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
    pytest.fail(f"LLM did not complete in {timeout}s. Last status={last.get('llm_status') if last else None}")


def _assert_llm_invariants_00316(data, run_label):
    ai = data.get("ai_analysis") or {}
    src = ai.get("mssp_report_source")
    assert src == "llm", f"[{run_label}] mssp_report_source={src}"

    rpt = ai.get("mssp_report") or {}
    gen_by = ai.get("generated_by") or rpt.get("generated_by") or ""
    assert str(gen_by).startswith("llm:"), f"[{run_label}] generated_by={gen_by!r}"

    kbl = rpt.get("kb_learning") or {}
    assert kbl.get("ticket_count") == 6, f"[{run_label}] kb_learning={kbl}"

    def has_ip(t):
        return "10.13.122.218" in t or "162.159.134.233" in t

    an_lines = rpt.get("analysis_lines") or []
    recs = [_txt(r) for r in (rpt.get("recommendations") or [])]

    grounded_analysis = sum(1 for b in an_lines if has_ip(_txt(b)))
    assert grounded_analysis >= 2, (
        f"[{run_label}] grounded analysis bullets={grounded_analysis}: "
        f"{[_txt(b) for b in an_lines]}"
    )

    # llm_grounded_bullets metric (report-level count of grounded bullets)
    llm_grounded = ai.get("llm_grounded_bullets") or rpt.get("llm_grounded_bullets")
    if llm_grounded is not None:
        assert llm_grounded >= 2, f"[{run_label}] llm_grounded_bullets={llm_grounded}"

    # Recommendations: 3-6 items, grounded where they refer to external IP / source host
    assert 3 <= len(recs) <= 6, f"[{run_label}] rec count {len(recs)}: {recs}"
    external_ip_recs = [r for r in recs if re.search(r"external ip|block", r, re.I)]
    if external_ip_recs:
        assert any("162.159.134.233" in r for r in external_ip_recs), (
            f"[{run_label}] external-IP rec missing IP: {external_ip_recs}"
        )
    source_host_recs = [r for r in recs if re.search(r"source host|investigate.*host", r, re.I)]
    if source_host_recs:
        assert any("10.13.122.218" in r for r in source_host_recs), (
            f"[{run_label}] source-host rec missing IP: {source_host_recs}"
        )

    # No echoed artifact bullets
    for r in recs:
        s = r.strip()
        assert not ECHOED_RE.match(s), f"[{run_label}] echoed artifact rec: {r!r}"
        assert not s.endswith(":"), f"[{run_label}] rec ends with bare colon: {r!r}"
        assert "ARTIFACTS OF THIS OFFENSE" not in r.upper(), f"[{run_label}] {r}"
        assert not REVIEW_RE.search(r), f"[{run_label}] review-logs pointer: {r}"

    # No "inbound" in analysis of Outbound offense
    for b in an_lines:
        t = _txt(b)
        assert "inbound" not in t.lower(), f"[{run_label}] inbound in analysis: {t!r}"
        assert not t.strip().endswith(":"), f"[{run_label}] bullet ends with bare colon: {t!r}"

    # Verdict
    verdict = (rpt.get("verdict") or ai.get("verdict") or "").upper()
    assert verdict in {"TP", "FP", "SUSPICIOUS"}, f"[{run_label}] verdict={verdict}"
    vreason = rpt.get("verdict_reason") or ai.get("verdict_reason") or ""
    assert not vreason.startswith("*"), f"[{run_label}] verdict_reason starts with *: {vreason!r}"


# --- Test 1a & 1b: 00316 Outbound LLM run twice ---

def test_00316_outbound_llm_run1(headers, offenses):
    off = _find(offenses, "IND-UC-00316-Permit Connections CTI_IP Feeds Outbound")
    assert off, "00316 Outbound not found"
    _investigate(headers, off["id"])
    data = _poll_llm(headers, off["id"], timeout=200)
    _assert_llm_invariants_00316(data, "run1")


def test_00316_outbound_llm_run2(headers, offenses):
    off = _find(offenses, "IND-UC-00316-Permit Connections CTI_IP Feeds Outbound")
    assert off
    _investigate(headers, off["id"])
    data = _poll_llm(headers, off["id"], timeout=200)
    _assert_llm_invariants_00316(data, "run2")


# --- Test 2: 00317 Inbound must not match Outbound KB ---

def test_00317_inbound_no_kb(headers, offenses):
    off = _find(offenses, "IND-UC-00317-Permit Connections CTI_IP Feeds Inbound")
    assert off
    resp = _investigate(headers, off["id"])
    ai = resp.get("ai_analysis") or {}
    src = ai.get("mssp_report_source")
    assert src == "rule-engine", f"expected rule-engine, got {src}"
    rpt = ai.get("mssp_report") or {}
    assert not rpt.get("kb_learning"), f"kb_learning should be absent: {rpt.get('kb_learning')}"


# --- Test 3: PowerShell regression ---

def test_powershell_kb_and_llm(headers, offenses):
    off = _find(offenses, "Suspicious PowerShell Encoded Command Execution")
    assert off
    _investigate(headers, off["id"])
    data = _poll_llm(headers, off["id"], timeout=200)
    ai = data.get("ai_analysis") or {}
    rpt = ai.get("mssp_report") or {}
    kbl = rpt.get("kb_learning") or {}
    assert kbl.get("ticket_count") == 1, f"kb_learning={kbl}"

    imp = [_txt(b) for b in (rpt.get("impact_lines") or [])]
    for b in imp:
        low = b.lower().strip()
        assert not re.match(r"^(block|isolate|collect the host)\b", low), f"imperative in impact: {b}"
        assert not low.startswith("report:"), f"junk in impact: {b}"
        assert not low.startswith("type:"), f"junk in impact: {b}"

    recs_text = " ".join(_txt(r) for r in (rpt.get("recommendations") or [])).lower()
    assert "powershell.exe" in recs_text or "outlook.exe" in recs_text, f"recs not grounded: {recs_text[:400]}"
