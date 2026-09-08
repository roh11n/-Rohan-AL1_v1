"""Iteration 19 — IND-GLUC-10020 login-failure KB-aligned analysis + regressions.

Validates deterministic (rule-engine) MSSP report for:
 - Login-failure offense 15a8105b-... (IND-GLUC-10020 Multiple login failure from admin/administrator)
 - Regression CTI offense b3d62492-... (6-sentence CTI analyst template)
 - Regression malware offense 0d75ac25-... (persistence content preserved)
 - Regression proxy offense aa245d82-... (web-request-blocked, not routed to malware/CTI)
"""

import os
import time
import pytest
import requests

BASE_URL = (os.environ.get("REACT_APP_BACKEND_URL") or "https://socpilot-local.preview.emergentagent.com").rstrip("/")

LOGIN_FAIL_OFFENSE = "15a8105b-54d7-4cbb-8526-aaa3d5384177"
CTI_OFFENSE        = "b3d62492-eec6-458b-b090-d2264b3cacad"
UC508_OFFENSE      = "0d75ac25-9714-4f42-a854-03af415d43ff"
PROXY_OFFENSE      = "aa245d82-c472-4368-bc18-22891af6da9e"

ADMIN_EMAIL = "admin@socpilot.ai"
ADMIN_PASSWORD = "Admin@123"


@pytest.fixture(scope="module")
def headers():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=90,
    )
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:400]}"
    tok = r.json().get("access_token")
    assert tok
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def _get(offense_id, h):
    r = requests.get(f"{BASE_URL}/api/offenses/{offense_id}", headers=h, timeout=30)
    assert r.status_code == 200, f"GET failed: {r.status_code} {r.text[:400]}"
    return r.json()


def _lines_text(lines):
    out = []
    for ln in lines or []:
        if isinstance(ln, dict):
            out.append(ln.get("text", ""))
        else:
            out.append(str(ln))
    return out


def _investigate_and_fetch(offense_id, h, wait_llm=False, timeout_s=45):
    r = requests.post(
        f"{BASE_URL}/api/offenses/{offense_id}/investigate",
        headers=h,
        timeout=60,
    )
    assert r.status_code in (200, 202), f"investigate {offense_id}: {r.status_code} {r.text[:400]}"
    body = {}
    try:
        body = r.json()
    except Exception:
        pass
    ai = body.get("ai_analysis") if isinstance(body, dict) else None
    if ai and ai.get("mssp_report") and not wait_llm:
        return ai
    if ai and ai.get("mssp_report") and wait_llm and ai.get("llm_status") in ("done", "failed"):
        return ai
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        off = _get(offense_id, h)
        ai = off.get("ai_analysis") or {}
        rpt = ai.get("mssp_report") or {}
        if rpt:
            if not wait_llm:
                return ai
            if ai.get("llm_status") in ("done", "failed"):
                return ai
        time.sleep(3)
    return ai or {}


def _all_report_text(rpt):
    parts = []
    parts.extend(_lines_text(rpt.get("analysis_lines")))
    parts.extend([str(x) for x in (rpt.get("impact_lines") or [])])
    parts.extend([str(x) for x in (rpt.get("recommendations") or [])])
    return "\n".join(parts)


# ------------------ IND-GLUC-10020 login-failure ------------------

def test_login_failure_analysis(headers):
    ai = _investigate_and_fetch(LOGIN_FAIL_OFFENSE, headers)
    rpt = ai.get("mssp_report") or {}
    assert rpt, f"mssp_report missing for LOGIN-FAIL offense; ai keys={list((ai or {}).keys())}"

    a_lines = _lines_text(rpt.get("analysis_lines"))
    a_text = "\n".join(a_lines)
    a_low = a_text.lower()
    print(f"\nLOGIN-FAIL ANALYSIS:\n{a_text}\n")

    # (1) Names privileged account 'Admin' with src IP 45.227.254.14 and host 192.168.50.22
    assert 'admin' in a_low, f"account 'Admin' missing: {a_text}"
    assert '45.227.254.14' in a_text, f"source IP missing: {a_text}"
    assert '192.168.50.22' in a_text, f"host IP missing: {a_text}"

    # (2) Logon Type 3 (Network) and status code 0xC000006D (bad username / invalid auth info)
    assert 'logon type' in a_low and '3' in a_text, f"Logon Type 3 missing: {a_text}"
    assert 'network' in a_low, f"'Network' (logon type 3) missing: {a_text}"
    assert '0xc000006d' in a_low, f"status 0xC000006D missing: {a_text}"
    assert ('bad username' in a_low or 'invalid auth' in a_low or 'invalid authentication' in a_low), (
        f"status meaning (bad username/invalid auth) missing: {a_text}"
    )

    # (3) Credential spraying / brute-force framing + legitimate admin confirmation note
    assert ('credential spray' in a_low or 'spraying' in a_low or 'brute' in a_low), (
        f"credential-spray/brute-force framing missing: {a_text}"
    )
    assert ('legitimate' in a_low and ('admin' in a_low or 'confirm' in a_low)), (
        f"legitimate admin activity / confirmation framing missing: {a_text}"
    )

    # First line must NOT have raw newline in offense name
    if a_lines:
        first = a_lines[0]
        assert '\n' not in first, f"raw newline in first analysis line: {first!r}"
        assert '\r' not in first, f"raw CR in first analysis line: {first!r}"

    # Impact: 3 lines with the specific themes
    impact = rpt.get("impact_lines") or []
    imp_low = " \n ".join(str(x) for x in impact).lower()
    print(f"LOGIN-FAIL IMPACT: {impact}")
    assert len(impact) == 3, f"impact expected 3 lines, got {len(impact)}: {impact}"
    assert ('spray' in imp_low or 'brute' in imp_low) and 'unauthorized' in imp_low, (
        f"impact missing credential-spray/unauthorized access theme: {impact}"
    )
    assert ('compromise' in imp_low) and ('internal' in imp_low or 'resource' in imp_low or 'expose' in imp_low), (
        f"impact missing account-compromise/internal exposure theme: {impact}"
    )
    assert ('lockout' in imp_low or 'lock out' in imp_low) and ('service' in imp_low or 'disruption' in imp_low), (
        f"impact missing lockout/service-disruption theme: {impact}"
    )

    # Recommendations: 4 login-failure actions
    recs = rpt.get("recommendations") or []
    r_low = " \n ".join(str(x) for x in recs).lower()
    print(f"LOGIN-FAIL RECS: {recs}")
    assert len(recs) >= 4, f"expected >=4 recs, got {len(recs)}: {recs}"
    # verify source IP 45.227.254.14
    assert '45.227.254.14' in r_low, f"rec missing source IP verification: {recs}"
    # confirm with account owner/administrator
    assert ('confirm' in r_low) and ('admin' in r_low or 'owner' in r_low), (
        f"rec missing 'confirm with admin/owner': {recs}"
    )
    # check successful logon following failures
    assert ('success' in r_low) and ('follow' in r_low or 'after' in r_low or 'subsequent' in r_low), (
        f"rec missing 'successful logon after failures' check: {recs}"
    )
    # monitor for lockout / MFA / reset
    assert ('lockout' in r_low or 'lock out' in r_low or 'mfa' in r_low or 'reset' in r_low), (
        f"rec missing lockout/MFA/reset action: {recs}"
    )

    # No 'Historical KB reference' / 'Historical similar incident' anywhere in analysis
    assert 'historical kb reference' not in a_low, f"'Historical KB reference' present: {a_text}"
    assert 'historical similar incident' not in a_low, f"'Historical similar incident' present: {a_text}"
    full = _all_report_text(rpt).lower()
    assert 'historical kb reference' not in full
    assert 'historical similar incident' not in full

    # source should be rule-engine (deterministic base)
    src = ai.get("mssp_report_source") or rpt.get("source") or rpt.get("generated_by")
    print(f"LOGIN-FAIL source={src}, llm_status={ai.get('llm_status')}")
    assert src == "rule-engine", f"mssp_report_source expected rule-engine, got {src}"


# ------------------ Regression: CTI ------------------

def test_cti_regression(headers):
    ai = _investigate_and_fetch(CTI_OFFENSE, headers, wait_llm=True, timeout_s=45)
    rpt = ai.get("mssp_report") or {}
    assert rpt, "CTI mssp_report missing"
    assert ai.get("llm_status") == "done", f"CTI llm_status={ai.get('llm_status')}"
    src = ai.get("mssp_report_source") or rpt.get("source") or rpt.get("generated_by")
    assert src == "rule-engine", f"CTI source={src}"
    a_lines = _lines_text(rpt.get("analysis_lines"))
    assert len(a_lines) == 6, f"CTI expected 6 analysis lines, got {len(a_lines)}"
    assert len(rpt.get("impact_lines") or []) == 3
    assert len(rpt.get("recommendations") or []) == 3
    full = _all_report_text(rpt).lower()
    assert 'historical similar incident' not in full
    assert 'historical kb reference' not in full


# ------------------ Regression: UC-00508 malware persistence ------------------

def test_uc508_regression(headers):
    ai = _investigate_and_fetch(UC508_OFFENSE, headers, wait_llm=False, timeout_s=45)
    rpt = ai.get("mssp_report") or {}
    assert rpt, "UC-00508 mssp_report missing"
    a_low = "\n".join(_lines_text(rpt.get("analysis_lines"))).lower()
    assert 'figma_agent.exe' in a_low, f"figma_agent.exe missing: {a_low}"
    assert 'run' in a_low and ('registry' in a_low or 'hkcu' in a_low or 'currentversion' in a_low), (
        f"registry Run key context missing: {a_low}"
    )
    assert 'assess' in a_low
    imp_low = " ".join(str(x) for x in (rpt.get("impact_lines") or [])).lower()
    assert any(w in imp_low for w in ['startup', 'autorun', 'persistence']), f"persistence impact missing: {imp_low}"
    recs = rpt.get("recommendations") or []
    assert len(recs) >= 3
    full = _all_report_text(rpt).lower()
    assert 'historical similar incident' not in full
    assert 'historical kb reference' not in full


# ------------------ Regression: Proxy web-blocked ------------------

def test_proxy_regression(headers):
    ai = _investigate_and_fetch(PROXY_OFFENSE, headers)
    rpt = ai.get("mssp_report") or {}
    assert rpt, "PROXY mssp_report missing"
    a_low = "\n".join(_lines_text(rpt.get("analysis_lines"))).lower()
    assert 'block' in a_low, f"blocked missing: {a_low}"
    assert 'http://malicious.example.com/dropper.exe' in a_low, f"URL missing: {a_low}"
    assert '80' in a_low, f"port 80 missing: {a_low}"
    # Not routed to malware/persistence or CTI
    for w in ['persistence', 'run key', 'hkcu', 'registry run']:
        assert w not in a_low, f"forbidden malware wording {w!r} in PROXY: {a_low}"
    for w in ['cti feed', 'threat intelligence feed', 'cti-monitored']:
        assert w not in a_low, f"forbidden CTI wording {w!r} in PROXY: {a_low}"
    full = _all_report_text(rpt).lower()
    assert 'historical similar incident' not in full
    assert 'historical kb reference' not in full
