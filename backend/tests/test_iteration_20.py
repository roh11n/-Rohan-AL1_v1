"""Iteration 20 — UC-00508 malware/persistence multi-line grounded analysis.

Validates that the deterministic (rule-engine) FALLBACK for the malware +
'New startup program' persistence offense (0d75ac25...) produces MULTIPLE
discrete grounded analyst lines matching the reference MSSP analysis quality,
so that even when OpenRouter LLM is rate-limited (429), the fallback matches
the expected multi-point analysis. Also runs the two regressions.
"""

import os
import time
import pytest
import requests

BASE_URL = (os.environ.get("REACT_APP_BACKEND_URL")
            or "https://socpilot-local.preview.emergentagent.com").rstrip("/")

UC508_OFFENSE       = "0d75ac25-9714-4f42-a854-03af415d43ff"
LOGIN_FAIL_OFFENSE  = "15a8105b-54d7-4cbb-8526-aaa3d5384177"
CTI_OFFENSE         = "b3d62492-eec6-458b-b090-d2264b3cacad"

ADMIN_EMAIL = "admin@socpilot.ai"
ADMIN_PASSWORD = "Admin@123"


@pytest.fixture(scope="module")
def headers():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=90)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:400]}"
    tok = r.json().get("access_token")
    assert tok
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def _lines_text(lines):
    out = []
    for ln in lines or []:
        if isinstance(ln, dict):
            out.append(ln.get("text", ""))
        else:
            out.append(str(ln))
    return out


def _investigate_immediate(offense_id, h):
    """Return the ai_analysis from the IMMEDIATE investigate response — this is
    the deterministic rule-engine FALLBACK under test."""
    r = requests.post(f"{BASE_URL}/api/offenses/{offense_id}/investigate",
                      headers=h, timeout=60)
    assert r.status_code in (200, 202), f"investigate {offense_id}: {r.status_code} {r.text[:400]}"
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    ai = body.get("ai_analysis") if isinstance(body, dict) else None
    if ai and ai.get("mssp_report"):
        return ai
    # fallback: GET the offense once
    r2 = requests.get(f"{BASE_URL}/api/offenses/{offense_id}", headers=h, timeout=30)
    assert r2.status_code == 200
    return (r2.json() or {}).get("ai_analysis") or {}


def _all_report_text(rpt):
    parts = []
    parts.extend(_lines_text(rpt.get("analysis_lines")))
    parts.extend([str(x) for x in (rpt.get("impact_lines") or [])])
    parts.extend([str(x) for x in (rpt.get("recommendations") or [])])
    return "\n".join(parts)


# ------------- UC-00508 multi-line grounded analysis (deterministic fallback) -------------

def test_uc508_multiline_analysis(headers):
    ai = _investigate_immediate(UC508_OFFENSE, headers)
    rpt = ai.get("mssp_report") or {}
    assert rpt, f"mssp_report missing; ai keys={list((ai or {}).keys())}"

    # Source must be deterministic rule-engine (the fallback under test)
    src = ai.get("mssp_report_source") or rpt.get("source") or rpt.get("generated_by")
    print(f"UC508 source={src}, llm_status={ai.get('llm_status')}")
    assert src == "rule-engine", f"expected mssp_report_source=rule-engine, got {src}"

    a_lines = _lines_text(rpt.get("analysis_lines"))
    a_text = "\n".join(a_lines)
    a_low = a_text.lower()
    print(f"\nUC508 ANALYSIS ({len(a_lines)} lines):\n{a_text}\n")

    # Must be MULTIPLE discrete lines, not one dense sentence
    assert len(a_lines) >= 5, f"expected >=5 discrete analysis lines, got {len(a_lines)}: {a_lines}"

    # (1) Detection line: tool 'Trend ... Apex ... Central' + host 'LTWGSLVAP1424'
    assert ("trend" in a_low and "apex" in a_low and "central" in a_low), (
        f"detection tool 'Trend Apex Central' missing: {a_text}"
    )
    assert "ltwgslvap1424" in a_low, f"host 'LTWGSLVAP1424' missing: {a_text}"

    # (2) Registry Run key with 'Figma Agent' + figma_agent.exe file
    assert "figma_agent.exe" in a_low, f"figma_agent.exe missing: {a_text}"
    assert ("hkcu" in a_low and "run" in a_low
            and ("currentversion" in a_low or "software\\microsoft\\windows" in a_low)), (
        f"HKCU..CurrentVersion\\Run key context missing: {a_text}"
    )
    assert "figma agent" in a_low, f"'Figma Agent' Run entry name missing: {a_text}"

    # (3) File location described as user's LOCAL application-data (AppData\Local)
    assert ("local application-data" in a_low or "appdata\\local" in a_low
            or "local app data" in a_low or "local application data" in a_low), (
        f"file location AppData\\Local wording missing: {a_text}"
    )
    assert "validation" in a_low or "requires validation" in a_low, (
        f"'requires validation' framing missing on file-location line: {a_text}"
    )

    # (4) Device action 'Assess' explained (detected/evaluated per policy without blocking/removing)
    assert "'assess'" in a_low or " assess" in a_low or a_low.startswith("assess"), (
        f"device action 'Assess' missing: {a_text}"
    )
    assert (("without" in a_low and ("block" in a_low or "remov" in a_low))
            or "per policy" in a_low or "evaluated" in a_low), (
        f"'Assess' explanation (detected/evaluated per policy, no blocking/removal) missing: {a_text}"
    )

    # (5) Conclusion line: no confirmed compromise / requires validation
    assert ("no evidence" in a_low or "no confirmed" in a_low), (
        f"'no confirmed compromise / no evidence' conclusion missing: {a_text}"
    )
    assert ("compromise" in a_low or "confirmed malicious" in a_low), (
        f"conclusion wording missing: {a_text}"
    )

    # Must NOT contain forbidden historical-KB wording
    assert "historical kb reference" not in a_low, f"forbidden 'Historical KB reference' present: {a_text}"
    assert "historical similar incident" not in a_low, f"forbidden 'Historical similar incident' present: {a_text}"

    # First line clean (no raw newlines)
    if a_lines:
        assert "\n" not in a_lines[0] and "\r" not in a_lines[0], (
            f"raw newline in first line: {a_lines[0]!r}"
        )

    # Impact: still covers persistence (startup/autorun) + no-confirmed-compromise validation
    impact = rpt.get("impact_lines") or []
    imp_low = " \n ".join(str(x) for x in impact).lower()
    print(f"UC508 IMPACT: {impact}")
    assert any(w in imp_low for w in ("startup", "autorun", "persistence")), (
        f"impact missing persistence theme: {impact}"
    )
    assert ("no evidence" in imp_low or "no confirmed" in imp_low) and "validation" in imp_low, (
        f"impact missing no-confirmed-compromise/validation note: {impact}"
    )

    # Recommendations: 4 persistence actions
    recs = [str(x) for x in (rpt.get("recommendations") or [])]
    r_low = " \n ".join(recs).lower()
    print(f"UC508 RECS: {recs}")
    assert len(recs) >= 4, f"expected >=4 persistence recs, got {len(recs)}: {recs}"
    assert ("figma_agent.exe" in r_low and ("legit" in r_low or "verify" in r_low)), (
        f"rec missing 'verify figma_agent.exe legitimacy': {recs}"
    )
    assert ("startup" in r_low or "autorun" in r_low) and ("registry" in r_low or "scheduled" in r_low), (
        f"rec missing 'review startup/registry autorun/scheduled tasks': {recs}"
    )
    assert (("av" in r_low or "antivirus" in r_low) and "edr" in r_low and "scan" in r_low), (
        f"rec missing 'full AV/EDR scan': {recs}"
    )
    assert ("remove" in r_low or "delete" in r_low) and ("persistence" in r_low or "file" in r_low), (
        f"rec missing 'remove persistence/delete file': {recs}"
    )

    full = _all_report_text(rpt).lower()
    assert "historical kb reference" not in full
    assert "historical similar incident" not in full


# ------------- Regression: login-failure IND-GLUC-10020 -------------

def test_login_failure_regression(headers):
    ai = _investigate_immediate(LOGIN_FAIL_OFFENSE, headers)
    rpt = ai.get("mssp_report") or {}
    assert rpt, "login-failure mssp_report missing"
    src = ai.get("mssp_report_source") or rpt.get("source") or rpt.get("generated_by")
    assert src == "rule-engine", f"login-fail source={src}"

    a_low = "\n".join(_lines_text(rpt.get("analysis_lines"))).lower()
    assert "admin" in a_low
    assert "45.227.254.14" in a_low
    assert "192.168.50.22" in a_low
    assert "logon type" in a_low and "3" in a_low
    assert "network" in a_low
    assert "0xc000006d" in a_low
    assert ("bad username" in a_low or "invalid auth" in a_low)
    assert ("spray" in a_low or "brute" in a_low)

    impact = rpt.get("impact_lines") or []
    assert len(impact) == 3, f"impact expected 3 lines, got {len(impact)}: {impact}"

    recs = rpt.get("recommendations") or []
    assert len(recs) >= 4, f"expected >=4 recs, got {len(recs)}: {recs}"

    full = _all_report_text(rpt).lower()
    assert "historical kb reference" not in full
    assert "historical similar incident" not in full


# ------------- Regression: CTI 6-sentence template -------------

def test_cti_regression(headers):
    # For CTI we may need to wait briefly for llm_status
    deadline = time.time() + 45
    ai = _investigate_immediate(CTI_OFFENSE, headers)
    while time.time() < deadline and ai.get("llm_status") not in ("done", "failed"):
        time.sleep(3)
        r2 = requests.get(f"{BASE_URL}/api/offenses/{CTI_OFFENSE}", headers=headers, timeout=30)
        if r2.status_code == 200:
            ai = (r2.json() or {}).get("ai_analysis") or ai
    rpt = ai.get("mssp_report") or {}
    assert rpt, "CTI mssp_report missing"
    src = ai.get("mssp_report_source") or rpt.get("source") or rpt.get("generated_by")
    assert src == "rule-engine", f"CTI source={src}"
    a_lines = _lines_text(rpt.get("analysis_lines"))
    assert len(a_lines) == 6, f"CTI expected 6 analysis lines, got {len(a_lines)}: {a_lines}"
    assert len(rpt.get("impact_lines") or []) == 3
    assert len(rpt.get("recommendations") or []) == 3
    full = _all_report_text(rpt).lower()
    assert "historical similar incident" not in full
    assert "historical kb reference" not in full
