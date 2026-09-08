"""Iteration 18 — Field extraction & branch-routing for 3 NEW offenses.

Validates deterministic (rule-engine) MSSP report for:
 - Auth offense 2d819087-... (WinSec 4625 brute force -> success)
 - Proxy/Web offense aa245d82-... (Zscaler BLOCKED)
 - Firewall permit offense 74733a74-... (Palo Alto permitted outbound DNS)

Plus regressions:
 - CTI offense b3d62492-... (CTI analyst template preserved)
 - Malware offense 0d75ac25-... (persistence grounded content preserved)
"""

import os
import time
import pytest
import requests

BASE_URL = (os.environ.get("REACT_APP_BACKEND_URL") or "https://socpilot-local.preview.emergentagent.com").rstrip("/")

AUTH_OFFENSE   = "2d819087-0ad7-4ebc-9498-57fda4f61f53"
PROXY_OFFENSE  = "aa245d82-c472-4368-bc18-22891af6da9e"
FW_OFFENSE     = "74733a74-0da4-4cba-b1b7-c376af971949"
CTI_OFFENSE    = "b3d62492-eec6-458b-b090-d2264b3cacad"
UC508_OFFENSE  = "0d75ac25-9714-4f42-a854-03af415d43ff"

ADMIN_EMAIL = "admin@socpilot.ai"
ADMIN_PASSWORD = "Admin@123"


@pytest.fixture(scope="module")
def headers():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=90,
    )
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
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
    """Trigger investigate and return the immediate response's ai_analysis if present.
    We assert on the deterministic (rule-engine) mssp_report which is populated
    synchronously in the investigate response."""
    r = requests.post(
        f"{BASE_URL}/api/offenses/{offense_id}/investigate",
        headers=h,
        timeout=60,
    )
    assert r.status_code in (200, 202), f"investigate {offense_id} failed: {r.status_code} {r.text[:400]}"
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
    fields = rpt.get("fields") or {}
    if isinstance(fields, dict):
        for k, v in fields.items():
            parts.append(f"{k}: {v}")
    elif isinstance(fields, list):
        for item in fields:
            parts.append(str(item))
    return "\n".join(parts)


# ---------------- Auth offense ----------------

def test_auth_offense_analysis(headers):
    ai = _investigate_and_fetch(AUTH_OFFENSE, headers)
    rpt = ai.get("mssp_report") or {}
    assert rpt, f"mssp_report missing for AUTH offense; ai keys={list((ai or {}).keys())}"

    a_lines = _lines_text(rpt.get("analysis_lines"))
    a_text = "\n".join(a_lines)
    a_low = a_text.lower()
    print(f"\nAUTH ANALYSIS:\n{a_text}\n")

    # Must reference the failed authentication for user jdoe from 10.20.30.40
    assert 'jdoe' in a_low, f"user jdoe missing: {a_text}"
    assert '10.20.30.40' in a_text, f"source IP missing: {a_text}"
    assert any(w in a_low for w in ['failed', 'failure', 'brute', 'multiple']), f"failed auth context missing: {a_text}"

    # Grounded line with logon type 3, workstation WS-FIN-12, status code 0xC000006D
    assert 'ws-fin-12' in a_low, f"workstation WS-FIN-12 missing from analysis: {a_text}"
    assert '0xc000006d' in a_low, f"status code 0xC000006D missing from analysis: {a_text}"
    # Logon type 3
    assert ('logon type' in a_low and '3' in a_text) or 'logontype=3' in a_low or 'logon type 3' in a_low, (
        f"logon type 3 missing from analysis: {a_text}"
    )

    # No historical similar incident
    full = _all_report_text(rpt).lower()
    assert 'historical similar incident' not in full, "'Historical similar incident' present in AUTH report"


# ---------------- Proxy / Web offense ----------------

def test_proxy_offense_analysis(headers):
    ai = _investigate_and_fetch(PROXY_OFFENSE, headers)
    rpt = ai.get("mssp_report") or {}
    assert rpt, "mssp_report missing for PROXY offense"

    a_text = "\n".join(_lines_text(rpt.get("analysis_lines")))
    a_low = a_text.lower()
    print(f"\nPROXY ANALYSIS:\n{a_text}\n")

    # WEB request from asmith on host 10.5.6.7 to URL, blocked by Zscaler
    assert 'asmith' in a_low, f"user asmith missing: {a_text}"
    assert '10.5.6.7' in a_text, f"host 10.5.6.7 missing: {a_text}"
    assert 'http://malicious.example.com/dropper.exe' in a_low, f"URL missing: {a_text}"
    assert ('block' in a_low), f"'blocked' verdict missing: {a_text}"
    assert 'zscaler' in a_low, f"Zscaler missing: {a_text}"

    # Grounded protocol/port
    assert 'tcp' in a_low, f"TCP protocol missing: {a_text}"
    assert '80' in a_text, f"port 80 missing: {a_text}"

    # Must NOT contain persistence/malware branch content
    forbidden_malware = ['behavior monitoring', 'startup program', 'registry', 'hkcu', 'run key', 'persistence']
    for w in forbidden_malware:
        assert w not in a_low, f"forbidden malware/persistence wording {w!r} present in PROXY analysis:\n{a_text}"

    # Must NOT contain CTI feed wording
    forbidden_cti = ['cti feed', 'threat intelligence feed', 'threat intel feed', 'cti-monitored', 'cti monitored']
    for w in forbidden_cti:
        assert w not in a_low, f"forbidden CTI wording {w!r} in PROXY analysis:\n{a_text}"

    # Impact: request blocked -> no compromise expected; NOT the CTI 'internally hosted service' text
    impact = rpt.get("impact_lines") or []
    imp_low = " \n ".join(str(x) for x in impact).lower()
    print(f"PROXY IMPACT: {impact}")
    assert impact, "impact_lines empty for PROXY offense"
    assert 'block' in imp_low, f"impact does not mention blocked: {impact}"
    assert 'no compromise' in imp_low or 'no impact' in imp_low or 'not expected' in imp_low or 'no host compromise' in imp_low, (
        f"impact does not say no compromise expected: {impact}"
    )
    assert 'internally hosted service' not in imp_low, f"CTI 'internally hosted service' text leaked into PROXY impact: {impact}"

    full = _all_report_text(rpt).lower()
    assert 'historical similar incident' not in full


# ---------------- Firewall permit offense ----------------

def test_firewall_permit_offense_analysis(headers):
    ai = _investigate_and_fetch(FW_OFFENSE, headers)
    rpt = ai.get("mssp_report") or {}
    assert rpt, "mssp_report missing for FW offense"

    a_text = "\n".join(_lines_text(rpt.get("analysis_lines")))
    a_low = a_text.lower()
    print(f"\nFW ANALYSIS:\n{a_text}\n")

    # Grammatical sentence with Palo Alto, allowed outbound dns, 10.1.1.5 -> 8.8.8.8, UDP port 53
    assert 'palo alto' in a_low, f"Palo Alto missing: {a_text}"
    assert ('allowed' in a_low or 'permitted' in a_low), f"allowed/permitted missing: {a_text}"
    assert 'dns' in a_low, f"dns missing: {a_text}"
    assert '10.1.1.5' in a_text, f"source IP 10.1.1.5 missing: {a_text}"
    assert '8.8.8.8' in a_text, f"destination 8.8.8.8 missing: {a_text}"
    assert 'udp' in a_low, f"UDP missing: {a_text}"
    assert '53' in a_text, f"port 53 missing: {a_text}"

    # Grounded lines: firewall policy 'Allow-Outbound-DNS', zones Trust->Untrust, bytes/packets 214/2
    assert 'allow-outbound-dns' in a_low, f"policy 'Allow-Outbound-DNS' missing: {a_text}"
    assert 'trust' in a_low and 'untrust' in a_low, f"zones Trust->Untrust missing: {a_text}"
    assert '214' in a_text, f"bytes 214 missing: {a_text}"
    assert ('2 packets' in a_low or 'packets: 2' in a_low or ' 2 ' in a_text), f"packets 2 missing: {a_text}"

    # Must NOT be routed to DNS-tunneling or CTI
    forbidden = ['dns tunneling', 'dns-tunnel', 'tunneling', 'cti feed', 'threat intelligence feed', 'cti-monitored']
    for w in forbidden:
        assert w not in a_low, f"forbidden wording {w!r} in FW analysis:\n{a_text}"

    # Impact must be firewall-permit impact, not CTI
    impact = rpt.get("impact_lines") or []
    imp_low = " \n ".join(str(x) for x in impact).lower()
    print(f"FW IMPACT: {impact}")
    assert impact
    assert 'internally hosted service' not in imp_low, f"CTI text leaked: {impact}"
    assert ('permit' in imp_low or 'allowed' in imp_low or 'egress' in imp_low or 'outbound' in imp_low), (
        f"firewall-permit impact missing: {impact}"
    )

    # No description bleed into extracted field values: session_end_reason should be a single token like 'aged-out'
    # search fields for aged-out
    fields = rpt.get("fields") or {}
    field_dict = {}
    if isinstance(fields, dict):
        field_dict = {str(k): str(v) for k, v in fields.items()}
    elif isinstance(fields, list):
        for item in fields:
            if isinstance(item, dict):
                k = item.get("label") or item.get("key") or item.get("name") or ""
                v = item.get("value") or ""
                field_dict[str(k)] = str(v)
    # Include x_ keys on report root
    for k, v in rpt.items():
        if k.startswith("x_"):
            field_dict[k] = str(v)

    print(f"FW FIELDS: {field_dict}")
    for k, v in field_dict.items():
        low_v = str(v).lower()
        if 'aged-out' in low_v:
            # session end reason must be clean
            assert 'palo alto' not in low_v, f"description bleed into field {k}: {v!r}"
            assert 'firewall permitted' not in low_v, f"description bleed into field {k}: {v!r}"

    full = _all_report_text(rpt).lower()
    assert 'historical similar incident' not in full


# ---------------- Regression: CTI offense ----------------

def test_cti_regression(headers):
    ai = _investigate_and_fetch(CTI_OFFENSE, headers, wait_llm=True, timeout_s=45)
    rpt = ai.get("mssp_report") or {}
    assert rpt, "CTI mssp_report missing"

    assert ai.get("llm_status") == "done", f"CTI llm_status={ai.get('llm_status')}"
    src = ai.get("mssp_report_source") or rpt.get("source") or rpt.get("generated_by")
    assert src == "rule-engine", f"CTI mssp_report_source={src}"

    a_lines = _lines_text(rpt.get("analysis_lines"))
    assert len(a_lines) == 6, f"expected 6 analysis lines, got {len(a_lines)}: {a_lines}"
    impact = rpt.get("impact_lines") or []
    assert len(impact) == 3, f"CTI impact expected 3 lines, got {len(impact)}"
    recs = rpt.get("recommendations") or []
    assert len(recs) == 3, f"CTI recs expected 3, got {len(recs)}"

    full = _all_report_text(rpt).lower()
    assert 'historical similar incident' not in full


# ---------------- Regression: UC-00508 malware persistence ----------------

def test_uc00508_regression(headers):
    ai = _investigate_and_fetch(UC508_OFFENSE, headers, wait_llm=True, timeout_s=170)
    rpt = ai.get("mssp_report") or {}
    assert rpt, "UC-00508 mssp_report missing"

    a_text = "\n".join(_lines_text(rpt.get("analysis_lines")))
    a_low = a_text.lower()
    a_norm = a_low.replace("\\\\", "\\")

    assert r"hkcu\software\microsoft\windows\currentversion\run\figma agent" in a_norm, (
        f"registry key missing:\n{a_text}"
    )
    assert 'figma_agent.exe' in a_low
    assert 'ltwgslvap1424' in a_low
    assert 'assess' in a_low

    impact = rpt.get("impact_lines") or []
    imp_low = " ".join(str(x) for x in impact).lower()
    assert any(w in imp_low for w in ['startup', 'autorun', 'persistence']), f"persistence impact missing: {impact}"

    recs = rpt.get("recommendations") or []
    assert len(recs) >= 3, f"UC-00508 fewer than 3 recs: {recs}"

    full = _all_report_text(rpt).lower()
    assert 'historical similar incident' not in full
