"""Iteration 16 — UC-00508 Trend Micro Apex Central (Virus/Behavior Monitoring/Persistence)

Validates the fix for offense 0d75ac25-9714-4f42-a854-03af415d43ff:
  - CEF/Apex Central payload artifacts are extracted (file path, registry autorun,
    host, action).
  - Deterministic Analysis mentions the grounded artifacts.
  - Deterministic Impact is non-empty, mentions persistence/autorun and 'no evidence
    of confirmed compromise/infection'.
  - Deterministic Recommendations contain persistence-handling actions.
  - No prompt/meta echo leakage.
  - No "user None" text.
  - Grounded content survives in BOTH the immediate rule-engine response AND the
    final state after the background OpenRouter LLM completes/fails.
"""

import os
import time
import re
import pytest
import requests

BASE_URL = (os.environ.get("REACT_APP_BACKEND_URL") or "https://socpilot-local.preview.emergentagent.com").rstrip("/")
OFFENSE_ID = "0d75ac25-9714-4f42-a854-03af415d43ff"

ADMIN_EMAIL = "admin@socpilot.ai"
ADMIN_PASSWORD = "Admin@123"

REGISTRY_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Figma Agent"
FILE_MARKER = "figma_agent.exe"
HOST_MARKER = "LTWGSLVAP1424"
ACTION_MARKER = "Assess"

META_ECHOES = [
    "We need to output",
    "each starting with",
    "REASON:",
    "Must mention actual IP",
    "ANALYSIS section",
    "<one technical sentence>",
]


@pytest.fixture(scope="module")
def token():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=90,
    )
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    tok = r.json().get("access_token")
    assert tok
    return tok


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _get_offense(headers):
    r = requests.get(f"{BASE_URL}/api/offenses/{OFFENSE_ID}", headers=headers, timeout=30)
    assert r.status_code == 200, f"GET offense failed: {r.status_code} {r.text[:400]}"
    return r.json()


def _extract_report(offense):
    ai = offense.get("ai_analysis") or {}
    rpt = ai.get("mssp_report") or {}
    return ai, rpt


def _all_text(rpt):
    parts = []
    for ln in rpt.get("analysis_lines") or []:
        if isinstance(ln, dict):
            parts.append(ln.get("text", ""))
        else:
            parts.append(str(ln))
    parts.extend([str(x) for x in (rpt.get("impact_lines") or [])])
    parts.extend([str(x) for x in (rpt.get("recommendations") or [])])
    parts.append(str(rpt.get("verdict_reason") or ""))
    return "\n".join(parts)


def _assert_grounded(rpt, phase):
    text = _all_text(rpt)
    low = text.lower()

    # Analysis-specific artifact checks
    analysis_text = "\n".join(
        (ln.get("text", "") if isinstance(ln, dict) else str(ln))
        for ln in (rpt.get("analysis_lines") or [])
    )
    a_low = analysis_text.lower()

    # Normalize backslashes (backend may emit escaped \\ vs \)
    a_norm = a_low.replace("\\\\", "\\")
    reg_norm = REGISTRY_KEY.lower().replace("\\\\", "\\")

    assert reg_norm in a_norm, (
        f"[{phase}] Registry autorun key missing from analysis. Got:\n{analysis_text}"
    )
    assert FILE_MARKER.lower() in a_low, (
        f"[{phase}] '{FILE_MARKER}' missing from analysis. Got:\n{analysis_text}"
    )
    assert HOST_MARKER.lower() in a_low, (
        f"[{phase}] Host '{HOST_MARKER}' missing from analysis. Got:\n{analysis_text}"
    )
    assert ACTION_MARKER.lower() in a_low, (
        f"[{phase}] Action '{ACTION_MARKER}' missing from analysis. Got:\n{analysis_text}"
    )

    # Impact section
    impact = rpt.get("impact_lines") or []
    assert isinstance(impact, list) and len(impact) > 0, (
        f"[{phase}] impact_lines is empty. Report keys: {list(rpt.keys())}"
    )
    impact_text = " ".join(str(x) for x in impact).lower()
    assert "persistence" in impact_text or "autorun" in impact_text or "startup" in impact_text, (
        f"[{phase}] impact_lines does not mention persistence/autorun/startup: {impact}"
    )
    assert (
        ("no evidence" in impact_text and ("compromise" in impact_text or "infection" in impact_text or "confirmed" in impact_text))
    ), f"[{phase}] impact_lines missing 'no evidence of confirmed compromise/infection': {impact}"

    # Recommendations
    recs = rpt.get("recommendations") or []
    assert len(recs) >= 3, f"[{phase}] Fewer than 3 recommendations: {recs}"
    recs_text = " ".join(str(x) for x in recs).lower()

    checks = {
        "verify legitimacy of figma_agent.exe": (
            ("verify" in recs_text or "confirm" in recs_text or "validate" in recs_text)
            and "figma_agent.exe" in recs_text
        ),
        "review startup / registry autorun / scheduled tasks": (
            ("startup" in recs_text or "autorun" in recs_text or "scheduled task" in recs_text or "run key" in recs_text or "registry" in recs_text)
        ),
        "full AV/EDR scan on endpoint": (
            ("scan" in recs_text) and ("antivirus" in recs_text or "edr" in recs_text or "full" in recs_text)
        ),
        "remove persistence / delete file if malicious": (
            ("remove" in recs_text or "delete" in recs_text or "quarantine" in recs_text)
            and ("persistence" in recs_text or "autorun" in recs_text or "run key" in recs_text or "file" in recs_text or "registry" in recs_text)
        ),
    }
    missing = [k for k, v in checks.items() if not v]
    assert not missing, f"[{phase}] Missing recommendation actions {missing}. recs={recs}"

    # No meta/prompt echo leakage
    for bad in META_ECHOES:
        assert bad.lower() not in low, f"[{phase}] Prompt/meta echo leak found: '{bad}' in report"
    # Literal placeholder angle-brackets like <one technical sentence>
    assert not re.search(r"<[a-zA-Z][^>]{2,40}>", text), (
        f"[{phase}] Placeholder <...> found in report text"
    )

    # No "user None"
    assert "user none" not in low and "user 'none'" not in low, (
        f"[{phase}] 'user None' text present in report"
    )


def test_investigate_uc00508_immediate_and_final(headers):
    # Trigger investigate
    r = requests.post(
        f"{BASE_URL}/api/offenses/{OFFENSE_ID}/investigate",
        headers=headers,
        timeout=60,
    )
    assert r.status_code in (200, 202), f"investigate failed: {r.status_code} {r.text[:400]}"

    # Immediate state (rule-engine base)
    offense = _get_offense(headers)
    ai, rpt = _extract_report(offense)
    assert rpt, f"mssp_report missing on immediate GET. ai_analysis keys={list(ai.keys())}"
    immediate_source = rpt.get("source") or rpt.get("generated_by") or ai.get("mssp_report_source")
    print(f"IMMEDIATE source={immediate_source} llm_status={ai.get('llm_status')}")
    _assert_grounded(rpt, "immediate")

    # Poll until llm_status is done/failed (up to ~150s)
    deadline = time.time() + 160
    final_status = None
    while time.time() < deadline:
        offense = _get_offense(headers)
        ai, rpt = _extract_report(offense)
        status = ai.get("llm_status")
        if status in ("done", "failed"):
            final_status = status
            break
        time.sleep(5)

    assert final_status in ("done", "failed"), (
        f"llm_status did not reach done/failed within timeout: last={ai.get('llm_status')}"
    )
    print(f"FINAL llm_status={final_status} source={rpt.get('source') or rpt.get('generated_by')}")
    _assert_grounded(rpt, f"final ({final_status})")
