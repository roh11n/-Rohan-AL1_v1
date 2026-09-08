"""Iteration 17 — CTI Inbound Feed offense + UC-00508 regression.

Validates the MSSP report for CTI-inbound offense b3d62492-eec6-458b-b090-d2264b3cacad:
 - Analysis is the analyst-template narrative (opens with the required sentence,
   mentions inbound CTI-monitored IP on firewall, permitted connection details,
   Implied Rule policy, Accept action, SOURCE IP matched CTI feed).
 - Impact has exactly 3 lines with CTI-listed IP + reconnaissance + reachability.
 - Recommendations has 3 lines with block IP 194.165.16.163, verify comms,
   review firewall rule 'Implied Rule'.
 - Fields include Source Port, Destination Port 264, Protocol TCP, Action Accept,
   Rule Name Implied Rule. No duplicate Policy Name==Rule Name and no duplicate
   Destination NAT IP==Post NAT Destination IP.
 - No 'Historical similar incident' text anywhere.
 - ai_analysis.llm_status == 'done' and mssp_report_source == 'rule-engine'.

Also regression-tests UC-00508 offense 0d75ac25-... grounded content survives.
"""

import os
import time
import pytest
import requests

BASE_URL = (os.environ.get("REACT_APP_BACKEND_URL") or "https://socpilot-local.preview.emergentagent.com").rstrip("/")
CTI_OFFENSE_ID = "b3d62492-eec6-458b-b090-d2264b3cacad"
UC508_OFFENSE_ID = "0d75ac25-9714-4f42-a854-03af415d43ff"

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


def _get(offense_id, headers):
    r = requests.get(f"{BASE_URL}/api/offenses/{offense_id}", headers=headers, timeout=30)
    assert r.status_code == 200, f"GET offense {offense_id} failed: {r.status_code} {r.text[:400]}"
    return r.json()


def _lines_text(lines):
    out = []
    for ln in lines or []:
        if isinstance(ln, dict):
            out.append(ln.get("text", ""))
        else:
            out.append(str(ln))
    return out


def _all_text(rpt):
    parts = []
    parts.extend(_lines_text(rpt.get("analysis_lines")))
    parts.extend([str(x) for x in (rpt.get("impact_lines") or [])])
    parts.extend([str(x) for x in (rpt.get("recommendations") or [])])
    parts.append(str(rpt.get("verdict_reason") or ""))
    # fields
    fields = rpt.get("fields") or {}
    if isinstance(fields, dict):
        for k, v in fields.items():
            parts.append(f"{k}: {v}")
    elif isinstance(fields, list):
        for item in fields:
            parts.append(str(item))
    return "\n".join(parts)


# ---------- CTI offense ----------

def test_cti_offense_investigate_and_report(headers):
    # Trigger investigate
    r = requests.post(
        f"{BASE_URL}/api/offenses/{CTI_OFFENSE_ID}/investigate",
        headers=headers,
        timeout=60,
    )
    assert r.status_code in (200, 202), f"investigate failed: {r.status_code} {r.text[:400]}"

    # Poll briefly (should be immediate/deterministic)
    deadline = time.time() + 40
    ai = rpt = None
    while time.time() < deadline:
        offense = _get(CTI_OFFENSE_ID, headers)
        ai = offense.get("ai_analysis") or {}
        rpt = ai.get("mssp_report") or {}
        if rpt and ai.get("llm_status") in ("done", "failed"):
            break
        time.sleep(3)

    assert rpt, f"mssp_report missing. ai keys={list((ai or {}).keys())}"

    # llm_status must be done, source rule-engine
    assert ai.get("llm_status") == "done", f"expected llm_status done, got {ai.get('llm_status')}"
    src = ai.get("mssp_report_source") or rpt.get("source") or rpt.get("generated_by")
    assert src == "rule-engine", f"expected mssp_report_source rule-engine, got {src}"

    # ---- Analysis ----
    a_lines = _lines_text(rpt.get("analysis_lines"))
    a_text = "\n".join(a_lines)
    a_low = a_text.lower()
    print(f"CTI ANALYSIS:\n{a_text}\n")

    assert 'we have observed an offense' in a_low, f"opening phrase missing:\n{a_text}"
    assert 'ind-uc-00317-permit connections cti_ip feeds inbound' in a_low, (
        f"offense name missing:\n{a_text}"
    )
    # Inbound CTI-monitored IP on firewall
    assert ('inbound' in a_low and 'cti' in a_low and 'firewall' in a_low), (
        f"inbound CTI firewall context missing:\n{a_text}"
    )
    # Source IP, destination IP, NAT internal, TCP port 264
    for marker in ["194.165.16.163", "115.113.135.130", "115.113.135.131", "264"]:
        assert marker in a_text, f"marker {marker!r} missing from analysis:\n{a_text}"
    assert 'tcp' in a_low, f"protocol TCP missing:\n{a_text}"
    # Implied Rule policy
    assert 'implied rule' in a_low, f"firewall policy 'Implied Rule' missing:\n{a_text}"
    # Accept action
    assert 'accept' in a_low, f"action Accept missing:\n{a_text}"
    # Match reason
    assert ('source ip' in a_low and 'matched' in a_low and ('cti' in a_low or 'threat intelligence' in a_low) and 'feed' in a_low), (
        f"CTI feed match statement missing:\n{a_text}"
    )

    # ---- Impact ----
    impact = rpt.get("impact_lines") or []
    print(f"CTI IMPACT: {impact}")
    assert len(impact) == 3, f"expected exactly 3 impact lines, got {len(impact)}: {impact}"
    imp_all = " \n ".join(str(x) for x in impact).lower()
    assert 'cti' in imp_all and ('internally hosted' in imp_all or 'internal' in imp_all), (
        f"impact line about CTI IP -> internal service missing: {impact}"
    )
    assert any(w in imp_all for w in ['reconnaissance', 'scanning', 'enumeration', 'exploitation']), (
        f"impact reconnaissance/scanning/enumeration/exploitation missing: {impact}"
    )
    assert ('permit' in imp_all or 'permitted' in imp_all) and 'reachab' in imp_all, (
        f"impact reachability/permitted missing: {impact}"
    )

    # ---- Recommendations ----
    recs = rpt.get("recommendations") or []
    print(f"CTI RECS: {recs}")
    assert len(recs) == 3, f"expected exactly 3 recommendations, got {len(recs)}: {recs}"
    r_all = " \n ".join(str(x) for x in recs).lower()
    assert 'block' in r_all and '194.165.16.163' in r_all, f"block-IP rec missing: {recs}"
    assert ('verify' in r_all or 'confirm' in r_all or 'validate' in r_all), (
        f"verify-comms rec missing: {recs}"
    )
    assert '194.165.16.163' in r_all
    assert 'implied rule' in r_all and ('review' in r_all or 'restrict' in r_all), (
        f"review firewall rule 'Implied Rule' rec missing: {recs}"
    )

    # ---- Fields extraction ----
    fields = rpt.get("fields") or {}
    # Normalize to a searchable text and a key->value dict when possible
    field_text = ""
    field_dict = {}
    if isinstance(fields, dict):
        field_dict = {str(k): str(v) for k, v in fields.items()}
        field_text = "\n".join(f"{k}: {v}" for k, v in field_dict.items())
    elif isinstance(fields, list):
        for item in fields:
            if isinstance(item, dict):
                k = item.get("label") or item.get("key") or item.get("name") or ""
                v = item.get("value") or ""
                field_dict[str(k)] = str(v)
                field_text += f"{k}: {v}\n"
            else:
                field_text += f"{item}\n"

    # x_ keys on the report root
    x_keys = {k: v for k, v in rpt.items() if k.startswith("x_")}
    field_text += "\n" + "\n".join(f"{k}: {v}" for k, v in x_keys.items())
    ft_low = field_text.lower()
    print(f"CTI FIELDS TEXT:\n{field_text}\n")

    assert '264' in field_text, f"Destination Port 264 not in fields: {field_text}"
    assert 'tcp' in ft_low, f"Protocol TCP not in fields: {field_text}"
    assert 'accept' in ft_low, f"Action Accept not in fields: {field_text}"
    assert 'implied rule' in ft_low, f"Rule Name 'Implied Rule' not in fields: {field_text}"
    assert 'source port' in ft_low, f"Source Port label not in fields: {field_text}"
    assert 'destination port' in ft_low, f"Destination Port label not in fields: {field_text}"

    # No duplicate Policy Name == Rule Name
    def _val_for(label_substr):
        for k, v in field_dict.items():
            if label_substr.lower() in k.lower():
                return v
        return None

    rule_name = _val_for("Rule Name")
    policy_name = _val_for("Policy Name")
    if policy_name is not None and rule_name is not None:
        assert policy_name != rule_name, (
            f"Duplicate Policy Name == Rule Name found: {policy_name!r}"
        )

    post_nat = _val_for("Post NAT Destination IP") or _val_for("Post-NAT")
    dest_nat = _val_for("Destination NAT IP")
    if post_nat is not None and dest_nat is not None:
        assert post_nat != dest_nat, (
            f"Duplicate Destination NAT IP == Post NAT Destination IP: {post_nat!r}"
        )

    # ---- No 'Historical similar incident' anywhere ----
    full = _all_text(rpt).lower()
    assert 'historical similar incident' not in full, (
        f"Removed line 'Historical similar incident' still present"
    )


# ---------- UC-00508 regression ----------

def test_uc00508_regression(headers):
    r = requests.post(
        f"{BASE_URL}/api/offenses/{UC508_OFFENSE_ID}/investigate",
        headers=headers,
        timeout=60,
    )
    assert r.status_code in (200, 202)

    deadline = time.time() + 160
    ai = rpt = None
    status = None
    while time.time() < deadline:
        offense = _get(UC508_OFFENSE_ID, headers)
        ai = offense.get("ai_analysis") or {}
        rpt = ai.get("mssp_report") or {}
        status = ai.get("llm_status")
        if status in ("done", "failed") and rpt:
            break
        time.sleep(5)

    assert rpt, "UC-00508 mssp_report missing"
    assert status in ("done", "failed"), f"llm_status={status}"

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
    assert len(impact) > 0, "impact_lines empty for UC-00508"
    imp_low = " ".join(str(x) for x in impact).lower()
    assert any(w in imp_low for w in ['startup', 'autorun', 'persistence'])

    recs = rpt.get("recommendations") or []
    assert len(recs) >= 3, f"UC-00508 fewer than 3 recs: {recs}"

    # No 'Historical similar incident' regression
    full = _all_text(rpt).lower()
    assert 'historical similar incident' not in full
