"""SOC investigation engine: IOC extraction, MITRE mapping, risk scoring,
recommendation, and optional Local LLM narrative augmentation."""
import re
import base64
import binascii
import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------- IOC extraction ----------
IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "registry": re.compile(r"HK(?:LM|CU|CR|U|CC)\\\\?[\w\\\\ .-]+", re.IGNORECASE),
    "command_line": re.compile(r"(?:powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe[^\n]{0,200}", re.IGNORECASE),
}

PRIVATE_IP = re.compile(r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)")


def extract_iocs(text: str) -> dict[str, list[str]]:
    text = text or ""
    results: dict[str, list[str]] = {}
    for name, pat in IOC_PATTERNS.items():
        matches = list({m if isinstance(m, str) else m[0] for m in pat.findall(text)})
        if name == "ipv4":
            external = [ip for ip in matches if not PRIVATE_IP.match(ip)]
            internal = [ip for ip in matches if PRIVATE_IP.match(ip)]
            results["ipv4_external"] = sorted(external)
            results["ipv4_internal"] = sorted(internal)
        elif name == "domain":
            # Require a real public TLD (2+ alpha) and reject code identifiers
            # like "System.Net.WebClient" that also match the regex.
            KNOWN_TLDS = {
                "com","net","org","io","co","us","uk","de","fr","in","cn","jp","ru",
                "gov","edu","mil","biz","info","xyz","ai","app","dev","cloud","tech",
                "site","online","top","live","tv","me","ly","sh","so","fm","cc",
            }
            filtered = []
            import re as _re
            _camel = _re.compile(r"^[A-Z][a-z]")
            for d in matches:
                if d.endswith(".exe") or d.endswith(".dll") or d.endswith(".ps1"):
                    continue
                parts = d.split(".")
                if len(parts) < 2:
                    continue
                tld = parts[-1].lower()
                if tld not in KNOWN_TLDS:
                    continue
                # CamelCase labels (System, WebClient, ...) → code identifier, not a domain
                if any(_camel.match(p) for p in parts):
                    continue
                filtered.append(d)
            results[name] = sorted(filtered)
        else:
            results[name] = sorted(matches)
    return results


def decode_base64_blobs(text: str) -> list[str]:
    """Best-effort decode of Base64 blobs found in text (>=40 chars)."""
    text = text or ""
    decoded_out = []
    for m in re.finditer(r"[A-Za-z0-9+/=]{40,}", text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            try:
                utf16 = raw.decode("utf-16-le", errors="ignore")
                if sum(c.isprintable() for c in utf16) > len(utf16) * 0.6:
                    decoded_out.append(utf16.strip())
                    continue
            except Exception:
                pass
            utf8 = raw.decode("utf-8", errors="ignore")
            if sum(c.isprintable() for c in utf8) > len(utf8) * 0.6 and len(utf8) > 8:
                decoded_out.append(utf8.strip())
        except (binascii.Error, ValueError):
            continue
    return decoded_out[:5]


# ---------- MITRE ATT&CK Mapping ----------
MITRE_TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

MITRE_RULES = [
    # (technique_id, technique_name, tactic_id, tactic_name, keywords)
    ("T1110", "Brute Force", "TA0006", "Credential Access", ["brute force", "failed password", "failed login", "multiple failed"]),
    ("T1078", "Valid Accounts", "TA0001", "Initial Access", ["successful login", "accepted password", "sign-in"]),
    ("T1059.001", "PowerShell", "TA0002", "Execution", ["powershell", "powershell.exe", "-enc", "-encodedcommand"]),
    ("T1027", "Obfuscated Files or Information", "TA0005", "Defense Evasion", ["-enc", "encodedcommand", "base64", "obfusc"]),
    ("T1071.004", "DNS", "TA0011", "Command and Control", ["dns tunneling", "txt query", "dns query"]),
    ("T1046", "Network Service Discovery", "TA0007", "Discovery", ["firewall deny", "port scan", "recon"]),
    ("T1486", "Data Encrypted for Impact", "TA0040", "Impact", ["ransomware", "lockbit", ".lockbit", "encrypt"]),
    ("T1041", "Exfiltration Over C2 Channel", "TA0010", "Exfiltration", ["exfil", "large outbound", "data transfer"]),
    ("T1543.003", "Windows Service", "TA0003", "Persistence", ["service registry", "sc.exe config", "services\\"]),
    ("T1055", "Process Injection", "TA0005", "Defense Evasion", ["process injection", "reflective dll"]),
    ("T1021.001", "Remote Desktop Protocol", "TA0008", "Lateral Movement", ["rdp", "3389"]),
    ("T1090", "Proxy", "TA0011", "Command and Control", ["proxy", "tor", "185.220.101"]),
    ("T1566", "Phishing", "TA0001", "Initial Access", ["outlook.exe", "phishing", "attachment"]),
    ("T1136", "Create Account", "TA0003", "Persistence", ["net user /add", "new-localuser"]),
    ("T1112", "Modify Registry", "TA0005", "Defense Evasion", ["hklm\\", "hkcu\\", "reg add"]),
    ("T1548", "Abuse Elevation Control Mechanism", "TA0004", "Privilege Escalation", ["uac bypass", "sc.exe config"]),
    ("T1078.004", "Cloud Accounts", "TA0001", "Initial Access", ["azure ad", "microsoftonline", "sign-in from"]),
    ("T1114", "Email Collection", "TA0009", "Collection", ["mailbox", "outlook mail"]),
]


def map_mitre(text: str, categories: list[str]) -> list[dict]:
    lowered = (text or "").lower()
    cats = " ".join(categories or []).lower()
    hits: list[dict] = []
    seen = set()
    for tech_id, tech_name, tac_id, tac_name, kws in MITRE_RULES:
        for kw in kws:
            if kw in lowered or kw in cats:
                if tech_id in seen:
                    break
                seen.add(tech_id)
                hits.append({
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic_id": tac_id,
                    "tactic_name": tac_name,
                    "evidence_keyword": kw,
                })
                break
    return hits


# ---------- Risk scoring ----------
def compute_risk_score(offense: dict, mitre: list[dict], iocs: dict) -> int:
    sev = int(offense.get("severity", 0))
    cred = int(offense.get("credibility", 0))
    mag = int(offense.get("magnitude", 0))
    rel = int(offense.get("relevance", 0))
    base = (sev * 4) + (mag * 2.5) + (cred * 1.5) + (rel * 2)  # up to ~100
    ext_ips = len(iocs.get("ipv4_external", []))
    hashes = len(iocs.get("md5", []) + iocs.get("sha1", []) + iocs.get("sha256", []))
    urls = len(iocs.get("url", []))
    mitre_count = len(mitre)
    bonus = min(10, ext_ips * 2) + min(10, hashes * 4) + min(5, urls * 1) + min(15, mitre_count * 3)
    critical_techniques = {"T1486", "T1041", "T1078.004"}
    if any(t.get("technique_id") in critical_techniques for t in mitre):
        bonus += 10
    score = int(min(100, base + bonus))
    return max(0, score)


# ---------- Recommendation ----------
DISPOSITIONS = ["Close Benign", "False Positive", "Monitor", "Escalate L2", "Escalate L3", "IR Required", "Contain Immediately"]


def recommend(risk: int, mitre: list[dict], offense: dict) -> tuple[str, int]:
    ttypes = {t.get("technique_id") for t in mitre}
    if "T1486" in ttypes or risk >= 90:
        return "Contain Immediately", 95
    if any(t in ttypes for t in ("T1041", "T1078.004")) or risk >= 80:
        return "IR Required", 88
    if risk >= 65:
        return "Escalate L3", 82
    if risk >= 50:
        return "Escalate L2", 75
    if risk >= 35:
        return "Monitor", 68
    if risk >= 20:
        return "False Positive", 62
    return "Close Benign", 55


# ---------- Analyst investigation orchestrator ----------
def analyze_offense(offense: dict, kb_matches: list[dict] | None = None,
                    similar: list[dict] | None = None,
                    llm_narrative: str | None = None,
                    ti_settings: dict | None = None,
                    learned_adjustments: dict | None = None) -> dict:
    events = offense.get("events", []) or []
    text_blob_parts = [offense.get("description", "")]
    text_blob_parts.extend(offense.get("categories", []) or [])
    text_blob_parts.extend(offense.get("rules", []) or [])
    for e in events:
        for k in ("event_name", "payload", "decoded_payload", "command_line",
                  "process", "parent_process", "url", "registry", "log_source", "category"):
            v = e.get(k)
            if v:
                text_blob_parts.append(str(v))
    blob = "\n".join(text_blob_parts)

    decoded = decode_base64_blobs(blob)
    if decoded:
        blob += "\n[DECODED]\n" + "\n".join(decoded)

    iocs = extract_iocs(blob)
    mitre = map_mitre(blob, offense.get("categories", []))
    risk = compute_risk_score(offense, mitre, iocs)

    # Threat Intel enrichment (only if configured)
    ti = None
    if ti_settings and any([
        ti_settings.get("virustotal_enabled") and ti_settings.get("virustotal_api_key"),
        ti_settings.get("abuseipdb_enabled") and ti_settings.get("abuseipdb_api_key"),
        ti_settings.get("misp_enabled") and ti_settings.get("misp_api_key") and ti_settings.get("misp_url"),
    ]):
        try:
            from threat_intel import enrich as ti_enrich
            ti = ti_enrich(iocs, ti_settings)
            # bump risk if TI confirms malicious
            if ti and ti.get("verdicts", {}).get("malicious", 0) > 0:
                risk = min(100, risk + 10 + min(15, ti["verdicts"]["malicious"] * 3))
        except Exception:
            ti = None

    # Analyst-coach learned adjustment
    risk, coach_delta = apply_learned_adjustment(risk, offense, learned_adjustments or {})

    rec, conf = recommend(risk, mitre, offense)

    kb_matches = kb_matches or []
    similar = similar or []
    fp_probability = 15 if risk >= 50 else 45 if risk < 30 else 30
    if any(s.get("was_false_positive") for s in similar):
        fp_probability = min(90, fp_probability + 30)

    if llm_narrative:
        summary = llm_narrative.strip()
    else:
        summary = _rule_narrative(offense, mitre, iocs, risk, rec, decoded)

    timeline = _build_timeline(offense, events)
    containment = _containment_steps(mitre, iocs, rec)
    attack_path = build_attack_path(offense, mitre, iocs, ti)
    mssp_report = build_mssp_report(offense, similar=similar, iocs=iocs, mitre=mitre,
                                     risk=risk, ti=ti, kb_matches=kb_matches)
    # Fill the recommendation string on the MSSP report
    rec_map = {
        "Close Benign": "Close as benign after user confirmation.",
        "False Positive": "Close as false positive; recommend detection tuning.",
        "Monitor": "Keep in monitoring queue for 24 hours.",
        "Escalate L2": "Escalate to L2 for deeper analysis.",
        "Escalate L3": "Escalate to L3 SME with full evidence pack.",
        "IR Required": "Engage Incident Response team immediately; open P1.",
        "Contain Immediately": "Isolate the affected host/account and engage IR.",
    }
    mssp_report["recommendation_text"] = rec_map.get(rec, rec)

    analysis = {
        "executive_summary": summary,
        "mssp_report": mssp_report,
        "timeline": timeline,
        "attack_path": attack_path,
        "mitre": mitre,
        "iocs": iocs,
        "decoded_payloads": decoded,
        "attack_stage": _attack_stage(mitre),
        "user_analysis": _user_analysis(offense),
        "host_analysis": _host_analysis(offense, iocs),
        "network_analysis": _network_analysis(iocs),
        "asset_criticality": _asset_criticality(offense),
        "historical_comparison": {"similar_count": len(similar), "matches": similar[:5]},
        "false_positive_probability": fp_probability,
        "business_impact": _business_impact(risk),
        "threat_intel_correlation": ti if ti else _threat_intel(iocs),
        "detection_logic": offense.get("rules", []),
        "confidence": conf,
        "recommended_action": rec,
        "containment_steps": containment,
        "escalation_recommendation": _escalation(rec),
        "closing_recommendation": _closing(rec),
        "risk_score": risk,
        "coach_adjustment": coach_delta,
        "kb_matches": kb_matches[:5],
    }
    return analysis


def _rule_narrative(off: dict, mitre: list[dict], iocs: dict, risk: int, rec: str, decoded: list[str]) -> str:
    """Compose a concise 3-4 sentence executive summary specific to the offense."""
    desc = off.get("description") or "Offense"
    users = off.get("usernames") or []
    src = (off.get("source_ips") or [None])[0]
    dst = (off.get("destination_ips") or [None])[0]
    rules = off.get("rules") or []
    net = off.get("network") or "the environment"
    top_techs = [t.get("technique_name") for t in (mitre or [])[:3] if t.get("technique_name")]
    ext_ips = iocs.get("ipv4_external") or []
    hashes = (iocs.get("sha256") or []) + (iocs.get("md5") or []) + (iocs.get("sha1") or [])

    parts: list[str] = []
    # Sentence 1: what happened + rule + scope
    who = f"user '{users[0]}'" if users else (f"source IP {src}" if src else "an unidentified actor")
    parts.append(f"The offense '{desc}' was raised on {net} network involving {who}"
                 + (f" targeting {dst}" if dst else "") + ".")
    # Sentence 2: technique / evidence
    if top_techs:
        parts.append(f"Behaviour aligns with MITRE ATT&CK techniques: {', '.join(top_techs)}.")
    elif rules:
        parts.append(f"Detection was triggered by rule(s): {', '.join(rules[:2])}.")
    # Sentence 3: indicators
    ind_bits = []
    if ext_ips:
        ind_bits.append(f"{len(ext_ips)} external IP(s) ({', '.join(ext_ips[:2])})")
    if hashes:
        ind_bits.append(f"{len(hashes)} file hash(es)")
    if decoded:
        ind_bits.append("base64-decoded command payload")
    if ind_bits:
        parts.append("Observed indicators: " + "; ".join(ind_bits) + ".")
    # Sentence 4: risk + recommendation
    parts.append(f"Computed risk score is {risk}/100 and the recommended action is '{rec}'.")
    return " ".join(parts)


def _build_timeline(off: dict, events: list[dict]) -> list[dict]:
    tl = [{
        "ts": off.get("start_time"),
        "label": "Offense started",
        "detail": off.get("description"),
    }]
    for e in events[:20]:
        tl.append({
            "ts": e.get("event_time"),
            "label": e.get("event_name") or e.get("category") or "Event",
            "detail": (e.get("decoded_payload") or e.get("payload") or ""),
        })
    tl.append({
        "ts": off.get("last_updated"),
        "label": "Last updated",
        "detail": f"{off.get('event_count', 0)} total events, {off.get('flow_count', 0)} flows",
    })
    return tl


def _containment_steps(mitre: list[dict], iocs: dict, rec: str) -> list[str]:
    steps = []
    ttypes = {t.get("technique_id") for t in mitre}
    if "T1486" in ttypes:
        steps.append("Isolate affected host from network immediately (block MAC/IP at switch).")
        steps.append("Take memory snapshot & disk image before shutdown for forensics.")
        steps.append("Identify backup restore point pre-encryption.")
    if "T1110" in ttypes:
        steps.append("Block source IP at perimeter firewall.")
        steps.append("Force password reset for targeted account(s).")
        steps.append("Enable MFA if not already enforced.")
    if "T1059.001" in ttypes:
        steps.append("Kill PowerShell process on host and quarantine parent binary.")
        steps.append("Search EDR for the decoded command across environment.")
    if "T1041" in ttypes:
        steps.append("Block destination IP/domain at proxy and DNS.")
        steps.append("Preserve NetFlow/PCAP for the transfer window.")
    if not steps and rec not in ("Close Benign", "False Positive"):
        steps.append("Monitor source host & user for 24h; add temporary detection rule.")
    if not steps:
        steps.append("No containment required — verified benign activity.")
    return steps


def _attack_stage(mitre: list[dict]) -> str:
    tactics_order = [t[1] for t in MITRE_TACTICS]
    hit_tactics = [t.get("tactic_name") for t in mitre]
    for t in reversed(tactics_order):
        if t in hit_tactics:
            return t
    return "Reconnaissance"


def _user_analysis(off: dict) -> dict:
    return {
        "users": off.get("usernames", []),
        "count": off.get("username_count", 0),
        "note": "VIP/critical status pending KB enrichment." if off.get("usernames") else "No user context.",
    }


def _host_analysis(off: dict, iocs: dict) -> dict:
    return {
        "internal_hosts": iocs.get("ipv4_internal", []),
        "external_hosts": iocs.get("ipv4_external", []),
    }


def _network_analysis(iocs: dict) -> dict:
    return {
        "external_ip_count": len(iocs.get("ipv4_external", [])),
        "urls": iocs.get("url", [])[:10],
        "domains": iocs.get("domain", [])[:10],
    }


def _asset_criticality(off: dict) -> str:
    net = str(off.get("network") or "").lower()
    if any(x in net for x in ("prod", "db", "file", "domain")):
        return "HIGH"
    if "dmz" in net:
        return "MEDIUM"
    return "STANDARD"


def _business_impact(risk: int) -> str:
    if risk >= 85:
        return "Critical — potential service disruption, data loss, or regulatory exposure."
    if risk >= 65:
        return "High — active threat requiring rapid response."
    if risk >= 40:
        return "Moderate — worth investigation, potential precursor."
    return "Low — likely noise or benign."


def _threat_intel(iocs: dict) -> dict:
    # Placeholder for TI enrichment (MISP/OTX/VT). Marked so UI can call out.
    ext = iocs.get("ipv4_external", [])
    urls = iocs.get("url", [])
    hashes = iocs.get("sha256", []) + iocs.get("md5", []) + iocs.get("sha1", [])
    return {
        "queried": False,
        "note": "Configure MISP/VirusTotal/AbuseIPDB in Settings for live enrichment.",
        "external_ips": ext[:5],
        "urls": urls[:5],
        "hashes": hashes[:5],
    }


def _escalation(rec: str) -> str:
    if rec in ("Contain Immediately", "IR Required"):
        return "Notify Incident Response team & SOC Manager on-call. Open P1 ticket."
    if rec in ("Escalate L3",):
        return "Assign to L3 SME with full evidence pack."
    if rec in ("Escalate L2",):
        return "Assign to L2 queue for deeper analysis."
    return "No escalation required."


def _closing(rec: str) -> str:
    if rec in ("Close Benign",):
        return "Close as benign — user activity within policy."
    if rec in ("False Positive",):
        return "Close as false positive — recommend detection tuning."
    if rec in ("Monitor",):
        return "Keep open in monitoring queue for 24h before closing."
    return "Do not close — active investigation."


# ---------- MSSP Analyst Report (structured & templated) ----------
WINDOWS_EVENT_NAMES = {
    "4624": "An account was successfully logged on",
    "4625": "An account failed to log on",
    "4634": "An account was logged off",
    "4648": "A logon was attempted using explicit credentials",
    "4672": "Special privileges assigned to new logon",
    "4720": "A user account was created",
    "4726": "A user account was deleted",
    "4738": "A user account was changed",
    "4740": "A user account was locked out",
}

WINDOWS_ERROR_MEANINGS = {
    "0xC0000064": "user name does not exist",
    "0xC000006A": "user name is correct but the password is wrong",
    "0xC0000234": "user is currently locked out",
    "0xC0000072": "account is currently disabled",
    "0xC000006F": "user tried to logon outside authorized hours",
    "0xC0000070": "workstation restriction",
    "0xC0000193": "account has expired",
    "0xC0000071": "expired password",
    "0xC0000133": "clocks between DC and other computer too far out of sync",
    "0xC0000224": "user is required to change password at next logon (or expired password)",
    "0xC0000225": "evidently a bug in Windows and not a risk",
    "0xC000015B": "user has not been granted the requested logon type",
}


def _first(values):
    for v in values or []:
        if v:
            return v
    return None


def _extract_field(events: list[dict], key: str):
    """Return the first non-empty value of `key` across events, or scan payload text."""
    for e in events or []:
        v = e.get(key)
        if v:
            return str(v)
    return None


def _is_cre_source(name) -> bool:
    """QRadar 'Custom Rule Engine' / CRE pseudo log-source — never a real onboarded source."""
    return bool(re.search(r"(?i)custom\s*rule\s*engine|\bCRE\b|rule\s*engine", str(name or "")))


def _leef_source(events: list[dict]):
    """Derive vendor/product from a LEEF header (LEEF:1.0|Vendor|Product|...)."""
    for e in events or []:
        for f in ("payload", "decoded_payload"):
            m = re.search(r"LEEF:\d+\.\d+\|([^|]+)\|([^|]+)\|", e.get(f) or "")
            if m:
                return f"{m.group(1).strip()} {m.group(2).strip()}".strip()
    return None


def _extract_log_source(events: list[dict]):
    """Pick the REAL onboarded log source that generated the events, skipping QRadar's
    Custom Rule Engine (CRE) pseudo-source. Falls back to LEEF-derived vendor/product."""
    real, cre = [], []
    for e in events or []:
        for key in ("log_source", "log_source_name", "logsourcename",
                    "device", "devicename", "log_source_type", "device_product"):
            v = e.get(key)
            if v:
                (cre if _is_cre_source(v) else real).append(str(v))
                break
    if real:
        return real[0]
    return _leef_source(events)  # never return the CRE pseudo-source


def _scan_payload_regex(events: list[dict], pattern: str, group: int = 0):
    import re as _re
    for e in events or []:
        for f in ("payload", "decoded_payload"):
            text = e.get(f) or ""
            m = _re.search(pattern, text)
            if m:
                try:
                    return m.group(group)
                except IndexError:
                    return m.group(0)
    return None


def _verdict_for(offense: dict, similar: list[dict] | None, iocs: dict,
                 mitre: list[dict], risk: int, ti: dict | None,
                 kb_matches: list[dict] | None) -> tuple[str, str]:
    """Return (verdict, reason). Verdict in {TP, FP, Suspicious}.

    Heuristics:
      - Confirmed malicious TI verdict → TP
      - Ransomware / exfil / cloud-account compromise (T1486/T1041/T1078.004) → TP
      - Historical closest match was FP AND risk<60 → FP
      - Rule name / KB matches contain phrases like "false positive", "expected", "policy" → FP
      - Risk < 30 and no external IPs / hashes → FP
      - Otherwise → Suspicious (verify)
    """
    similar = similar or []
    kb_matches = kb_matches or []
    ti_mal = ((ti or {}).get("verdicts", {}) or {}).get("malicious", 0)

    ttypes = {t.get("technique_id") for t in mitre}
    if ti_mal > 0:
        return "TP", f"Threat Intelligence confirmed {ti_mal} malicious indicator(s) linked to this offense."
    if any(t in ttypes for t in ("T1486", "T1041", "T1078.004")) or risk >= 85:
        return "TP", "High-risk technique observed (ransomware, exfiltration or account compromise) with strong evidence."

    fp_signals = []
    top_similar = similar[0] if similar else None
    if top_similar and top_similar.get("was_false_positive") and int(top_similar.get("similarity", 0)) >= 55:
        fp_signals.append(f"similar past incident (similarity {top_similar['similarity']}%) was closed as False Positive")

    kb_text_all = " ".join((m.get("text") or "").lower() for m in kb_matches)
    # De-obfuscate common HTML entities that appear in analyst-uploaded CSVs
    import html as _html
    try:
        kb_text_all = _html.unescape(kb_text_all)
    except Exception:
        pass
    fp_keywords = ("false positive", "expected activity", "known benign", "authorized",
                   "policy exception", "closed - benign", "closed as benign",
                   "closed benign", "no action required", "legitimate activity")
    if any(kw in kb_text_all for kw in fp_keywords):
        fp_signals.append("knowledge base flags this pattern as benign / authorized activity")
    # Additional signal: a matching KB row containing the same offense description AND the word "closed"
    off_desc = (offense.get("description") or "").lower()
    if off_desc and off_desc[:20] in kb_text_all and "closed" in kb_text_all:
        fp_signals.append("historical KB record shows a similar offense was resolved (Closed)")

    rule_text = " ".join((r or "").lower() for r in (offense.get("rules") or []))
    if any(kw in rule_text for kw in ("expected", "baseline", "test", "maintenance", "scheduled")):
        fp_signals.append("detection rule name suggests expected/baseline activity")

    if fp_signals and risk < 60:
        return "FP", "Likely False Positive — " + "; ".join(fp_signals) + "."

    if risk < 30 and not iocs.get("ipv4_external") and not (iocs.get("sha256") or iocs.get("md5")):
        return "FP", "Low risk, no external indicators, no malicious artefacts — most likely noise."

    reason_parts = []
    if risk >= 65:
        reason_parts.append(f"elevated risk score ({risk}/100)")
    if mitre:
        reason_parts.append(f"{len(mitre)} MITRE technique(s) mapped")
    if iocs.get("ipv4_external"):
        reason_parts.append(f"{len(iocs['ipv4_external'])} external IP(s) require verification")
    if top_similar:
        reason_parts.append(f"closest historical case ({top_similar['similarity']}%) suggests '{top_similar.get('recommendation') or 'monitor'}'")
    reason = "Suspicious — verify with the affected user/host. " + ("Signals: " + "; ".join(reason_parts) + "." if reason_parts else "Insufficient signal to auto-classify.")
    return "Suspicious", reason


def _generate_impact_lines(offense, events, payload_kv, src_ip, dst_ip,
                           username, machine_id) -> list[str]:
    """Deterministic 1-2 sentence business/technical impact, tailored by category.
    Used as the base impact (the LLM refines it; kept when the LLM leaves it empty)."""
    desc_l = (offense.get("description") or "").lower()
    ll = " ".join((offense.get("categories") or []) + (offense.get("rules") or [])).lower()
    host = machine_id or (payload_kv or {}).get("host") or src_ip or "the affected endpoint"
    pkv = payload_kv or {}
    url = pkv.get("domain_url") or pkv.get("url")
    action = str(pkv.get("action") or "").lower()
    if ("virus detected" in desc_l or "behavior monitoring" in desc_l
            or "startup program" in desc_l or "persistence" in ll or "new startup" in desc_l
            or (pkv.get("registry") and "run\\" in str(pkv.get("registry")).lower())):
        return [
            f"A new startup/autorun program was created on endpoint {host}, which could allow an "
            "application to execute automatically every time the system starts (persistence).",
            "Based on the available logs there is no evidence of a confirmed malware infection or "
            "endpoint compromise; the activity requires validation before closure.",
        ]
    if "phish" in desc_l or "phish" in ll:
        return [f"User {username or 'the user'} on host {host} accessed a site categorised as phishing, "
                "which could lead to credential theft or malware delivery if interacted with."]
    if _is_cti_feed(desc_l, ll):
        outbound = "outbound" in desc_l
        nat_ip = pkv.get("nat_destination_ip")
        if outbound:
            return [
                f"An internal host ({src_ip or 'source host'}) established communication with a "
                f"CTI-listed external IP address ({dst_ip or 'external IP'}).",
                "The observed activity may indicate malware command-and-control, data exfiltration, or "
                "communication with a known-malicious host.",
                "Since the connection was permitted by firewall policy, the internal host successfully "
                "reached the external malicious IP.",
            ]
        return [
            f"A CTI-listed IP address ({src_ip or 'the source IP'}) was able to establish communication "
            f"with an internally hosted service{f' ({nat_ip})' if nat_ip else ''} exposed through the firewall.",
            "The observed activity may indicate reconnaissance, scanning, service enumeration, or "
            "attempted exploitation against the exposed application.",
            "Since the connection was permitted by firewall policy, the destination host was reachable "
            "from the external source IP.",
        ]
    if url or "proxy" in ll or ("web" in ll and "url" not in ll) or "url" in ll:
        blocked = action in ("blocked", "block", "denied", "deny", "drop")
        if blocked:
            return [f"The web request from host {host} to {url or dst_ip} was blocked by the proxy, so no "
                    "compromise is expected; the block confirms the policy/threat category worked as intended."]
        return [f"Host {host} was able to reach {url or dst_ip}; if the destination is malicious this could "
                "lead to malware delivery, credential theft or data exposure and requires validation."]
    if "vpn" in ll or _is_login_failure(desc_l, ll):
        return [
            "Credential spraying or brute-force activity may result in unauthorized access if valid "
            "credentials are discovered.",
            f"Compromise of the targeted account could provide access to internal resources hosted on {host}.",
            "Repeated failed authentication attempts may lead to account lockouts and service disruption.",
        ]
    if "sql" in ll or "dam" in ll or "database" in ll:
        return [f"A database command was executed against {dst_ip or 'the target DB'}; if unauthorised it "
                "could impact data integrity or availability."]
    if "permit" in ll or "firewall" in ll or "traffic" in ll or action in ("allow", "accept", "permit"):
        return [f"The firewall permitted a connection between {src_ip or 'the source'} and "
                f"{dst_ip or 'the destination'}; if the traffic is not expected it could indicate "
                "unauthorised access or data movement and should be validated against policy."]
    return []


def build_mssp_report(offense: dict, similar: list[dict] | None = None,
                      iocs: dict | None = None, mitre: list[dict] | None = None,
                      risk: int | None = None, ti: dict | None = None,
                      kb_matches: list[dict] | None = None) -> dict:
    """Produce a structured MSSP-style analyst report from an offense.

    Returns a dict with the specific field ordering used by SOC L1 tickets:
    Offense ID / Offense Name / Severity / Date & Time / Source IP / Destination IP /
    Username / Event name / Low Level Category / Error Code / Event ID / Failure Reason /
    Machine Identifier / Log source / Analysis (numbered points) / Recommendation.
    """
    events = offense.get("events") or []
    similar = similar or []

    # Event-derived fields (prefer explicit event field, else scan payload)
    event_name = _extract_field(events, "event_name")
    low_level_category = (_extract_field(events, "low_level_category")
                          or _extract_field(events, "category"))
    error_code = (_extract_field(events, "error_code")
                  or _scan_payload_regex(events, r"(?:Status|Sub\s*Status|Error\s*Code)[:=]\s*(0x[0-9A-Fa-f]+)", 1)
                  or _scan_payload_regex(events, r"\b(0xC[0-9A-Fa-f]{7})\b", 1))
    event_id = (_extract_field(events, "windows_event_id")
                or _extract_field(events, "event_id")
                or _scan_payload_regex(events, r"Event\s*ID[:=]?\s*(\d{3,5})", 1))
    failure_reason = (_extract_field(events, "failure_reason")
                      or _scan_payload_regex(events, r"Failure\s*Reason[:=]\s*([^\n\r]+?)(?:\.\s|\s+Status|$)", 1))
    machine_id = (_extract_field(events, "machine_identifier")
                  or _extract_field(events, "hostname")
                  or _scan_payload_regex(events, r"Workstation(?:\s*Name)?[:=]\s*([A-Za-z0-9._-]+)", 1))

    # Enrich event name from Windows Event ID table
    if event_id and (not event_name or event_name.lower().startswith("event")):
        event_name = WINDOWS_EVENT_NAMES.get(str(event_id), event_name)

    log_source_name = _extract_log_source(events)
    log_source_str = None
    if log_source_name:
        if "@" in log_source_name or "::" in log_source_name:
            log_source_str = log_source_name
        else:
            _ls_ip = _extract_field(events, "log_source_ip") or _first(offense.get("destination_ips"))
            log_source_str = f"{log_source_name} @ {_ls_ip}" if _ls_ip else log_source_name

    payload_kv = _parse_payload_kv(events, offense=offense)
    custom_fields = payload_kv.pop("_custom", []) if isinstance(payload_kv.get("_custom"), list) else []
    src_ip = _first(offense.get("source_ips")) or payload_kv.get("source_ip")
    dst_ip = _first(offense.get("destination_ips")) or payload_kv.get("destination_ip")
    username = _first(offense.get("usernames")) or payload_kv.get("username")
    if not machine_id and payload_kv.get("host"):
        machine_id = payload_kv["host"]

    # Date formatting: "21 Jul 2026, 09:29:58"
    from datetime import datetime as _dt
    dt_str = None
    ts = offense.get("start_time")
    if ts:
        try:
            dt = _dt.fromisoformat(ts.replace("Z", "+00:00"))
            dt_str = dt.strftime("%d %b %Y, %H:%M:%S")
        except Exception:
            dt_str = ts

    # ---- Build Analysis (numbered narrative, context-aware) ----
    # Base fields always shown; optional fields only when present in event data.
    base_fields = [
        ("offense_id", "Offense ID"),
        ("offense_name", "Offense Name"),
        ("severity", "Severity"),
        ("date_time", "Date and time"),
    ]
    optional_fields = []
    if src_ip: optional_fields.append(("source_ip", "Source IP"))
    if dst_ip: optional_fields.append(("destination_ip", "Destination IP"))
    if username: optional_fields.append(("username", "Username"))
    if event_name: optional_fields.append(("event_name", "Event name"))
    if low_level_category: optional_fields.append(("low_level_category", "Low Level Category"))
    if error_code: optional_fields.append(("error_code", "Error Code"))
    if event_id: optional_fields.append(("event_id", "Event ID"))
    if failure_reason: optional_fields.append(("failure_reason", "Failure Reason"))
    if machine_id: optional_fields.append(("machine_identifier", "Machine Identifier"))
    if log_source_str: optional_fields.append(("log_source", "Log source"))

    # Discover NEW fields dynamically from event payloads (LLM-style extraction via regex).
    # Prepend the LEEF/key=value parsed fields (ports, protocol, action, rule name).
    pkv_fields = []
    if payload_kv.get("source_port"): pkv_fields.append(("Source Port", payload_kv["source_port"]))
    if payload_kv.get("destination_port"): pkv_fields.append(("Destination Port", payload_kv["destination_port"]))
    if payload_kv.get("protocol"): pkv_fields.append(("Protocol", payload_kv["protocol"]))
    if payload_kv.get("action"): pkv_fields.append(("Action", payload_kv["action"]))
    if payload_kv.get("rule_name"): pkv_fields.append(("Rule Name", payload_kv["rule_name"]))
    if payload_kv.get("policy_name") and payload_kv.get("policy_name") != payload_kv.get("rule_name"):
        pkv_fields.append(("Policy Name", payload_kv["policy_name"]))
    if payload_kv.get("source_zone"): pkv_fields.append(("Source Zone", payload_kv["source_zone"]))
    if payload_kv.get("dest_zone"): pkv_fields.append(("Destination Zone", payload_kv["dest_zone"]))
    if payload_kv.get("session_id"): pkv_fields.append(("Session ID", payload_kv["session_id"]))
    if payload_kv.get("session_end_reason"): pkv_fields.append(("Session End Reason", payload_kv["session_end_reason"]))
    if payload_kv.get("packets"): pkv_fields.append(("Total Packets", payload_kv["packets"]))
    if payload_kv.get("process"): pkv_fields.append(("Process", payload_kv["process"]))
    if payload_kv.get("file_path"): pkv_fields.append(("File Path", payload_kv["file_path"]))
    if payload_kv.get("registry"): pkv_fields.append(("Registry", payload_kv["registry"]))
    if payload_kv.get("host"): pkv_fields.append(("Host", payload_kv["host"]))
    if payload_kv.get("operation"): pkv_fields.append(("Operation", payload_kv["operation"]))
    if payload_kv.get("risk_level"): pkv_fields.append(("Risk Level", payload_kv["risk_level"]))
    if payload_kv.get("event_type"): pkv_fields.append(("Event Type", payload_kv["event_type"]))
    if payload_kv.get("application"): pkv_fields.append(("Application", payload_kv["application"]))
    if payload_kv.get("bytes"): pkv_fields.append(("Bytes", payload_kv["bytes"]))
    if payload_kv.get("post_nat_source_ip"): pkv_fields.append(("Post NAT Source IP", payload_kv["post_nat_source_ip"]))
    if payload_kv.get("post_nat_destination_ip"): pkv_fields.append(("Post NAT Destination IP", payload_kv["post_nat_destination_ip"]))
    if payload_kv.get("domain_url"): pkv_fields.append(("Domain URL", payload_kv["domain_url"]))
    if payload_kv.get("content_type"): pkv_fields.append(("Content Type", payload_kv["content_type"]))
    for lbl, val in custom_fields:
        pkv_fields.append((lbl, val))
    discovered = pkv_fields + _structured_event_fields(events) + _discover_extra_fields(events)
    _seen_lbl = set()
    discovered = [(l, v) for (l, v) in discovered if not (l in _seen_lbl or _seen_lbl.add(l))]
    for label, value in discovered:
        key = f"x_{label.lower().replace(' ', '_')}"
        optional_fields.append((key, label))
        # attach value directly on the report dict below

    fields = base_fields + optional_fields

    analysis_lines = _generate_analysis_lines(offense, events, similar, kb_matches or [],
                                              iocs or {}, mitre or [],
                                              src_ip, dst_ip, username, event_name,
                                              failure_reason, error_code, log_source_str,
                                              machine_id, dt_str)

    # Recommendation text (short human-readable)
    rec_map = {
        "Close Benign": "Close as benign after user confirmation.",
        "False Positive": "Close as false positive; recommend detection tuning.",
        "Monitor": "Keep in monitoring queue for 24 hours.",
        "Escalate L2": "Escalate to L2 for deeper analysis.",
        "Escalate L3": "Escalate to L3 SME.",
        "IR Required": "Engage Incident Response team immediately.",
        "Contain Immediately": "Isolate the affected host/account and engage IR.",
    }
    rec_str = None  # filled by caller from `analyze_offense` recommendation

    # Verdict (TP/FP/Suspicious)
    verdict = None
    verdict_reason = None
    if risk is not None:
        verdict, verdict_reason = _verdict_for(offense, similar, iocs or {}, mitre or [], int(risk), ti, kb_matches)

    # Per-offense, verdict-aware 2-3 recommendation bullets
    recommendations = _generate_recommendations(offense, verdict, iocs or {}, mitre or [],
                                                username, src_ip, dst_ip, machine_id,
                                                success_present=any("success" in (e.get("event_name") or "").lower()
                                                                    or "success" in (e.get("low_level_category") or "").lower()
                                                                    for e in events))

    report_dict = {
        "offense_id": offense.get("qradar_offense_id") or offense.get("id"),
        "offense_name": offense.get("description"),
        "severity": offense.get("severity_label"),
        "date_time": dt_str,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "username": username,
        "event_name": event_name,
        "low_level_category": low_level_category,
        "error_code": error_code,
        "event_id": event_id,
        "failure_reason": failure_reason,
        "machine_identifier": machine_id,
        "log_source": log_source_str,
        "fields": fields,
        "analysis_lines": analysis_lines,
        "impact_lines": _generate_impact_lines(offense, events, payload_kv, src_ip, dst_ip,
                                                username, machine_id),
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "recommendations": recommendations,
        "recommendation_text": rec_str,
    }
    # Attach discovered field values on the report so the UI can render them
    for label, value in discovered:
        key = f"x_{label.lower().replace(' ', '_')}"
        report_dict.setdefault(key, value)
    return report_dict


def _parse_payload_kv(events: list[dict], offense: dict | None = None) -> dict:
    """Extract SOC fields from event payloads AND the offense description text.
    Handles LEEF/CEF `key=value`, `Key: Value`, QRadar summary text
    ("Source IP(s) 1.2.3.4", "Destination IP(s) 5.6.7.8") and QRadar
    "(custom)" properties ("Action Taken (custom) Assess", "Asset Name (custom) HOST",
    "File Path (custom) C:\\..."). Custom properties are returned under "_custom"
    as [(label, value), ...] so the report can surface them as extra fields."""
    import re as _re
    payload_parts = [str(e.get("decoded_payload") or e.get("payload") or "") for e in events or []]
    ev_desc = " ".join(str(e["event_description"]) for e in events or [] if e.get("event_description"))
    payload_text = "\n".join(p for p in payload_parts if p)
    desc_text = str(offense["description"]) if offense and offense.get("description") else ""
    # key=value / Key: Value parsing runs ONLY on structured logs (payload + event desc),
    # never on the free-text offense description (prevents values bleeding into it).
    kv_source = "\n".join(x for x in [payload_text, ev_desc] if x)
    # `text` (used for IP-label lookups + QRadar "(custom)" properties) may include the description.
    text = "  ".join(x for x in [payload_text, ev_desc, desc_text] if x)
    if not text:
        return {}

    kv: dict[str, str] = {}
    for m in _re.finditer(r"([A-Za-z_][A-Za-z0-9_.]*)=([^=]*?)(?=\s+[A-Za-z_][A-Za-z0-9_.]*=|\s{2,}|[\n\r]|$)", kv_source):
        k = m.group(1).strip().lower()
        v = m.group(2).strip().strip('"').strip("'")
        if v and k not in kv:
            kv[k] = v
    for m in _re.finditer(r"([A-Za-z][A-Za-z _]{1,30}?)\s*:\s*([^\n\r]+?)(?:\s{2,}|[\n\r]|$)", kv_source):
        k = m.group(1).strip().lower().replace(" ", "_")
        v = m.group(2).strip()
        if v and k not in kv:
            kv[k] = v

    def pick(*names):
        for n in names:
            if kv.get(n):
                return kv[n]
        return None

    def find_ip(label):
        m = _re.search(r"(?i)" + label + r"\s*IP\(?s?\)?\s*[:(]*\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]{4,})", text)
        return m.group(1) if m else None

    # QRadar "(custom)" properties
    custom: list[tuple[str, str]] = []
    seen = set()
    for m in _re.finditer(
        r"([A-Za-z][A-Za-z0-9 _/]{1,30}?)\s*\(custom\)\s*(.+?)"
        r"(?=\s+[A-Za-z][A-Za-z0-9 _/]{1,30}?\s*\(custom\)|\s+Log Source\b|\s+Offense\b|\s+Event Description\b|\s+Destination IP\b|$)",
        text):
        lbl = m.group(1).strip()
        val = m.group(2).strip()
        if not val or lbl.lower() in seen:
            continue
        seen.add(lbl.lower())
        custom.append((lbl, val[:300]))

    def ev_get(*keys):
        for k in keys:
            for e in events or []:
                v = e.get(k)
                if v not in (None, "", "0.0.0.0", "0"):
                    return v
        return None

    proto = ev_get("protocol") or pick("proto", "protocol", "protocolname")
    if proto and str(proto).isdigit():
        proto = {"1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP"}.get(str(proto), str(proto))
    action = pick("action", "rule_action", "act")
    if not action:
        for lbl, val in custom:
            if "action" in lbl.lower():
                action = val
                break

    # CEF custom-string label/value pairs (csNLabel=Rule_Name  csN=New Startup Program).
    cef_labeled: dict[str, str] = {}
    for k in list(kv):
        lm = _re.fullmatch(r"(cs\d+|cn\d+|c6a\d+|flexstring\d+)label", k)
        if lm and kv.get(lm.group(1)):
            lbl = kv[k].strip().lower().replace(" ", "_").replace("-", "_")
            cef_labeled[lbl] = kv[lm.group(1)]

    # Endpoint/EDR artifacts (Trend Micro Apex, Sysmon, CEF): process image, file path,
    # registry autorun target and detected host — needed to ground malware/persistence alerts.
    proc = pick("sproc", "deviceprocessname", "dproc", "process", "image", "processname")
    file_path = None
    if proc and ("\\" in proc or "/" in proc or proc.lower().endswith(".exe") or proc.lower().endswith(".tmp")):
        file_path = proc
    file_path = file_path or pick("filepath", "fpath", "filename", "fname")
    registry = pick("tmcmlogtarget", "targetobject", "registry")
    if not registry:
        rm = IOC_PATTERNS["registry"].search(text)
        registry = rm.group(0) if rm else None
    if registry and not _re.match(r"(?i)HK(LM|CU|CR|U|CC)\\", registry):
        registry = None
    host = pick("tmcmlogdetectedhost", "shost", "computername", "hostname", "dvchost")
    if host and _re.fullmatch(r"[0-9.]+", host):
        host = None
    domain = pick("dntdom", "devicentdomain", "ntdomain")

    # Palo Alto / firewall session fields (zones, NAT, policy, session, packets).
    def _nz(v):
        return v if v not in (None, "", "0", "0.0.0.0") else None
    nat_dst = (_nz(ev_get("postnatdestinationip"))
               or pick("postnatdestinationip", "dnat", "postnatdst", "nat_destination_ip", "translateddst"))
    src_zone = pick("srczone", "src_zone", "sourcezone", "source_zone", "fromzone", "from_zone", "szone")
    dst_zone = pick("dstzone", "dst_zone", "destinationzone", "destination_zone", "tozone", "to_zone", "dzone")
    policy_name = pick("policy_name", "policyname", "policy", "rule", "rulename", "rule_name", "sec_rule")
    session_id = pick("session_id", "sessionid", "sessid", "session")
    session_end = pick("session_end_reason", "sessionendreason", "reason", "sessendreason")
    packets = pick("packets", "totalpackets", "total_packets", "pkts", "packets_total")

    # Structured event fields take priority, then payload key=value, then description text.
    out = {
        "source_ip": ev_get("sourceip", "source_ip") or pick("src", "source_ip", "sourceip", "source_address", "shost", "client_ip") or find_ip("source"),
        "destination_ip": ev_get("destinationip", "destination_ip") or pick("dst", "destination_ip", "destinationip", "dest_ip", "dhost") or find_ip("destination"),
        "source_port": ev_get("sourceport") or pick("srcport", "source_port", "sport", "spt"),
        "destination_port": ev_get("destinationport") or pick("dstport", "destination_port", "dport", "dpt"),
        "protocol": proto,
        "action": action,
        "rule_name": cef_labeled.get("rule_name") or pick("rule_name", "rulename"),
        "policy_name": policy_name,
        "source_zone": src_zone,
        "dest_zone": dst_zone,
        "nat_destination_ip": nat_dst,
        "session_id": session_id,
        "session_end_reason": session_end,
        "packets": packets,
        "process": proc,
        "file_path": file_path,
        "registry": registry,
        "host": host,
        "operation": cef_labeled.get("operation"),
        "risk_level": cef_labeled.get("risk_level"),
        "event_type": cef_labeled.get("event_type"),
        "domain": domain,
        "username": ev_get("username") or pick("usrname", "username", "user", "suser", "duser", "account_name", "src_user"),
        "application": ev_get("application", "app") or pick("app", "application", "appname", "requestclientapplication"),
        "bytes": pick("bytes", "byte", "in", "out", "bytesin", "bytesout"),
        "post_nat_source_ip": ev_get("postnatsourceip"),
        "post_nat_destination_ip": ev_get("postnatdestinationip"),
        "domain_url": ev_get("domain_url", "domainurl", "url") or pick("domain_url", "url", "domain", "dhost"),
        "http_method": pick("method", "http_method", "requestmethod", "httpmethod"),
        "url_category": pick("urlcategory", "url_category", "category", "cat", "webcategory"),
        "logon_type": pick("logontype", "logon_type"),
        "workstation": pick("workstationname", "workstation", "ws", "src_host"),
        "status_code": pick("status", "substatus", "resultcode", "errorcode"),
        "content_type": ev_get("content_type", "contenttype") or pick("content_type", "contenttype"),
        "event_name": ev_get("event_name"),
        "low_level_category": ev_get("category_name") or pick("low_level_category"),
        "log_source": ev_get("log_source", "logsource"),
    }
    res = {k: v for k, v in out.items() if v}
    if custom:
        res["_custom"] = custom
    return res


def _structured_event_fields(events: list[dict]) -> list[tuple[str, str]]:
    """Surface analyst-critical fields directly from structured event keys (Sysmon/EDR
    style) so process, command line, file hash, host, etc. are never missed even when
    they aren't in the free-text payload."""
    label_map = [
        ("process", "Process"), ("process_name", "Process"), ("image", "Process"),
        ("parent_process", "Parent Process"), ("parent_image", "Parent Process"),
        ("command_line", "Command Line"), ("commandline", "Command Line"),
        ("process_command_line", "Command Line"),
        ("file_hash", "File Hash"), ("sha256", "SHA256"), ("sha1", "SHA1"), ("md5", "MD5"),
        ("file_name", "File Name"), ("filename", "File Name"), ("file_path", "File Path"),
        ("host", "Host"), ("hostname", "Host"),
        ("registry", "Registry"), ("url", "URL"), ("query", "Query"),
    ]
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, label in label_map:
        if label in seen:
            continue
        for e in events or []:
            v = e.get(key) if isinstance(e, dict) else None
            if v not in (None, "", "0", "0.0.0.0", "-"):
                out.append((label, str(v)[:250]))
                seen.add(label)
                break
    return out


def _discover_extra_fields(events: list[dict]) -> list[tuple[str, str]]:
    """Scan event payloads and pull out additional analyst-useful fields.
    Returns [(label, value), ...] with de-duped values."""
    if not events:
        return []
    text = " ".join(
        [str(e.get("payload") or "") + " " + str(e.get("decoded_payload") or "") for e in events]
    )
    text += " " + " ".join(
        [f"{k}={v}" for e in events for k, v in e.items() if k in ("process", "parent_process", "command_line", "url", "file_hash", "registry", "protocol")]
    )
    import re as _re
    import html as _html
    text = _html.unescape(text)

    patterns = [
        ("SQL Command", r"SQL\s*Command\s*[:=]\s*([^\n\r]+?)(?:\s{2,}|Log Source|$)"),
        ("URL", r"URL[:=]\s*(https?://\S+)"),
        ("Request Path", r"Request\s*Path[:=]\s*(\S+)"),
        ("HTTP Method", r"\bMethod[:=]\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b"),
        ("Response Code", r"Response\s*Code[:=]\s*(\d{3})"),
        ("ASN", r"ASN[:=]\s*([^\n\r]+?)(?:\s{2,}|City|Log Source|$)"),
        ("User Agent", r"User\s*Agent[:=]\s*([^\n\r]+?)(?:\s{2,}|Log Source|$)"),
        ("Process", r"(?:New\s*Process\s*Name|ProcessName|Image|ProgramName|Process(?:\s*Name)?)\s*[:=]\s*([^\n\r,;]+)"),
        ("Parent Process", r"(?:ParentImage|ParentProcessName|parent_process)\s*[:=]\s*([^\n\r,;]+)"),
        ("Command Line", r"(?:CommandLine|command_line|Command\s*Line|Process\s*Command\s*Line)\s*[:=]\s*([^\n\r]+?)(?:\s{2,}|$)"),
        ("File Hash", r"\b(?:file[_ ]?hash|hashes?|SHA[- ]?256|SHA[- ]?1|MD5)\s*[:=]\s*([a-fA-F0-9]{32,64})\b"),
        ("File Name", r"\b(?:file[_ ]?name|file)\s*[:=]\s*([^\s,]+)"),
        ("Destination Port", r"Destination\s*Port[:=]\s*(\d+)"),
        ("Source Port", r"Source\s*Port[:=]\s*(\d+)"),
        ("Protocol", r"\bProtocol[:=]\s*(TCP|UDP|ICMP|HTTPS?)\b"),
        ("Device Serial", r"Serial[:=]\s*([A-Za-z0-9]+)"),
        ("Logon Type", r"Logon\s*Type[:=]?\s*(\d+)"),
        ("City", r"City[:=]\s*([^\n\r]+?)(?:\s{2,}|DST|Log Source|$)"),
        ("Bytes Transferred", r"(\d+(?:\.\d+)?\s*(?:MB|GB|KB))\s*(?:transferred|outbound)"),
    ]
    found: list[tuple[str, str]] = []
    seen_labels = set()
    for label, pat in patterns:
        if label in seen_labels:
            continue
        m = _re.search(pat, text, _re.IGNORECASE)
        if m:
            val = m.group(1).strip().strip('"').strip("'")
            if val and len(val) < 250:
                found.append((label, val))
                seen_labels.add(label)
    return found


# ---- Context-aware analysis + recommendation helpers ----
_CTI_FEED_RE = re.compile(r"\b(cti|rbi[_ ]?ioc)\b|ip[_ ]?feeds?\b", re.IGNORECASE)


def _is_cti_feed(*texts) -> bool:
    """True only for genuine CTI / threat-intel IP-feed offenses (word-boundary match,
    so it never fires on substrings like 'aCTIvity')."""
    return any(t and _CTI_FEED_RE.search(str(t)) for t in texts)


_LOGON_TYPES = {"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
                "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
                "10": "RemoteInteractive/RDP", "11": "CachedInteractive"}
_STATUS_MEANINGS = {
    "0xc000006d": "a bad username or invalid authentication information",
    "0xc000006a": "an incorrect password", "0xc0000064": "the username does not exist",
    "0xc0000234": "the account is locked out", "0xc0000072": "the account is disabled",
    "0xc0000193": "the account has expired", "0xc0000071": "the password has expired",
    "0xc000015b": "the user is not allowed the requested logon type"}


def _is_login_failure(*texts) -> bool:
    j = " ".join(str(t or "").lower() for t in texts)
    return ("brute" in j or "spray" in j or "login failure" in j or "logon failure" in j
            or ("multiple" in j and ("fail" in j or "login" in j)))


def _cti_feed_analysis(offense, events, src_ip, dst_ip, dt_str, log_source_str):
    """MSSP L1 narrative for CTI/threat-intel IP-feed firewall-permit offenses
    (inbound or outbound). Field-driven: each sentence is emitted only when its
    supporting artifact (zone/policy/NAT/session/bytes) is present in the event."""
    pkv = _parse_payload_kv(events, offense)
    desc = re.sub(r"\s+", " ", (offense.get("description") or "")).strip()
    name = re.split(r"(?i)\s+containing\s+", desc)[0].strip() or desc
    lower = desc.lower()
    outbound = "outbound" in lower
    inbound = ("inbound" in lower) or not outbound
    direction_word = "inbound" if inbound else "outbound"
    proto = pkv.get("protocol") or "TCP"
    app = pkv.get("application")
    dport = pkv.get("destination_port")
    nat_ip = pkv.get("nat_destination_ip")
    policy = pkv.get("policy_name") or pkv.get("rule_name")
    szone = pkv.get("source_zone")
    dzone = pkv.get("dest_zone")
    action = pkv.get("action") or "Allow"
    bytes_ = pkv.get("bytes")
    packets = pkv.get("packets")
    sess_reason = pkv.get("session_end_reason")
    fw = None
    if log_source_str and not _is_cre_source(log_source_str):
        fw = log_source_str.split("::")[0].strip()

    lines: list[dict] = []
    _n = [0]

    def add(t):
        _n[0] += 1
        lines.append({"n": _n[0], "text": t})

    when = f' on "{dt_str}"' if dt_str else ""
    add(f'We have observed an offense "{name}" triggered{when}.')
    add(f'On {dt_str or "the reported time"}, an {direction_word} connection associated with a '
        f'CTI-monitored IP address was observed' + (f' on firewall "{fw}"' if fw else "") + ".")

    conn = (f'We observed a permitted {direction_word} {(app + " ") if app else ""}'
            f'connection from source IP {src_ip} to destination')
    if nat_ip:
        conn += f' public IP {dst_ip}, which was translated to internal host {nat_ip}'
    else:
        conn += f' IP {dst_ip}'
    conn += f' over {proto} port {dport}.' if dport else '.'
    add(conn)

    if policy:
        add(f'The communication was allowed through firewall policy {policy}.')
    if szone and dzone:
        rel = "external-to-internal" if inbound else "internal-to-external"
        add(f'The traffic originated from Source Zone {szone} and was directed towards '
            f'Destination Zone {dzone}, indicating {rel} network communication.')
    add(f'The firewall action was recorded as {action}, confirming that the connection was '
        'permitted based on the configured security policy.')
    matched_ip = src_ip if inbound else dst_ip
    add(f'The offense was generated because the {"source" if inbound else "destination"} IP '
        f'{matched_ip} matched an indicator present within the configured Threat Intelligence (CTI) feeds.')
    if bytes_ or packets or sess_reason:
        seg = "The session"
        if bytes_:
            seg += f" exchanged {bytes_}"
        if packets:
            seg += (" across" if bytes_ else " comprised") + f" {packets} packets"
        if sess_reason:
            seg += f" and was logged with Session End Reason: {sess_reason}"
        add(seg + ".")
    return lines


def _generate_analysis_lines(offense, events, similar, kb_matches, iocs, mitre,
                             src_ip, dst_ip, username, event_name, failure_reason,
                             error_code, log_source_str, machine_id, dt_str):
    """Produce a numbered analysis matching the ITSM_Analysis style from analyst KB.

    Line 1: what happened (offense name, when, who, from where)
    Line 2: technical details (protocol/port/URL/SQL/error meaning)
    Line 3: correlation/observation (success logins, historical KB match, IOC data)
    Line 4: verdict + verify-the-legitimacy call to action
    """
    desc = re.sub(r"\s+", " ", str(offense.get("description") or "Offense")).strip()
    rules = offense.get("rules") or []
    lines: list[dict] = []
    lower_desc = desc.lower()
    ll = " ".join((offense.get("categories") or []) + rules).lower()

    # CTI IP-feed firewall permit (inbound/outbound) — dedicated MSSP narrative.
    if _is_cti_feed(lower_desc, ll):
        return _cti_feed_analysis(offense, events, src_ip, dst_ip, dt_str, log_source_str)

    # Line 1 — canonical opener
    when = f" on {dt_str}" if dt_str else ""
    lines.append({"n": 1, "text": f'An offense "{desc}" was triggered{when}.'})

    # Line 2+ — technical detail, tailored by category and GROUNDED in extracted fields.
    import re as _re2
    pkv = _parse_payload_kv(events, offense)
    payloads = " ".join(str(e.get("decoded_payload") or e.get("payload") or "") for e in events).lower()
    host = machine_id or pkv.get("host") or pkv.get("workstation") or src_ip
    action = pkv.get("action")
    url = pkv.get("domain_url") or pkv.get("url")
    app = pkv.get("application")
    proto = pkv.get("protocol")
    dport = pkv.get("destination_port")
    sport = pkv.get("source_port")

    def _priv(ip):
        return bool(ip) and (str(ip).startswith("10.") or str(ip).startswith("192.168.")
                             or bool(_re2.match(r"172\.(1[6-9]|2\d|3[01])\.", str(ip))))

    def _grounded(exclude=()):  # extra sentences for artifacts not already narrated
        s = []
        proc = pkv.get("file_path") or pkv.get("process")
        if proc and "process" not in exclude:
            s.append(f"The activity involved {proc} on host {host}.")
        if pkv.get("registry") and "registry" not in exclude:
            s.append(f"A registry autorun entry was observed at {pkv['registry']}.")
        if url and "url" not in exclude:
            seg = f"The request targeted {url}"
            if pkv.get("http_method"):
                seg += f" using HTTP {pkv['http_method']}"
            if pkv.get("url_category"):
                seg += f" (category {pkv['url_category']})"
            s.append(seg + ".")
        if "conn" not in exclude and (dport or app or (proto and (src_ip or dst_ip))):
            parts = []
            if app:
                parts.append(f"application {app}")
            if proto:
                parts.append(f"protocol {str(proto).upper()}")
            seg = "The connection used " + (", ".join(parts) if parts else "the observed protocol")
            if dport:
                seg += f" on destination port {dport}"
            if sport:
                seg += f" (source port {sport})"
            s.append(seg + ".")
        if action and "action" not in exclude:
            s.append(f"The device action recorded was '{action}'.")
        return s

    l2 = None
    extra_lines: list[str] = []

    if "sql" in ll or "dam" in ll or "database" in ll:
        m = _extract_field(events, "process")
        sql = _scan_payload_regex(events, r"SQL\s*Command\s*[:=]\s*([^\n\r]+?)(?:\s{2,}|Log Source|$)", 1)
        l2 = (f"Database user '{username}' from host {src_ip} executed on target DB {dst_ip}"
              + (f" via {m}" if m else "")
              + (f" the SQL command: {sql!r}." if sql else "."))
        extra_lines = _grounded(exclude=("conn",))
    elif "phish" in lower_desc or "phish" in ll:
        l2 = (f"User '{username}' from host {src_ip} accessed the flagged URL {url}." if url
              else f"User '{username}' from host {src_ip} was flagged accessing a phishing category site.")
        extra_lines = _grounded(exclude=("url",))
    elif "cloud" in ll or "upload" in ll:
        l2 = f"User '{username}' from host {src_ip} uploaded content to {url or dst_ip}."
        extra_lines = _grounded(exclude=("url",))
    elif url or "proxy" in ll or "web" in ll or "url" in ll or "http" in ll:
        verbed = {"blocked": "blocked", "block": "blocked", "denied": "blocked", "deny": "blocked",
                  "allowed": "permitted", "allow": "permitted", "permit": "permitted"}.get(
                      str(action or "").lower(), action or "observed")
        who = f"user '{username}'" if username and str(username).lower() != "none" else "an internal host"
        l2 = (f"A web request from {who} on host {src_ip} to {url or dst_ip} was {verbed}"
              + (f" by {log_source_str}" if log_source_str else "") + ".")
        extra_lines = _grounded(exclude=("url", "action"))
    elif "brute" in ll or "spray" in ll or _is_login_failure(lower_desc, ll) or \
            ("fail" in ll and "logon" in str(event_name or "").lower()):
        is_admin = ("admin" in str(username or "").lower() or "admin" in lower_desc
                    or "administrator" in lower_desc)
        acct = f"the privileged account '{username}'" if is_admin else f"user '{username}'"
        l2 = (f"Multiple failed authentication attempts were observed for {acct} "
              f"from source IP {src_ip} against host {dst_ip or host}.")
        lt, stt, wkst = pkv.get("logon_type"), pkv.get("status_code"), pkv.get("workstation")
        if lt or stt or wkst:
            seg = "The failed logon"
            if lt:
                lname = _LOGON_TYPES.get(str(lt))
                seg += f" used Logon Type {lt}" + (f" ({lname})" if lname else "")
            if wkst:
                seg += (", from" if lt else " from") + f" workstation {wkst}"
            if stt:
                mean = _STATUS_MEANINGS.get(str(stt).lower())
                seg += ((" and returned" if (lt or wkst) else " returned")
                        + f" status code {stt}" + (f", indicating {mean}" if mean else ""))
            extra_lines.append(seg + ".")
        extra_lines.append(
            "Repeated failures against "
            + ("a privileged/administrator account" if is_admin else "the account")
            + " can indicate password-spraying or brute-force activity; historically, similar alerts "
            "have often been legitimate administrator activity or stale/expired credentials and require "
            "confirmation with the account owner.")
    elif "vpn" in ll:
        failed = [e for e in events if "fail" in (e.get("event_name") or "").lower()]
        succ = [e for e in events if "success" in (e.get("event_name") or "").lower()]
        u_fail = sorted({e.get("username") for e in failed if e.get("username")})
        u_succ = sorted({e.get("username") for e in succ if e.get("username")})
        l2 = (f"Source IP {src_ip} attempted VPN authentication for user(s) [{', '.join(u_fail)}]"
              + (f" and successfully signed in as [{', '.join(u_succ)}]" if u_succ else "")
              + f" against VPN gateway {dst_ip}.")
    elif "expired" in lower_desc or (error_code and error_code.lower() == "0xc0000224"):
        l2 = (f"The event indicates the user's password has expired (Error Code: {error_code}, "
              f"Failure Reason: {failure_reason})." if failure_reason
              else f"The event indicates an expired-password login failure (Error Code: {error_code}).")
    elif "ransom" in ll or "ransom" in lower_desc:
        h = _first(iocs.get("sha256") or iocs.get("md5") or iocs.get("sha1"))
        l2 = f"Ransomware activity was detected on host {machine_id or dst_ip}" + (f" with file hash {h}" if h else "") + "."
        extra_lines = _grounded(exclude=("conn",))
    elif (("virus detected" in lower_desc) or ("behavior monitoring" in lower_desc)
          or ("startup program" in lower_desc) or ("new startup" in lower_desc)
          or ("persistence" in ll) or ("autorun" in payloads) or ("autostart" in payloads)
          or (pkv.get("registry") and "run\\" in str(pkv.get("registry")).lower())):
        fpath = pkv.get("file_path") or pkv.get("process")
        reg = pkv.get("registry")
        act = pkv.get("action")
        op = pkv.get("operation")
        h2 = machine_id or pkv.get("host") or src_ip
        tool = log_source_str.split("@")[0].strip() if log_source_str else "The endpoint security tool"
        who = (f" for user '{username}'" if username and str(username).lower() != "none" else "")
        l2 = (f"{tool} detected a Behavior Monitoring event on host {h2}{who}, "
              "related to the creation of a new startup/autorun program.")
        if reg:
            extra_lines.append(
                f"A new startup entry was {'written to' if op else 'added under'} the registry key {reg}"
                + (f", pointing to the file {fpath}" if fpath else "") + ".")
        elif fpath:
            extra_lines.append(f"The detected file is {fpath}.")
        if fpath:
            low = str(fpath).lower().replace("/", "\\").replace("\\\\", "\\")
            loc = ("the user's temporary directory" if "\\temp\\" in low or "\\tmp\\" in low
                   else "the user's local application-data directory" if "appdata\\local" in low
                   else "the user's roaming application-data directory" if "appdata\\roaming" in low
                   else "a user-writable profile directory" if "\\users\\" in low else None)
            if loc:
                extra_lines.append(f"The file resides in {loc}, which is used by both legitimate "
                                   "installers and malware and therefore requires validation.")
        if act:
            extra_lines.append(f"The device action was '{act}', meaning {tool} detected and evaluated "
                               "the activity per policy without automatically blocking or removing it.")
        extra_lines.append("Based on the available logs there is no evidence that the file is confirmed "
                           "malicious or that the endpoint has been compromised; the activity requires "
                           "validation before closure.")
    elif "usb" in ll or "removable" in ll:
        l2 = f"User '{username}' wrote files to a removable device on host {machine_id or src_ip}."
        extra_lines = _grounded()
    elif ("permit" in ll or "firewall" in ll or "traffic" in ll or "accept" in ll or "deny" in ll
          or str(action or "").lower() in ("allow", "accept", "deny", "drop", "permit")):
        if "outbound" in lower_desc:
            direction = "outbound"
        elif "inbound" in lower_desc:
            direction = "inbound"
        elif _priv(src_ip) and not _priv(dst_ip):
            direction = "outbound"
        elif _priv(dst_ip) and not _priv(src_ip):
            direction = "inbound"
        else:
            direction = "network"
        fw = log_source_str.split("@")[0].strip() if log_source_str else "The firewall"
        _verbmap = {"allow": "allowed", "accept": "accepted", "permit": "permitted",
                    "deny": "denied", "drop": "dropped", "block": "blocked"}
        verb = _verbmap.get(str(action or "").lower(), action or "permitted")
        art = "an" if direction and direction[0] in "aeiou" else "a"
        l2 = (f"{fw} {verb} {art} {direction} {(app + ' ') if app else ''}connection from {src_ip} to {dst_ip}"
              + (f" over {str(proto).upper()} port {dport}" if dport else "") + ".")
        pol = pkv.get("policy_name") or pkv.get("rule_name")
        if pol:
            extra_lines.append(f"The traffic matched firewall policy {pol}.")
        if pkv.get("source_zone") and pkv.get("dest_zone"):
            extra_lines.append(f"It traversed from zone {pkv['source_zone']} to zone {pkv['dest_zone']}.")
        if pkv.get("bytes") or pkv.get("packets"):
            seg = "The session"
            if pkv.get("bytes"):
                seg += f" transferred {pkv['bytes']} bytes"
            if pkv.get("packets"):
                seg += (" across" if pkv.get("bytes") else " comprised") + f" {pkv['packets']} packets"
            extra_lines.append(seg + ".")
    elif "tunnel" in ll or "dns tunnel" in lower_desc or ("dns" in ll and "exfil" in ll):
        dom = _first(iocs.get("domain")) or url
        l2 = f"Unusual DNS activity was observed from {src_ip}" + (f" to {dom}" if dom else "") + "."
        extra_lines = _grounded(exclude=("url",))
    elif event_name:
        who = f"user '{username}'" if username and str(username).lower() != "none" else "the endpoint"
        dst_seg = f" to {dst_ip}" if dst_ip else ""
        l2 = (f"The event '{event_name}' was observed for {who} from {src_ip}{dst_seg}"
              + (f" via {log_source_str}" if log_source_str else "") + ".")
        extra_lines = _grounded()
    else:
        l2 = f"Rule(s) triggered: {', '.join(rules) or 'unspecified'}."
        extra_lines = _grounded()
    lines.append({"n": 2, "text": l2})
    for s in extra_lines:
        lines.append({"n": len(lines) + 1, "text": s})

    # Line 3 — correlation / KB / historical
    success_present = any("success" in (e.get("event_name") or "").lower()
                          or "success" in (e.get("low_level_category") or "").lower() for e in events)
    if success_present:
        lines.append({"n": len(lines) + 1, "text": "On checking the logs for the user we have observed success logins after the failed ones. Kindly check the legitimacy of the user."})

    # Line 4 — closing call to action
    lines.append({"n": len(lines) + 1, "text": "Verify the legitimacy of the alert with the affected user/host owner before closing."})
    return lines


def _generate_recommendations(offense, verdict, iocs, mitre, username, src_ip, dst_ip,
                              machine_id, success_present: bool = False) -> list[str]:
    """Return 2-3 verdict-aware, offense-specific recommendation bullets."""
    desc_l = (offense.get("description") or "").lower()
    rule_l = " ".join(offense.get("rules") or []).lower()
    ttypes = {t.get("technique_id") for t in mitre}
    who = username or (offense.get("usernames") or ["the impacted account"])[0]
    host = machine_id or src_ip or "the affected host"
    ext_ip = _first(iocs.get("ipv4_external"))

    recs: list[str] = []
    # CTI / threat-intel IP-feed firewall-permit — dedicated recommendations (verdict-agnostic).
    if _is_cti_feed(desc_l, rule_l):
        pkv = _parse_payload_kv(offense.get("events") or [], offense)
        outbound = "outbound" in desc_l
        cti_ip = (dst_ip if outbound else src_ip) or ext_ip or "the flagged IP"
        policy = pkv.get("policy_name") or pkv.get("rule_name")
        recs.append(f"Kindly block the IP address {cti_ip}, if there is no legitimate business requirement.")
        recs.append(f"Verify whether communication {'to' if outbound else 'from'} {cti_ip} is expected and "
                    "associated with any approved business application, partner integration, or external service.")
        recs.append(f"Review the firewall rule {policy or 'associated with this connection'} and ensure access "
                    "is restricted to authorized source networks wherever possible.")
        return recs
    # Login-failure / brute-force / password-spray — dedicated recommendations (verdict-agnostic).
    if _is_login_failure(desc_l, rule_l) or "spray" in rule_l or "brute" in rule_l:
        recs.append(f"Verify the source IP {src_ip or 'of the attempts'} — confirm whether it is a known/managed host or an unexpected/external source.")
        recs.append(f"Confirm with the account owner/administrator whether the '{username or who}' logon activity is expected and legitimate.")
        recs.append(f"Check whether any successful logon followed the failures for '{username or who}'; if so, treat it as a potential compromise and escalate.")
        recs.append("Monitor the account for lockout; if the source is not recognised, reset/rotate the credentials and enforce MFA.")
        return recs[:4]
    if verdict == "TP":
        if "ransom" in desc_l or "T1486" in ttypes:
            recs.append(f"Isolate {host} from the network immediately (switch-level MAC block) and capture a memory image + disk image before shutdown.")
            recs.append("Trigger the ransomware IR playbook: identify last clean backup, notify the CISO and legal, and preserve encrypted samples for reversibility analysis.")
            recs.append("Rotate service-account credentials that had access to affected shares; scan the environment for the same file hash.")
        elif "phish" in desc_l:
            recs.append(f"Reset {who}'s password, revoke active SSO/OAuth sessions and enforce MFA re-registration.")
            recs.append(f"Block the phishing URL at the proxy and DNS sinkhole; hunt for other users who visited the same domain.")
            recs.append("Submit the URL to the corporate threat intel platform and email gateway signature update.")
        elif "ip feed" in rule_l or "rbi_ioc" in rule_l or "permit" in rule_l:
            recs.append(f"Block source IP {src_ip or ext_ip} at the perimeter firewall and update the RBI/IOC deny-list.")
            recs.append(f"Review other traffic from {src_ip or ext_ip} in the last 24 hours and hunt for successful connections to internal hosts.")
            recs.append("If the destination service is not intentionally exposed, restrict inbound rules and open a change to remove public exposure.")
        elif "exfil" in desc_l or "T1041" in ttypes:
            recs.append(f"Block outbound traffic to {ext_ip or dst_ip} and quarantine {host}.")
            recs.append("Preserve NetFlow/PCAP for the exfiltration window and identify the data classification of transferred files.")
            recs.append("Engage IR + Legal; consider DLP policy update to prevent recurrence.")
        else:
            recs.append(f"Contain {host} / {who} immediately and open a P1 incident ticket with IR.")
            recs.append("Collect evidence (payload, logs, memory) and pivot to identify blast radius across other assets.")
            recs.append("Notify SOC Manager on-call and the customer stakeholder within SLA.")
    elif verdict == "FP":
        if "expired" in desc_l:
            recs.append(f"Close the ticket as False Positive - password of user '{who}' has expired; user should reset it via the self-service portal.")
            recs.append("Update the detection tuning to auto-suppress this rule when Windows Error Code = 0xC0000224 for the same account within a short window.")
        else:
            recs.append("Close the ticket as False Positive after confirming activity is expected/authorized per KB reference.")
            recs.append(f"Add {who or src_ip} to the rule's whitelist / exception list if repeatedly benign, and document the exception in the KB.")
        recs.append("Consider tuning the detection rule threshold or adding contextual filters to reduce noise going forward.")
    else:  # Suspicious
        if "brute" in desc_l or ("multiple" in desc_l and "fail" in desc_l):
            recs.append(f"Contact {who} to confirm they were the source of the failed attempts; if not, force password reset and enable MFA.")
            recs.append(f"Enable enhanced monitoring on {who} and {src_ip} for 24 hours; alert on any new successful login.")
            recs.append("If failures continue past the monitoring window or a success login appears, escalate to L2 with the full evidence pack.")
        elif "vpn" in rule_l:
            recs.append(f"Verify with the impacted users whether the VPN attempts from {src_ip} are legitimate (travel / new device).")
            recs.append(f"If unauthorized, block {src_ip} at the VPN concentrator and force password reset for {', '.join((offense.get('usernames') or [])[:3])}.")
            recs.append("Monitor for further VPN sign-in attempts from the same source IP; escalate to L2 if a success is observed.")
        elif "sql" in rule_l or "dam" in rule_l:
            recs.append(f"Verify with the DBA/application team whether the SQL command executed by '{who}' from {src_ip} was part of an approved change window.")
            recs.append("If not approved, disable the DB user, capture the full SQL session and open a data-integrity ticket.")
            recs.append("If approved, document the change ticket ID in the KB and consider adding a temporary suppression rule for the change window.")
        elif "cloud" in rule_l or "upload" in rule_l:
            recs.append(f"Contact {who} to confirm whether the cloud upload was work-related; request the file name and business justification.")
            recs.append("Confirm the file's data classification with the data owner; if confidential, block and educate the user.")
            recs.append("Escalate to L2 if the file classification is Confidential/Restricted or the user cannot justify the upload.")
        elif ("virus" in desc_l or "malware" in rule_l or "behavior monitoring" in desc_l
              or "startup program" in desc_l or "persistence" in rule_l or "new startup" in desc_l):
            pkv = _parse_payload_kv(offense.get("events") or [], offense)
            fpath = pkv.get("file_path") or pkv.get("process")
            reg = pkv.get("registry")
            fname = (fpath.replace("/", "\\").split("\\")[-1] if fpath else None) or "the detected file"
            recs.append(f"Verify whether {fname} is associated with a legitimate software installation or update on {host}.")
            recs.append(f"Review the endpoint startup entries, registry autorun locations{f' (e.g. {reg})' if reg else ''} and scheduled tasks to determine whether persistence was successfully established.")
            recs.append(f"Perform a full antivirus and EDR scan on endpoint {host} to identify any additional suspicious activity.")
            recs.append(f"If {fname} is confirmed to be unauthorized or malicious, remove the persistence mechanism and delete the file from the endpoint.")
        else:
            recs.append(f"Verify with {who} and the asset owner of {host} that the activity is legitimate/expected.")
            recs.append(f"Add {src_ip or who} to enhanced monitoring for the next 24 hours; alert on repeated triggers.")
            recs.append("If activity is not confirmed benign within SLA, escalate to L2 for deeper analysis.")

    return recs[:4]


# ---------- Attack Path Replay (narrative story steps) ----------
def build_attack_path(offense: dict, mitre: list[dict], iocs: dict, ti: dict | None = None) -> list[dict]:
    """Build a sequential narrative of the attack for managers.
    Each step: order, phase, headline, actor, action, target, evidence, severity."""
    steps: list[dict] = []
    ext_ips = iocs.get("ipv4_external") or []
    int_ips = iocs.get("ipv4_internal") or []
    users = offense.get("usernames") or []
    hashes = iocs.get("sha256") or iocs.get("md5") or iocs.get("sha1") or []
    domains = iocs.get("domain") or []
    urls = iocs.get("url") or []
    ttypes = {t.get("technique_id"): t for t in mitre}
    ti_verdicts = (ti or {}).get("verdicts", {}) if ti else {}

    def add(phase, headline, actor, action, target, evidence, severity="info", tech=None):
        steps.append({
            "order": len(steps) + 1,
            "phase": phase,
            "headline": headline,
            "actor": actor,
            "action": action,
            "target": target,
            "evidence": evidence,
            "severity": severity,
            "technique": tech,
        })

    # 1. Origin
    if ext_ips:
        origin = ext_ips[0]
        actor_note = "external threat actor"
        if ti_verdicts.get("malicious", 0) > 0:
            actor_note += " (confirmed malicious by Threat Intel)"
        add("Reconnaissance", f"Traffic originates from {origin}",
            actor_note, "connects from external network", int_ips[0] if int_ips else "internal asset",
            f"External source IP: {origin}", "high" if ti_verdicts.get("malicious", 0) else "medium")

    # 2. Initial access / brute force
    if "T1110" in ttypes:
        add("Initial Access", "Brute-force login attempts",
            ext_ips[0] if ext_ips else "attacker", "repeatedly attempts credentials against",
            (int_ips[0] if int_ips else "server"), "Multiple failed authentications observed", "high", "T1110")
    if "T1078" in ttypes and any("T1110" == t.get("technique_id") for t in mitre):
        add("Initial Access", f"Successful login as {users[0] if users else 'user'}",
            ext_ips[0] if ext_ips else "attacker", "successfully authenticates as",
            users[0] if users else "target user", "Valid credentials used post-bruteforce", "critical", "T1078")
    elif "T1078.004" in ttypes:
        add("Initial Access", "Cloud account sign-in from unusual location",
            users[0] if users else "user", "signs in from anomalous geography",
            "cloud identity provider", "Impossible travel between sign-ins detected", "high", "T1078.004")

    # 3. Execution / evasion
    if "T1059.001" in ttypes:
        add("Execution", "Obfuscated PowerShell execution",
            users[0] if users else "endpoint user", "spawns PowerShell with encoded payload",
            int_ips[0] if int_ips else "endpoint",
            "Encoded PowerShell command discovered in payload", "critical", "T1059.001")
    if "T1027" in ttypes and "T1059.001" not in ttypes:
        add("Defense Evasion", "Obfuscated command payload",
            "attacker", "hides command intent via encoding",
            "endpoint", "Base64-encoded payload observed", "high", "T1027")

    # 4. C2 / lateral
    if "T1071.004" in ttypes:
        add("Command & Control", "DNS tunneling to external C2",
            int_ips[0] if int_ips else "endpoint", "beacons via DNS TXT queries to",
            domains[0] if domains else "external C2 domain",
            f"Rare/uncategorized domain: {domains[0] if domains else 'unknown'}", "high", "T1071.004")
    if "T1090" in ttypes:
        add("Command & Control", "Proxy / Tor exit node communication",
            int_ips[0] if int_ips else "endpoint", "communicates through proxy with",
            ext_ips[0] if ext_ips else "known anonymizer",
            "Anonymizer network traffic detected", "high", "T1090")

    # 5. Discovery / recon
    if "T1046" in ttypes:
        add("Discovery", "Network service scanning",
            ext_ips[0] if ext_ips else "attacker", "probes multiple ports on",
            "internal database segment", "Repeated firewall denies to DB ports", "medium", "T1046")

    # 6. Privilege escalation / persistence
    if "T1548" in ttypes or "T1543.003" in ttypes:
        add("Privilege Escalation", "Service or elevation abuse",
            users[0] if users else "user", "modifies system service binary path",
            "Windows service", "Service registry modification observed", "high",
            "T1548" if "T1548" in ttypes else "T1543.003")

    # 7. Collection / exfil
    if "T1041" in ttypes:
        add("Exfiltration", "Large outbound data transfer",
            int_ips[0] if int_ips else "endpoint", "sends significant data volume to",
            ext_ips[0] if ext_ips else "external destination",
            "Multi-GB outbound flow over short window", "critical", "T1041")

    # 8. Impact
    if "T1486" in ttypes:
        add("Impact", "Ransomware encryption behavior",
            "malware process", "encrypts files across",
            int_ips[0] if int_ips else "file server",
            f"Malicious hash: {hashes[0] if hashes else 'unknown'}", "critical", "T1486")

    # Fallback: at least one step
    if not steps:
        src = ext_ips[0] if ext_ips else (int_ips[0] if int_ips else "unknown source")
        tgt = int_ips[0] if int_ips else "monitored asset"
        add("Analysis", "Suspicious activity flagged",
            src, "triggered detection rule",
            tgt, offense.get("description", "See event details"), "medium")

    return steps


# ---------- Learned adjustments (Analyst Coach) ----------
def apply_learned_adjustment(risk: int, offense: dict, adjustments: dict) -> tuple[int, int]:
    """Apply per-rule risk adjustment learned from analyst feedback.
    Returns (adjusted_risk, delta)."""
    if not adjustments:
        return risk, 0
    delta = 0
    for rule in offense.get("rules") or []:
        adj = adjustments.get(rule)
        if adj:
            delta += int(adj.get("risk_delta") or 0)
    new_risk = max(0, min(100, risk + delta))
    return new_risk, delta


# ---------- Similarity between offenses ----------
def offense_similarity(a: dict, b: dict) -> float:
    """Lightweight similarity based on shared IPs, users, categories, rules."""
    score = 0.0
    weights = 0.0

    def _jaccard(x: list, y: list):
        sx, sy = set(x or []), set(y or [])
        if not sx and not sy:
            return 0
        return len(sx & sy) / max(1, len(sx | sy))

    score += _jaccard(a.get("source_ips"), b.get("source_ips")) * 3
    weights += 3
    score += _jaccard(a.get("usernames"), b.get("usernames")) * 3
    weights += 3
    score += _jaccard(a.get("rules"), b.get("rules")) * 2
    weights += 2
    score += _jaccard(a.get("categories"), b.get("categories")) * 2
    weights += 2
    return round((score / weights) * 100, 1)


# ---------- LLM (optional) ----------
_LLM_STATE = {"pipeline": None, "loading": False, "error": None}


def try_load_llm(model_name: str) -> str | None:
    """Attempt to load a HuggingFace text-generation pipeline synchronously.
    Returns error message on failure, None on success."""
    if _LLM_STATE["pipeline"] is not None:
        return None
    try:
        from transformers import pipeline  # type: ignore
        _LLM_STATE["loading"] = True
        pipe = pipeline("text-generation", model=model_name, device_map="cpu",
                        max_new_tokens=256, temperature=0.3, do_sample=False)
        _LLM_STATE["pipeline"] = pipe
        _LLM_STATE["loading"] = False
        _LLM_STATE["error"] = None
        return None
    except Exception as e:
        _LLM_STATE["loading"] = False
        _LLM_STATE["error"] = str(e)
        logger.exception("Failed to load local LLM: %s", e)
        return str(e)


def llm_narrative(offense: dict, iocs: dict, mitre: list[dict], risk: int, rec: str, model_name: str) -> str | None:
    pipe = _LLM_STATE.get("pipeline")
    if pipe is None:
        err = try_load_llm(model_name)
        if err:
            return None
        pipe = _LLM_STATE["pipeline"]
    try:
        prompt = (
            "You are a senior SOC analyst. Write a concise executive summary (5-7 sentences) of this security offense.\n\n"
            f"Offense: {offense.get('description')}\n"
            f"Rules: {', '.join(offense.get('rules', []))}\n"
            f"Sources: {', '.join(offense.get('source_ips', []))}\n"
            f"Users: {', '.join(offense.get('usernames', []))}\n"
            f"MITRE: {', '.join(t['technique_id'] + ' ' + t['technique_name'] for t in mitre[:5])}\n"
            f"External IPs: {', '.join(iocs.get('ipv4_external', [])[:5])}\n"
            f"Risk: {risk}/100. Recommendation: {rec}.\n\n"
            "Summary:"
        )
        out = pipe(prompt, return_full_text=False, max_new_tokens=220)
        text = out[0]["generated_text"].strip()
        return text
    except Exception as e:
        logger.warning("LLM inference failed: %s", e)
        return None
