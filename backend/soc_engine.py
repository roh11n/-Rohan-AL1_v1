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
    parts = [str(e.get("decoded_payload") or e.get("payload") or "") for e in events or []]
    for e in events or []:
        if e.get("event_description"):
            parts.append(str(e["event_description"]))
    if offense and offense.get("description"):
        parts.append(str(offense["description"]))
    text = "  ".join(p for p in parts if p)
    if not text:
        return {}

    kv: dict[str, str] = {}
    for m in _re.finditer(r"([A-Za-z_][A-Za-z0-9_.]*)=([^=]*?)(?=\s+[A-Za-z_][A-Za-z0-9_.]*=|$)", text):
        k = m.group(1).strip().lower()
        v = m.group(2).strip().strip('"').strip("'")
        if v and k not in kv:
            kv[k] = v
    for m in _re.finditer(r"([A-Za-z][A-Za-z _]{1,30}?)\s*:\s*([^\n\r]+?)(?:\s{2,}|$)", text):
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
    # Structured event fields take priority, then payload key=value, then description text.
    out = {
        "source_ip": ev_get("sourceip", "source_ip") or pick("src", "source_ip", "sourceip", "source_address", "shost", "client_ip") or find_ip("source"),
        "destination_ip": ev_get("destinationip", "destination_ip") or pick("dst", "destination_ip", "destinationip", "dest_ip", "dhost") or find_ip("destination"),
        "source_port": ev_get("sourceport") or pick("srcport", "source_port", "sport", "spt"),
        "destination_port": ev_get("destinationport") or pick("dstport", "destination_port", "dport", "dpt"),
        "protocol": proto,
        "action": action,
        "rule_name": pick("rule_name", "rulename"),
        "username": ev_get("username") or pick("usrname", "username", "user", "suser", "duser", "account_name", "src_user"),
        "application": ev_get("application", "app") or pick("app", "application", "appname", "requestclientapplication"),
        "bytes": pick("bytes", "byte", "in", "out", "bytesin", "bytesout"),
        "post_nat_source_ip": ev_get("postnatsourceip"),
        "post_nat_destination_ip": ev_get("postnatdestinationip"),
        "domain_url": ev_get("domain_url", "domainurl", "url") or pick("domain_url", "url", "domain", "dhost"),
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
def _generate_analysis_lines(offense, events, similar, kb_matches, iocs, mitre,
                             src_ip, dst_ip, username, event_name, failure_reason,
                             error_code, log_source_str, machine_id, dt_str):
    """Produce a numbered analysis matching the ITSM_Analysis style from analyst KB.

    Line 1: what happened (offense name, when, who, from where)
    Line 2: technical details (protocol/port/URL/SQL/error meaning)
    Line 3: correlation/observation (success logins, historical KB match, IOC data)
    Line 4: verdict + verify-the-legitimacy call to action
    """
    import html as _html
    desc = offense.get("description") or "Offense"
    rules = offense.get("rules") or []
    lines: list[dict] = []

    # Line 1 — canonical opener
    when = f" on {dt_str}" if dt_str else ""
    lines.append({"n": 1, "text": f'An offense "{desc}" was triggered{when}.'})

    # Line 2 — technical detail sentence, tailored by category / evidence
    l2 = None
    lower_desc = desc.lower()
    ll = " ".join((offense.get("categories") or []) + rules).lower()
    payloads = " ".join([str(e.get("payload") or "") for e in events])

    if "sql" in ll or "dam" in ll or "database" in ll:
        m = _extract_field(events, "process")
        sql = _scan_payload_regex(events, r"SQL\s*Command\s*[:=]\s*([^\n\r]+?)(?:\s{2,}|Log Source|$)", 1)
        l2 = (f"Database user '{username}' from host {src_ip} executed on target DB {dst_ip}"
              + (f" via {m}" if m else "")
              + (f" the SQL command: {sql!r}." if sql else "."))
    elif "phish" in lower_desc or "phish" in ll:
        url = _extract_field(events, "url") or _scan_payload_regex(events, r"URL[:=]\s*(https?://\S+)", 1)
        l2 = f"User '{username}' from host {src_ip} accessed the phishing URL {url}." if url else \
             f"User '{username}' from host {src_ip} was flagged accessing a phishing category site."
    elif "ip feed" in ll or "rbi_ioc" in ll or "permit" in ll:
        asn = _scan_payload_regex(events, r"ASN[:=]\s*([^\n\r]+?)(?:\s{2,}|City|$)", 1)
        port = _extract_field(events, "port") or _scan_payload_regex(events, r"Destination Port[:=]\s*(\d+)", 1)
        l2 = (f"An inbound permitted connection was observed from source IP {src_ip}"
              + (f" (ASN: {asn})" if asn else "")
              + f" to destination IP {dst_ip}"
              + (f" on port {port}" if port else "")
              + ".")
    elif "vpn" in ll:
        failed = [e for e in events if "fail" in (e.get("event_name") or "").lower()]
        succ = [e for e in events if "success" in (e.get("event_name") or "").lower()]
        u_fail = sorted({e.get("username") for e in failed if e.get("username")})
        u_succ = sorted({e.get("username") for e in succ if e.get("username")})
        l2 = (f"Source IP {src_ip} attempted VPN authentication for user(s) [{', '.join(u_fail)}]"
              + (f" and successfully signed in as [{', '.join(u_succ)}]" if u_succ else "")
              + f" against VPN gateway {dst_ip}.")
    elif "brute" in ll or ("multiple" in lower_desc and "fail" in lower_desc):
        l2 = f"Multiple failed authentication attempts were observed for user '{username}' from source IP {src_ip} against {dst_ip}."
    elif "expired" in lower_desc or (error_code and error_code.lower() == "0xc0000224"):
        l2 = f"The event indicates the user's password has expired (Error Code: {error_code}, Failure Reason: {failure_reason})." \
             if failure_reason else \
             f"The event indicates an expired-password login failure (Error Code: {error_code})."
    elif "ransom" in ll or "ransom" in lower_desc:
        h = _first(iocs.get("sha256") or iocs.get("md5") or iocs.get("sha1"))
        l2 = f"Ransomware activity was detected on host {machine_id or dst_ip}" + (f" with file hash {h}" if h else "") + "."
    elif "dns" in ll or "tunnel" in ll:
        dom = _first(iocs.get("domain"))
        l2 = f"Unusual DNS queries were observed from {src_ip}" + (f" to domain {dom}" if dom else "") + "."
    elif "cloud" in ll or "upload" in ll:
        url = _extract_field(events, "url")
        l2 = f"User '{username}' from host {src_ip} uploaded content to {url or dst_ip}."
    elif "usb" in ll or "removable" in ll:
        l2 = f"User '{username}' wrote files to a removable device on host {machine_id or src_ip}."
    elif event_name:
        l2 = (f"The event '{event_name}' was observed for user '{username}' from {src_ip} to {dst_ip}"
              + (f" via {log_source_str}" if log_source_str else "") + ".")
    else:
        l2 = f"Rule(s) triggered: {', '.join(rules) or 'unspecified'}."
    lines.append({"n": 2, "text": l2})

    # Line 3 — correlation / KB / historical
    success_present = any("success" in (e.get("event_name") or "").lower()
                          or "success" in (e.get("low_level_category") or "").lower() for e in events)
    kb_hint = None
    if kb_matches:
        # Try to surface an analyst-note fragment from the closest KB match
        best = max(kb_matches, key=lambda m: float(m.get("similarity") or 0))
        text = _html.unescape((best.get("text") or "").strip())
        m_ = None
        import re as _re
        for pat in (r"\bAnalysis\s*[-:]+[\s\S]{20,400}", r"\b1\)\s*[\s\S]{20,400}", r"\bClosed[\s\S]{5,200}"):
            m_ = _re.search(pat, text)
            if m_:
                break
        if m_:
            snippet = m_.group(0)[:280].strip()
            snippet = _re.sub(r"\s+", " ", snippet)
            kb_hint = f"Historical KB reference (similarity {int(float(best.get('similarity') or 0) * 100)}%): {snippet}."
    if success_present:
        lines.append({"n": 3, "text": "On checking the logs for the user we have observed success logins after the failed ones. Kindly check the legitimacy of the user."})
    elif kb_hint:
        lines.append({"n": 3, "text": kb_hint})
    elif similar:
        top = similar[0]
        lines.append({"n": 3, "text": f"Historical similar incident found (similarity {top.get('similarity')}%); previous outcome: '{top.get('recommendation') or 'monitor'}'."})
    else:
        lines.append({"n": 3, "text": "No corroborating success events or matching historical incidents were found within the offense window."})

    # Line 4 — closing call to action
    lines.append({"n": 4, "text": "Verify the legitimacy of the alert with the affected user/host owner before closing."})
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
        else:
            recs.append(f"Verify with {who} and the asset owner of {host} that the activity is legitimate/expected.")
            recs.append(f"Add {src_ip or who} to enhanced monitoring for the next 24 hours; alert on repeated triggers.")
            recs.append("If activity is not confirmed benign within SLA, escalate to L2 for deeper analysis.")

    return recs[:3]


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
