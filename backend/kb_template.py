"""Deterministic KB-template analysis engine.

KB mode: when a new offense's alert/rule name matches a manually-added
knowledge-base entry, reuse that entry's documented analysis / verdict /
recommendations as a template and swap in the CURRENT offense's artifacts
(source IP, destination IP, username, offense id, time). No model required.
"""
from __future__ import annotations

import re
from datetime import datetime


def _norm(s) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(s or "").lower()).strip()


def _tokens(s) -> set:
    return set(_norm(s).split())


def _candidates(offense: dict) -> list[str]:
    out: list[str] = []
    if offense.get("description"):
        out.append(offense["description"])
    for r in offense.get("rules") or []:
        if r:
            out.append(r)
    return out


# Word pairs that flip the meaning of a use case — a mismatch means a different use case.
_CONFLICTS = [
    {"inbound", "outbound"}, {"success", "successful", "failure", "failed", "failures"},
    {"allowed", "allow", "permit", "permitted", "denied", "deny", "blocked", "block"},
    {"internal", "external"}, {"upload", "download"}, {"login", "logout"},
    {"created", "deleted"}, {"enabled", "disabled"}, {"removed", "detected"},
]
_UC_NUM = re.compile(r"\b\d{3,6}\b")


def _conflicting(a: set, b: set) -> bool:
    for grp in _CONFLICTS:
        ia, ib = a & grp, b & grp
        if ia and ib and not (ia & ib):
            return True
    return False


def match_score(offense: dict, kb_entry: dict) -> int:
    """0-100 fuzzy score of the offense's alert name vs this KB entry's alert_name.
    Directional/outcome conflicts (Inbound vs Outbound, Allowed vs Denied) and differing
    use-case numbers (UC-00316 vs UC-00317) are treated as a different use case."""
    alert = kb_entry.get("alert_name") or ""
    at = _tokens(alert)
    if not at:
        return 0
    na = _norm(alert)
    best = 0
    for cand in _candidates(offense):
        nc = _norm(cand)
        if not nc:
            continue
        if na == nc or na in nc or nc in na:
            return 100
        ct = _tokens(cand)
        if _conflicting(at, ct):
            continue
        an, cn = set(_UC_NUM.findall(na)), set(_UC_NUM.findall(nc))
        if an and cn and not (an & cn):
            continue
        inter = len(at & ct)
        contain = int(100 * inter / len(at)) if at else 0
        best = max(best, contain)
    return best


def same_use_case(a: dict, b: dict) -> bool:
    """Two KB rows describe the same use case when their alert names are equivalent."""
    return _norm(a.get("alert_name")) == _norm(b.get("alert_name"))


def split_sentences(text) -> list[str]:
    if not text:
        return []
    if isinstance(text, list):
        out: list[str] = []
        for t in text:
            out.extend(split_sentences(t))
        return out
    parts = re.split(r"(?:\r?\n|•|(?<=[.;!?])\s+)", str(text))
    return [p.strip(" -*•\t") for p in parts if p and p.strip(" -*•\t")]


def _dedupe_sentences(sents: list[str], limit: int = 8, min_support: int = 1) -> list[str]:
    """Order-preserving de-duplication; near-duplicates (token Jaccard >= 0.8) collapse and
    count as support. Sentences are ranked by support (consensus across tickets) first."""
    kept: list[dict] = []
    for idx, s in enumerate(sents):
        toks = _tokens(s)
        if not toks:
            continue
        for k in kept:
            if len(toks & k["t"]) / max(1, len(toks | k["t"])) >= 0.8:
                k["n"] += 1
                break
        else:
            kept.append({"t": toks, "s": s, "n": 1, "i": idx})
    strong = [k for k in kept if k["n"] >= min_support]
    if len(strong) < 2:
        strong = kept
    strong.sort(key=lambda k: (-k["n"], k["i"]))
    return [k["s"] for k in strong][:limit]


_GROUNDERS = [
    (r"\b(?:the )?(?:external|destination|remote|malicious|flagged|listed|suspicious) IP(?: address)?\b", "destinationip"),
    (r"\b(?:the )?(?:source|internal|affected|compromised|impacted|infected|offending) (?:host|endpoint|machine|system|workstation|server)\b", "sourcehost"),
    (r"\b(?:the )?(?:source|internal) IP(?: address)?\b", "sourceip"),
    (r"\b(?:the )?(?:user|user account|account|affected user|end user)\b", "username"),
    (r"\b(?:the )?parent process\b", "parentprocess"),
    (r"\b(?:the )?(?:offending |suspicious |malicious )?(?:PowerShell )?process\b", "process"),
    (r"\b(?:the )?(?:file )?hash\b", "filehash"),
    (r"\b(?:the )?(?:destination |target )?port\b", "destinationport"),
    (r"\b(?:the )?(?:domain|URL|domain/URL)\b", "domainurl"),
]


def ground_sentence(text: str, fm: dict) -> str:
    """Inject THIS offense's concrete artifacts into a generic KB/LLM sentence, e.g.
    'Block the external IP at the firewall' -> 'Block the external IP 45.1.2.3 at the firewall'.
    Each artifact is inserted at most once and only if not already present."""
    if not text:
        return text
    out = text
    used = set()
    for pat, key in _GROUNDERS:
        val = fm.get(key)
        if not val or key in used:
            continue
        sval = str(val).split("@")[0].strip()
        if sval.lower() in out.lower():
            used.add(key)
            continue
        m = re.search(pat, out, flags=re.IGNORECASE)
        if not m:
            continue
        out = out[:m.end()] + f" {sval}" + out[m.end():]
        used.add(key)
    return out


def fix_direction(text: str, alert_name: str) -> str:
    """Correct an inbound/outbound slip against the offense's own alert name."""
    nt = _tokens(alert_name)
    for a, b in (("inbound", "outbound"), ("outbound", "inbound")):
        if a in nt and b not in nt:
            return re.sub(rf"\b{b}\b", a, text, flags=re.IGNORECASE)
    return text


def consolidate_entries(entries: list[dict]) -> dict:
    """Merge every KB row (ITSM ticket) of the same use case into one learned write-up:
    unique analysis / impact / recommendation sentences plus the verdict distribution."""
    entries = [e for e in (entries or []) if e]
    if not entries:
        return {}
    head = entries[0]
    ms = 2 if len(entries) >= 3 else 1
    analysis = _dedupe_sentences([s for e in entries for s in split_sentences(e.get("analysis"))], 6, ms)
    impact = _dedupe_sentences([s for e in entries for s in split_sentences(e.get("impact"))], 4, ms)
    recs = _dedupe_sentences([s for e in entries for s in split_sentences(e.get("recommendations"))], 6, ms)
    counts: dict[str, int] = {}
    for e in entries:
        if e.get("verdict"):
            counts[e["verdict"]] = counts.get(e["verdict"], 0) + 1
    verdict = max(counts, key=counts.get) if counts else None
    return {
        "alert_name": head.get("alert_name"),
        "analysis": " ".join(analysis),
        "impact": " ".join(impact),
        "recommendations": recs,
        "analysis_points": analysis,
        "impact_points": impact,
        "recommendation_points": recs,
        "verdict": verdict,
        "verdict_counts": counts,
        "ticket_count": len(entries),
        "ioc_enrichment": any(e.get("ioc_enrichment") for e in entries),
    }


def kb_learning_meta(kb_entry: dict, score: int) -> dict:
    return {
        "alert_name": kb_entry.get("alert_name"),
        "ticket_count": int(kb_entry.get("ticket_count") or 1),
        "match_score": score,
        "verdict_counts": kb_entry.get("verdict_counts") or {},
    }


def find_best_template(offense: dict, entries: list[dict], threshold: int = 60):
    """Return (best_entry, score) for the highest-scoring KB entry above threshold."""
    best = None
    best_score = 0
    for e in entries or []:
        s = match_score(offense, e)
        if s > best_score:
            best_score = s
            best = e
    if best and best_score >= threshold:
        return best, best_score
    return None, 0


def _fill(text: str, fm: dict) -> str:
    """Substitute [Placeholder], {placeholder} and "Placeholder" tokens with field
    values. Placeholder names are matched case/space/punctuation-insensitively."""
    if not text:
        return text

    def rep(m):
        inner = m.group(1)
        key = re.sub(r"[^a-z0-9]", "", inner.lower())
        return str(fm[key]) if fm.get(key) else m.group(0)

    text = re.sub(r"\[([^\[\]\n]{1,40})\]", rep, text)
    text = re.sub(r"\{([^{}\n]{1,40})\}", rep, text)
    text = re.sub(r'"([^"\n]{1,40})"', rep, text)
    return text


def _build_fieldmap(base: dict, offense: dict, vt: dict | None = None) -> dict:
    b = base or {}
    fm = {
        "sourceip": b.get("source_ip"), "srcip": b.get("source_ip"),
        "sourcehost": b.get("source_ip"), "sourcehostnameip": b.get("source_ip"),
        "destinationip": b.get("destination_ip"), "destip": b.get("destination_ip"),
        "destinationhost": b.get("destination_ip"), "destinationhostnameip": b.get("destination_ip"),
        "protocol": b.get("x_protocol"),
        "destinationport": b.get("x_destination_port"), "destport": b.get("x_destination_port"),
        "sourceport": b.get("x_source_port"), "srcport": b.get("x_source_port"),
        "port": b.get("x_destination_port") or b.get("x_source_port"),
        "rulename": b.get("x_rule_name"),
        "application": b.get("x_application"), "app": b.get("x_application"),
        "bytes": b.get("x_bytes"),
        "starttime": b.get("date_time"), "time": b.get("date_time"), "datetime": b.get("date_time"),
        "devicename": b.get("log_source"), "logsource": b.get("log_source"), "device": b.get("log_source"),
        "useraccount": b.get("username"), "username": b.get("username"), "user": b.get("username"),
        "assetname": b.get("x_asset_name"), "filepath": b.get("x_file_path"),
        "postnatsourceip": b.get("x_post_nat_source_ip"), "postnatsource": b.get("x_post_nat_source_ip"),
        "postnatdestinationip": b.get("x_post_nat_destination_ip"),
        "domainurl": b.get("x_domain_url"), "domain": b.get("x_domain_url"), "url_domain": b.get("x_domain_url"),
        "contenttype": b.get("x_content_type"),
        "lowlevelcategory": b.get("low_level_category"), "category": b.get("low_level_category"),
        "eventname": b.get("event_name"), "action": b.get("x_action"),
        "process": b.get("x_process"), "parentprocess": b.get("x_parent_process"),
        "commandline": b.get("x_command_line"),
        "filehash": b.get("x_file_hash") or b.get("x_sha256") or b.get("x_md5"),
        "filename": b.get("x_file_name"), "host": b.get("machine_identifier") or b.get("x_host"),
    }
    fm["sourcehost"] = b.get("machine_identifier") or b.get("x_host") or b.get("source_ip")
    if not fm.get("domainurl"):
        fm["domainurl"] = b.get("x_url")
    if vt:
        fm.update({
            "ispasn": vt.get("as_owner"), "isp": vt.get("as_owner"), "asn": vt.get("as_owner"),
            "country": vt.get("country"),
            "vtabusescore": vt.get("score"), "vtscore": vt.get("score"), "vt": vt.get("score"),
            "reputationscore": vt.get("score"), "url": vt.get("url"), "virustotal": vt.get("url"),
        })
    return {k: v for k, v in fm.items() if v}


def _to_bullets(text, fm: dict, alert_name: str = "") -> list[str]:
    """Fill placeholders, ground with this offense's artifacts, then split into bullets."""
    if not text:
        return []
    filled = _fill(text, fm)
    parts = re.split(r"(?:\r?\n|•|(?<=[.;])\s+)", filled)
    rows = [p.strip(" -*•\t") for p in parts if p and p.strip(" -*•\t")][:8]
    return [fix_direction(ground_sentence(r, fm), alert_name) for r in rows]


def build_fieldmap(base: dict, offense: dict, vt: dict | None = None) -> dict:
    return _build_fieldmap(base, offense, vt)


def build_kb_template_report(offense: dict, events: list[dict], kb_entry: dict,
                             base_report: dict, score: int, vt: dict | None = None) -> dict:
    """Populate the KB entry's sections (Analysis / Impact / Recommendations /
    IOC Enrichment) with this offense's fields (from offense + payload) and, when
    enabled, live VirusTotal enrichment. Fully dynamic — no per-use-case code.
    Sections are returned as separate structured fields the UI renders explicitly."""
    base = dict(base_report or {})
    fm = _build_fieldmap(base_report, offense, vt)
    an = str(offense.get("description") or "")

    analysis = _to_bullets(kb_entry.get("analysis"), fm, an)
    base["analysis_lines"] = [{"n": i, "text": t} for i, t in enumerate(analysis, 1)]
    base["impact_lines"] = _to_bullets(kb_entry.get("impact"), fm, an)

    recs = [_fill(r, fm) for r in (kb_entry.get("recommendations") or []) if r]
    if len(recs) == 1:  # single paragraph -> split into bullets
        recs = _to_bullets(recs[0], fm, an) or recs
    else:
        recs = [fix_direction(ground_sentence(r, fm), an) for r in recs]
    if recs:
        base["recommendations"] = recs
        base["recommendation_text"] = recs[0]

    if kb_entry.get("verdict"):
        base["verdict"] = kb_entry["verdict"]
        n = int(kb_entry.get("ticket_count") or 1)
        base["verdict_reason"] = (f"Consistent with {n} prior analyst-closed ticket{'s' if n != 1 else ''} "
                                  f"for this use case (closed as {kb_entry['verdict']}).")
    base["verdict_reason"] = (base.get("verdict_reason")
                              or f"Consistent with knowledge-base use case '{kb_entry.get('alert_name')}'.")
    if vt:
        base["ioc_enrichment"] = vt
    base["generated_by"] = f"kb-template:{kb_entry.get('alert_name')}"
    base["kb_template_alert"] = kb_entry.get("alert_name")
    base["kb_template_score"] = score
    base["kb_learning"] = kb_learning_meta(kb_entry, score)
    return base


def template_text(kb_entry: dict) -> str:
    """Flatten a KB entry into text for vector indexing / LLM context."""
    parts = [f"Alert: {kb_entry.get('alert_name', '')}"]
    if kb_entry.get("analysis"):
        parts.append(f"Analysis: {kb_entry['analysis']}")
    if kb_entry.get("impact"):
        parts.append(f"Impact: {kb_entry['impact']}")
    if kb_entry.get("verdict"):
        parts.append(f"Verdict: {kb_entry['verdict']}")
    if kb_entry.get("recommendations"):
        parts.append("Recommendations: " + "; ".join(kb_entry["recommendations"]))
    return "\n".join(parts)
