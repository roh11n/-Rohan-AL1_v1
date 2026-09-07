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


def match_score(offense: dict, kb_entry: dict) -> int:
    """0-100 how well the offense's alert name matches this KB entry's alert_name."""
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
        inter = len(at & ct)
        contain = int(100 * inter / len(at)) if at else 0
        best = max(best, contain)
    return best


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
    }
    if vt:
        fm.update({
            "ispasn": vt.get("as_owner"), "isp": vt.get("as_owner"), "asn": vt.get("as_owner"),
            "country": vt.get("country"),
            "vtabusescore": vt.get("score"), "vtscore": vt.get("score"), "vt": vt.get("score"),
            "reputationscore": vt.get("score"), "url": vt.get("url"), "virustotal": vt.get("url"),
        })
    return {k: v for k, v in fm.items() if v}


def build_kb_template_report(offense: dict, events: list[dict], kb_entry: dict,
                             base_report: dict, score: int, vt: dict | None = None) -> dict:
    """Populate the KB entry's sections (Analysis / IOC Enrichment / Impact /
    Recommendations) with this offense's fields (from offense + payload) and,
    when enabled, live VirusTotal enrichment. Fully dynamic — no per-use-case code."""
    base = dict(base_report or {})
    fm = _build_fieldmap(base_report, offense, vt)

    lines = []
    n = [1]

    def add(text):
        lines.append({"n": n[0], "text": text})
        n[0] += 1

    def section(title, body):
        if not body:
            return
        add(f"[{title}]")
        for seg in re.split(r"(?:\r?\n)+", _fill(body, fm)):
            seg = seg.strip()
            if seg:
                add(seg)

    add(f"Matched knowledge-base template '{kb_entry.get('alert_name')}' ({score}% name match). "
        f"Sections are populated from this offense's fields.")
    section("Analysis", kb_entry.get("analysis"))
    if vt and vt.get("text"):
        section("IOC Enrichment", vt["text"])
    elif kb_entry.get("ioc_enrichment"):
        add("[IOC Enrichment]")
        add("VirusTotal enrichment unavailable (no public IP matched or VT key not configured).")
    section("Impact", kb_entry.get("impact"))

    recs = [_fill(r, fm) for r in (kb_entry.get("recommendations") or [])]
    if recs:
        add("[Recommendations]")
        for r in recs:
            add(r)

    base["analysis_lines"] = lines
    if kb_entry.get("verdict"):
        base["verdict"] = kb_entry["verdict"]
    base["verdict_reason"] = base.get("verdict_reason") or f"Consistent with knowledge-base entry '{kb_entry.get('alert_name')}'."
    if recs:
        base["recommendations"] = recs
        base["recommendation_text"] = recs[0]
    if vt:
        base["ioc_enrichment"] = vt
    base["generated_by"] = f"kb-template:{kb_entry.get('alert_name')}"
    base["kb_template_alert"] = kb_entry.get("alert_name")
    base["kb_template_score"] = score
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
