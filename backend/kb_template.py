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


def _fmt_dt(offense: dict):
    ts = offense.get("start_time")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).strftime("%d %b %Y, %H:%M:%S")
    except Exception:
        return str(ts)


def _artifacts(offense: dict) -> dict:
    def first(key):
        v = offense.get(key) or []
        return v[0] if v else None
    return {
        "source_ip": first("source_ips"),
        "destination_ip": first("destination_ips"),
        "username": first("usernames"),
        "offense_id": offense.get("qradar_offense_id") or offense.get("id"),
        "date_time": _fmt_dt(offense),
    }


def _substitute(text: str, art: dict) -> str:
    out = text or ""
    mapping = {
        "{source_ip}": art.get("source_ip") or "N/A",
        "{destination_ip}": art.get("destination_ip") or "N/A",
        "{username}": art.get("username") or "N/A",
        "{offense_id}": str(art.get("offense_id") or "N/A"),
        "{date_time}": art.get("date_time") or "N/A",
    }
    for k, v in mapping.items():
        out = out.replace(k, str(v))
    return out


def template_text(kb_entry: dict) -> str:
    """Flatten a KB entry into text for vector indexing / LLM context."""
    parts = [f"Alert: {kb_entry.get('alert_name', '')}"]
    if kb_entry.get("analysis"):
        parts.append(f"Analysis: {kb_entry['analysis']}")
    if kb_entry.get("verdict"):
        parts.append(f"Verdict: {kb_entry['verdict']}")
    if kb_entry.get("recommendations"):
        parts.append("Recommendations: " + "; ".join(kb_entry["recommendations"]))
    return "\n".join(parts)


def build_kb_template_report(offense: dict, events: list[dict], kb_entry: dict,
                             base_report: dict, score: int) -> dict:
    """Adapt a KB entry's documented analysis to the current offense's artifacts.
    Starts from the rule-engine report (base_report) to keep extracted fields,
    then overrides analysis_lines / verdict / recommendations from the template."""
    art = _artifacts(offense)
    base = dict(base_report or {})

    lines = []
    n = 1
    lines.append({"n": n, "text": (
        f"This alert matches the knowledge-base template '{kb_entry.get('alert_name')}' "
        f"(name match {score}%). Reusing the documented analysis and adapting it to this "
        f"offense's artifacts.")})
    n += 1

    analysis_txt = _substitute(kb_entry.get("analysis") or "", art)
    for seg in re.split(r"(?:\r?\n)+|(?<=[.;])\s+(?=[A-Z0-9])", analysis_txt):
        seg = seg.strip()
        if seg:
            lines.append({"n": n, "text": seg})
            n += 1

    obs = []
    if art.get("source_ip"):
        obs.append(f"Source IP: {art['source_ip']}")
    if art.get("destination_ip"):
        obs.append(f"Destination IP: {art['destination_ip']}")
    if art.get("username"):
        obs.append(f"Username: {art['username']}")
    if art.get("date_time"):
        obs.append(f"Time: {art['date_time']}")
    obs.append(f"Offense ID: {art.get('offense_id')}")
    lines.append({"n": n, "text": "Observed artifacts in this offense — " + "; ".join(obs) + "."})

    base["analysis_lines"] = lines
    if kb_entry.get("verdict"):
        base["verdict"] = kb_entry["verdict"]
    base["verdict_reason"] = _substitute(
        base.get("verdict_reason") or f"Consistent with knowledge-base entry '{kb_entry.get('alert_name')}'.",
        art,
    )
    if kb_entry.get("recommendations"):
        base["recommendations"] = [_substitute(r, art) for r in kb_entry["recommendations"]]
    if base.get("recommendations"):
        base["recommendation_text"] = base["recommendations"][0]
    base["generated_by"] = f"kb-template:{kb_entry.get('alert_name')}"
    base["kb_template_alert"] = kb_entry.get("alert_name")
    base["kb_template_score"] = score
    return base
