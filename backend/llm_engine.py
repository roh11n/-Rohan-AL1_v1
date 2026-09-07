"""Local-LLM driven MSSP L1 report generation.

Three-step pipeline per user spec:
  1. `select_fields`   — LLM extracts the L1-report fields from offense + events.
  2. `analyze_with_kb` — LLM chooses same-use-case KB match (analyst_feedback weighted
                        2x) and either adapts its analysis or generates fresh.
  3. `cross_verify`    — LLM re-reads offense + events + draft report and validates
                        every field, correcting contradictions.

The whole chain is best-effort. Any failure (import, load, inference, JSON parse,
timeout, missing keys) returns None → caller falls back to the rule-engine report.

Runs entirely on CPU (12 GB RAM class hardware) using HuggingFace transformers.
Model is lazy-loaded on first call and cached in process memory.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any

logger = logging.getLogger("socpilot.llm_engine")

_STATE: dict[str, Any] = {
    "model": None,
    "tokenizer": None,
    "model_name": None,
    "load_error": None,
    "load_lock": threading.Lock(),
}

# One worker so we never run two inferences in parallel (would OOM on CPU/12 GB).
_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="llm-infer")


# --------------------------------------------------------------------------- #
# Model load                                                                  #
# --------------------------------------------------------------------------- #
def _load(model_name: str) -> tuple[Any, Any] | None:
    """Lazy-load the tokenizer + causal-LM. Returns (tok, model) or None."""
    if _STATE["model"] is not None and _STATE["model_name"] == model_name:
        return _STATE["tokenizer"], _STATE["model"]
    with _STATE["load_lock"]:
        if _STATE["model"] is not None and _STATE["model_name"] == model_name:
            return _STATE["tokenizer"], _STATE["model"]
        try:
            import torch  # type: ignore
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore

            logger.info("Loading local LLM %s (CPU, fp16 where supported)...", model_name)
            tok = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float32,   # fp32 is safest on CPU; ~6 GB for a 3B model
                device_map="cpu",
                low_cpu_mem_usage=True,
            )
            model.eval()
            _STATE.update({
                "model": model, "tokenizer": tok,
                "model_name": model_name, "load_error": None,
            })
            logger.info("Local LLM %s ready.", model_name)
            return tok, model
        except Exception as e:  # noqa: BLE001
            _STATE["load_error"] = str(e)
            logger.warning("Local LLM load failed for %s: %s", model_name, e)
            return None


# --------------------------------------------------------------------------- #
# Inference primitive                                                         #
# --------------------------------------------------------------------------- #
def _chat_once(model_name: str, messages: list[dict], max_new_tokens: int,
               temperature: float) -> str | None:
    """Single chat-format inference. Returns generated text (assistant reply)."""
    loaded = _load(model_name)
    if not loaded:
        return None
    tok, model = loaded
    try:
        import torch  # type: ignore
        prompt = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tok(prompt, return_tensors="pt", truncation=True, max_length=6000)
        with torch.no_grad():
            out = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=temperature > 0.001,
                temperature=max(0.001, temperature),
                pad_token_id=tok.eos_token_id,
            )
        gen = out[0][inputs["input_ids"].shape[1]:]
        return tok.decode(gen, skip_special_tokens=True).strip()
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM inference error: %s", e)
        return None


def _chat_with_timeout(model_name: str, messages: list[dict],
                        max_new_tokens: int, temperature: float,
                        timeout_seconds: int) -> str | None:
    """Run one chat inference in the single-worker thread pool with a hard cap."""
    future = _EXECUTOR.submit(_chat_once, model_name, messages,
                              max_new_tokens, temperature)
    try:
        return future.result(timeout=timeout_seconds)
    except FuturesTimeout:
        logger.warning("LLM step exceeded %ss timeout — aborting.", timeout_seconds)
        # We can't cancel a running torch generate, but we won't wait on it.
        return None
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM step failure: %s", e)
        return None


# --------------------------------------------------------------------------- #
# JSON extraction                                                             #
# --------------------------------------------------------------------------- #
_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(text: str | None) -> dict | None:
    if not text:
        return None
    txt = text.strip()
    # Strip common code fences
    if txt.startswith("```"):
        txt = re.sub(r"^```(?:json)?", "", txt).strip()
        if txt.endswith("```"):
            txt = txt[:-3].strip()
    # Try direct parse first
    try:
        return json.loads(txt)
    except Exception:
        pass
    # Fall back to greedy brace match
    m = _JSON_BLOCK.search(txt)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        # Second-chance: strip trailing commas before }
        try:
            cleaned = re.sub(r",\s*([}\]])", r"\1", m.group(0))
            return json.loads(cleaned)
        except Exception:
            return None


# --------------------------------------------------------------------------- #
# Prompt builders                                                             #
# --------------------------------------------------------------------------- #
_FIELD_KEYS = [
    "offense_id", "offense_name", "severity", "date_time",
    "source_ip", "destination_ip", "username", "event_name",
    "low_level_category", "error_code", "event_id", "failure_reason",
    "machine_identifier", "log_source",
]


def _fmt_events(events: list[dict], limit: int = 5) -> str:
    if not events:
        return "(no events)"
    lines: list[str] = []
    for i, e in enumerate((events or [])[:limit], 1):
        # Compact view: only useful keys, capped payload
        keys = ["event_name", "start_time", "source_ip", "destination_ip",
                "username", "low_level_category", "log_source",
                "event_id", "error_code", "failure_reason",
                "machine_identifier", "payload"]
        parts = []
        for k in keys:
            v = e.get(k) if isinstance(e, dict) else None
            if v not in (None, "", []):
                sval = str(v)
                if len(sval) > 240:
                    sval = sval[:240] + "…"
                parts.append(f"{k}={sval}")
        lines.append(f"  event[{i}]: " + "; ".join(parts))
    return "\n".join(lines)


def _fmt_offense(offense: dict) -> str:
    return (
        f"description: {offense.get('description','')}\n"
        f"rules: {', '.join(offense.get('rules') or [])}\n"
        f"categories: {', '.join(offense.get('categories') or [])}\n"
        f"severity: {offense.get('severity_label')} (score {offense.get('severity')})\n"
        f"source_ips: {', '.join(str(x) for x in (offense.get('source_ips') or [])[:10])}\n"
        f"destination_ips: {', '.join(str(x) for x in (offense.get('destination_ips') or [])[:10])}\n"
        f"usernames: {', '.join(str(x) for x in (offense.get('usernames') or [])[:10])}\n"
        f"start_time: {offense.get('start_time')}\n"
        f"qradar_offense_id: {offense.get('qradar_offense_id')}\n"
    )


def _weighted_kb_context(kb_matches: list[dict], max_docs: int = 4) -> str:
    """Rank KB matches: analyst_feedback entries get their similarity boosted 2x."""
    if not kb_matches:
        return "(no KB matches)"
    ranked = []
    for m in kb_matches:
        s = float(m.get("similarity") or 0)
        if m.get("kb_type") == "analyst_feedback":
            s *= 2.0
        ranked.append((s, m))
    ranked.sort(key=lambda x: x[0], reverse=True)
    picked = [m for _, m in ranked[:max_docs]]
    out = []
    for i, m in enumerate(picked, 1):
        tag = "ANALYST-FEEDBACK" if m.get("kb_type") == "analyst_feedback" else (m.get("kb_type") or "kb")
        out.append(f"[{i}] ({tag}, sim={m.get('similarity')}) source={m.get('source')}\n"
                   f"    {(m.get('text') or '')[:800]}")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Step 1 — Field selection                                                    #
# --------------------------------------------------------------------------- #
def _step1_select_fields(model_name: str, offense: dict, events: list[dict],
                          temperature: float, timeout: int) -> dict | None:
    sys_msg = (
        "You are a SOC L1 analyst. Extract the raw fields for an MSSP L1 report "
        "from a QRadar offense and its events. Return ONLY a compact JSON object "
        "with exactly these keys (use \"N/A\" if not present): "
        + ", ".join(_FIELD_KEYS)
    )
    user_msg = (
        "Offense:\n" + _fmt_offense(offense) + "\n"
        "Top events:\n" + _fmt_events(events) + "\n\n"
        "Return ONLY the JSON object. No prose, no code fences."
    )
    for attempt in range(2):
        reply = _chat_with_timeout(
            model_name,
            [{"role": "system", "content": sys_msg},
             {"role": "user", "content": user_msg
                               + ("\n\n(Reminder: strict JSON only.)" if attempt else "")}],
            max_new_tokens=400, temperature=temperature, timeout_seconds=timeout,
        )
        parsed = _extract_json(reply)
        if isinstance(parsed, dict):
            return {k: (parsed.get(k) if parsed.get(k) not in (None, "") else "N/A")
                    for k in _FIELD_KEYS}
    return None


# --------------------------------------------------------------------------- #
# Step 2 — KB-guided analysis (reuse if same use-case, else fresh)            #
# --------------------------------------------------------------------------- #
def _step2_analyze(model_name: str, offense: dict, events: list[dict],
                   fields: dict, kb_matches: list[dict],
                   temperature: float, timeout: int) -> dict | None:
    sys_msg = (
        "You are a senior SOC L1/L2 analyst producing an MSSP report. "
        "You will be given a new offense with its raw fields, events, and up to 4 "
        "knowledge-base matches from prior incidents in the same tenant "
        "(analyst-feedback entries reflect ground-truth analyst corrections and "
        "should be trusted more heavily). "
        "Decide: is this the SAME use case as any KB match? "
        "If YES — adapt that KB entry's analysis/verdict/recommendations to the "
        "specifics of the new offense. "
        "If NO — generate the analysis from scratch based on standard MSSP L1 SOP.\n\n"
        "Return ONLY a JSON object with these keys:\n"
        "  used_kb: boolean\n"
        "  matched_kb_index: integer (1-based) or null\n"
        "  analysis_lines: array of {\"n\": int, \"text\": string}  (3-6 items)\n"
        "  verdict: \"TP\" | \"FP\" | \"Suspicious\"\n"
        "  verdict_reason: string\n"
        "  recommendations: array of strings (3-5 items)\n"
    )
    user_msg = (
        "Extracted fields:\n" + json.dumps(fields, indent=2) + "\n\n"
        "Offense:\n" + _fmt_offense(offense) + "\n"
        "Top events:\n" + _fmt_events(events) + "\n\n"
        "Knowledge base (analyst-feedback ranked first, 2x weighted):\n"
        + _weighted_kb_context(kb_matches) + "\n\n"
        "Return ONLY the JSON object."
    )
    for attempt in range(2):
        reply = _chat_with_timeout(
            model_name,
            [{"role": "system", "content": sys_msg},
             {"role": "user", "content": user_msg
                               + ("\n\n(Reminder: strict JSON only.)" if attempt else "")}],
            max_new_tokens=800, temperature=temperature, timeout_seconds=timeout,
        )
        parsed = _extract_json(reply)
        if isinstance(parsed, dict) and parsed.get("verdict") and parsed.get("analysis_lines"):
            # Coerce analysis_lines shape
            lines = parsed.get("analysis_lines") or []
            fixed_lines = []
            for i, ln in enumerate(lines, 1):
                if isinstance(ln, dict) and ln.get("text"):
                    fixed_lines.append({"n": i, "text": str(ln.get("text"))[:2000]})
                elif isinstance(ln, str):
                    fixed_lines.append({"n": i, "text": ln[:2000]})
            recs = parsed.get("recommendations") or []
            recs = [str(r)[:2000] for r in recs if str(r).strip()]
            v = str(parsed.get("verdict") or "").strip()
            if v not in ("TP", "FP", "Suspicious"):
                # normalise common phrasings
                low = v.lower()
                if "false" in low: v = "FP"
                elif "true" in low: v = "TP"
                else: v = "Suspicious"
            return {
                "used_kb": bool(parsed.get("used_kb")),
                "matched_kb_index": parsed.get("matched_kb_index"),
                "analysis_lines": fixed_lines,
                "verdict": v,
                "verdict_reason": str(parsed.get("verdict_reason") or "")[:2000],
                "recommendations": recs,
            }
    return None


# --------------------------------------------------------------------------- #
# Step 3 — Cross-verification (every field)                                   #
# --------------------------------------------------------------------------- #
def _step3_verify(model_name: str, offense: dict, events: list[dict],
                  draft: dict, temperature: float, timeout: int) -> dict | None:
    sys_msg = (
        "You are a senior SOC quality reviewer. Given a draft MSSP L1 report and "
        "the source offense + events, cross-check EVERY field for consistency and "
        "accuracy: does source_ip in the report actually appear in the events? Is "
        "the verdict consistent with the recommendations? Does the analysis "
        "actually explain what happened? Fix any inaccuracies. Preserve schema.\n\n"
        "Return ONLY the corrected JSON with keys:\n"
        "  fields: object with keys: " + ", ".join(_FIELD_KEYS) + "\n"
        "  analysis_lines: array of {\"n\": int, \"text\": string}\n"
        "  verdict: \"TP\" | \"FP\" | \"Suspicious\"\n"
        "  verdict_reason: string\n"
        "  recommendations: array of strings"
    )
    user_msg = (
        "Draft report:\n" + json.dumps(draft, indent=2) + "\n\n"
        "Source offense:\n" + _fmt_offense(offense) + "\n"
        "Source events:\n" + _fmt_events(events) + "\n\n"
        "Return ONLY the JSON object."
    )
    for attempt in range(2):
        reply = _chat_with_timeout(
            model_name,
            [{"role": "system", "content": sys_msg},
             {"role": "user", "content": user_msg
                               + ("\n\n(Reminder: strict JSON only.)" if attempt else "")}],
            max_new_tokens=900, temperature=temperature, timeout_seconds=timeout,
        )
        parsed = _extract_json(reply)
        if isinstance(parsed, dict) and parsed.get("verdict") and parsed.get("analysis_lines"):
            fields = parsed.get("fields") or {}
            fields = {k: (str(fields.get(k)) if fields.get(k) not in (None, "") else "N/A")
                      for k in _FIELD_KEYS}
            lines = []
            for i, ln in enumerate(parsed.get("analysis_lines") or [], 1):
                if isinstance(ln, dict) and ln.get("text"):
                    lines.append({"n": i, "text": str(ln.get("text"))[:2000]})
                elif isinstance(ln, str):
                    lines.append({"n": i, "text": ln[:2000]})
            recs = [str(r)[:2000] for r in (parsed.get("recommendations") or []) if str(r).strip()]
            v = str(parsed.get("verdict") or "").strip()
            if v not in ("TP", "FP", "Suspicious"):
                low = v.lower()
                v = "FP" if "false" in low else ("TP" if "true" in low else "Suspicious")
            return {
                "fields": fields,
                "analysis_lines": lines,
                "verdict": v,
                "verdict_reason": str(parsed.get("verdict_reason") or "")[:2000],
                "recommendations": recs,
            }
    return None


# --------------------------------------------------------------------------- #
# Orchestrator                                                                #
# --------------------------------------------------------------------------- #
def build_llm_mssp_report(offense: dict, events: list[dict],
                          kb_matches: list[dict],
                          rule_engine_mssp: dict,
                          model_name: str = "Qwen/Qwen2.5-0.5B-Instruct",
                          temperature: float = 0.3,
                          step_timeout_seconds: int = 180) -> dict | None:
    """Run the 3-step LLM chain. Returns a full MSSP report dict on success, else None.

    On success the returned dict is a drop-in replacement for
    `ai_analysis['mssp_report']` and includes `generated_by = "llm:<model>"`.

    On failure, the caller keeps `rule_engine_mssp` as-is (fallback semantics).
    """
    started = time.time()
    try:
        # Step 1: field selection
        t0 = time.time()
        fields = _step1_select_fields(model_name, offense, events,
                                      temperature=temperature,
                                      timeout=step_timeout_seconds)
        if not fields:
            logger.warning("LLM step1 (field selection) failed — falling back.")
            return None
        logger.info("LLM step1 done in %.1fs", time.time() - t0)

        # Step 2: KB-guided analysis
        t0 = time.time()
        draft = _step2_analyze(model_name, offense, events, fields, kb_matches,
                               temperature=temperature,
                               timeout=step_timeout_seconds)
        if not draft:
            logger.warning("LLM step2 (KB-guided analysis) failed — falling back.")
            return None
        logger.info("LLM step2 done in %.1fs (used_kb=%s)",
                    time.time() - t0, draft.get("used_kb"))

        # Merge fields into draft for verification input
        merged_for_verify = {
            "fields": fields,
            "analysis_lines": draft.get("analysis_lines") or [],
            "verdict": draft.get("verdict"),
            "verdict_reason": draft.get("verdict_reason"),
            "recommendations": draft.get("recommendations") or [],
        }

        # Step 3: cross-verify every field
        t0 = time.time()
        verified = _step3_verify(model_name, offense, events, merged_for_verify,
                                 temperature=temperature,
                                 timeout=step_timeout_seconds)
        if not verified:
            logger.warning("LLM step3 (cross-verify) failed — using draft without verification.")
            verified = merged_for_verify

        # Assemble final mssp_report in the schema the frontend expects.
        # Start from the rule-engine report to preserve any schema fields we
        # don't explicitly produce (custom_fields, edited_by/_at, vt_lookups, ...).
        out = dict(rule_engine_mssp or {})
        vf = verified.get("fields") or {}
        for k in _FIELD_KEYS:
            if vf.get(k) not in (None, ""):
                out[k] = vf.get(k)
        out["analysis_lines"] = verified.get("analysis_lines") or draft.get("analysis_lines") or []
        out["recommendations"] = verified.get("recommendations") or draft.get("recommendations") or []
        out["verdict"] = verified.get("verdict") or draft.get("verdict")
        out["verdict_reason"] = verified.get("verdict_reason") or draft.get("verdict_reason")
        out["recommendation_text"] = out.get("recommendation_text") or (
            (out.get("recommendations") or [""])[0] if out.get("recommendations") else "Monitor"
        )
        out["generated_by"] = f"llm:{model_name}"
        out["llm_used_kb"] = bool(draft.get("used_kb"))
        out["llm_matched_kb_index"] = draft.get("matched_kb_index")
        out["llm_generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        out["llm_total_seconds"] = round(time.time() - started, 1)
        return out
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM pipeline unexpected failure: %s — falling back.", e)
        return None


def load_error() -> str | None:
    return _STATE.get("load_error")


def _kb_reference_block(kb_matches: list[dict], max_docs: int = 2) -> str:
    """Top KB reference(s) for the SAME use-case (analyst-feedback weighted 2x)."""
    if not kb_matches:
        return "(no knowledge-base reference for this use case)"
    ranked = []
    for m in kb_matches:
        s = float(m.get("similarity") or 0)
        if m.get("kb_type") == "analyst_feedback":
            s *= 2.0
        ranked.append((s, m))
    ranked.sort(key=lambda x: x[0], reverse=True)
    out = []
    for i, (_, m) in enumerate(ranked[:max_docs], 1):
        out.append(f"[ref {i}] {(m.get('text') or '').strip()[:900]}")
    return "\n".join(out)


def _fields_block(rule_engine_mssp: dict, offense: dict) -> str:
    """Human-readable block of the extracted offense fields (incl. payload-derived)."""
    b = rule_engine_mssp or {}
    keys = [
        ("Offense Name", b.get("offense_name") or offense.get("description")),
        ("Severity", b.get("severity") or offense.get("severity_label")),
        ("Source IP", b.get("source_ip")),
        ("Destination IP", b.get("destination_ip")),
        ("Username", b.get("username")),
        ("Event Name", b.get("event_name")),
        ("Log Source", b.get("log_source")),
        ("Event ID", b.get("event_id")),
        ("Error Code", b.get("error_code")),
        ("Failure Reason", b.get("failure_reason")),
        ("Machine/Host", b.get("machine_identifier")),
        ("Low Level Category", b.get("low_level_category")),
    ]
    lines = [f"{k}: {v}" for k, v in keys if v not in (None, "", "N/A")]
    for fk, label in (b.get("fields") or []):
        if isinstance(fk, str) and fk.startswith("x_") and b.get(fk):
            lines.append(f"{label}: {b.get(fk)}")
    return "\n".join(lines) or "(no extracted fields)"


def _events_block(events: list[dict], limit: int = 3) -> str:
    if not events:
        return "(no events)"
    out = []
    for i, e in enumerate((events or [])[:limit], 1):
        if not isinstance(e, dict):
            continue
        parts = []
        for k in ("event_name", "log_source", "source_ip", "destination_ip", "username",
                  "low_level_category", "category", "event_id"):
            v = e.get(k)
            if v not in (None, "", []):
                parts.append(f"{k}={v}")
        pay = e.get("decoded_payload") or e.get("payload") or ""
        if pay:
            parts.append(f"payload={str(pay)[:450]}")
        out.append(f"  event[{i}]: " + "; ".join(parts))
    return "\n".join(out)


def _bullets(val) -> list[str]:
    """Coerce an LLM 'section' (list or paragraph) into clean bullet strings."""
    out: list[str] = []
    if isinstance(val, list):
        for x in val:
            if isinstance(x, dict) and x.get("text"):
                out.append(str(x["text"]).strip())
            elif isinstance(x, str) and x.strip():
                out.append(x.strip())
    elif isinstance(val, str) and val.strip():
        for s in re.split(r"(?:\r?\n|•|(?<=[.;])\s+)", val):
            s = s.strip(" -*•\t")
            if s:
                out.append(s)
    return [b[:2000] for b in out if b][:8]


def _sanitize_bullets(items) -> list[str]:
    """Drop model artifacts (JSON/key=value/field echoes/code snippets) and keep clean prose."""
    out = []
    for b in items or []:
        s = str(b).strip().strip('"').strip()
        if not s or s in ("-", "*", "•"):
            continue
        # Bare section markers the model sometimes emits (e.g. 'VARIABLES:', 'NOTES:').
        if re.fullmatch(r"[A-Z][A-Z0-9 _/&-]{1,40}:?", s):
            continue
        # Code / script fragments the small model sometimes injects.
        if re.match(r"^[$\\{}\[\]<>]", s):
            continue
        if re.search(r"::|=\s*\[|\];|FromBase64|GetString|System\.[A-Z]|\bEncoding\]", s):
            continue
        # Echoed structured data rather than prose.
        if re.match(r"^[\{\}\[\]]", s) or re.match(r"^[\w ]{1,30}=", s):
            continue
        if s.count("=") >= 2:
            continue
        head = s.split(":", 1)[0].strip().lower() if ":" in s else ""
        if head in ("event_name", "log_source", "username", "category", "payload", "src", "dst",
                    "ip address", "cti feed", "variables used", "example encoded command"):
            continue
        out.append(s[:2000])
    return out[:8]


_STOP_RE = re.compile(r"(?i)^(knowledge|variables?\s+used|offense\s+fields?|events?\b|reference|note\b|layout\b|json\b)")


def _clean_line(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"^\d+[\.\)]\s*", "", s)   # leading "1. "
    s = re.sub(r"^#+\s*", "", s)          # markdown headers
    return s.strip(" -*•\t").strip()


def _parse_sections(text: str | None) -> dict | None:
    """Parse a labeled plain-text report (ANALYSIS/IMPACT/RECOMMENDATIONS/VERDICT/REASON)
    into structured fields. Tolerant of markdown, bullets and truncation."""
    if not text:
        return None
    t = re.sub(r"`{3}[a-zA-Z]*", "", text)
    t = t.replace("*", "").replace("#", "")   # strip markdown emphasis/headers
    heads = r"ANALYSIS|IMPACT|RECOMMENDATIONS?|VERDICT|REASON"

    def body(name: str) -> str:
        m = re.search(rf"(?is)\b{name}\s*:?\s*(.*?)(?=\b(?:{heads})\b\s*:|$)", t)
        return m.group(1).strip() if m else ""

    def to_bullets(s: str) -> list[str]:
        if not s:
            return []
        rows = []
        for ln in re.split(r"\r?\n", s):
            c = _clean_line(ln)
            if not c:
                continue
            if _STOP_RE.match(c):
                break   # stop at echoed input / other sections
            rows.append(c)
        if len(rows) <= 1 and s.strip():
            blob = _clean_line(s.replace("\n", " "))
            rows = [x.strip() for x in re.split(r"(?<=[.;])\s+", blob) if x.strip()]
        return rows

    analysis = to_bullets(body("ANALYSIS"))
    impact = to_bullets(body("IMPACT"))
    recs = to_bullets(body("RECOMMENDATIONS?"))
    verdict = ""
    vm = re.search(r"(?i)\bVERDICT\b\s*:?\s*(true\s*positive|false\s*positive|suspicious|TP|FP)", t)
    if vm:
        vv = vm.group(1).lower()
        verdict = ("TP" if ("tp" == vv or "true" in vv)
                   else "FP" if ("fp" == vv or "false" in vv)
                   else "Suspicious")
    reason = body("REASON")
    reason = re.split(r"\r?\n", reason)[0].strip() if reason else ""
    if not (analysis or impact or recs or verdict):
        return None
    return {"analysis": analysis, "impact": impact, "recommendations": recs,
            "verdict": verdict, "reason": reason}


def _ensure_review_logs(recs: list[str], log_source: str | None) -> list[str]:
    """Guarantee a 'review the logs' investigation pointer is present."""
    recs = [r for r in (recs or []) if str(r).strip()]
    if any(re.search(r"(?i)review.{0,20}logs?|logs?.{0,20}review|correlate.{0,20}events?", r) for r in recs):
        return recs
    ls = (log_source or "").split("@")[0].split("::")[0].strip() or "the relevant device"
    recs.append(f"Review the {ls} logs and correlate the surrounding events around the alert "
                f"time to confirm the scope, source and intent of the activity.")
    return recs


def _kb_writeup_block(kb_ref: dict | None) -> str:
    """Authoritative analyst KB write-up (ITSM columns) for the SAME use case."""
    if not kb_ref:
        return ""
    parts = [f"USE CASE: {kb_ref.get('alert_name') or ''}"]
    if kb_ref.get("analysis"):
        parts.append("KB_ANALYSIS: " + str(kb_ref["analysis"])[:1600])
    if kb_ref.get("impact"):
        parts.append("KB_IMPACT: " + str(kb_ref["impact"])[:1000])
    if kb_ref.get("recommendations"):
        recs = kb_ref["recommendations"]
        recs = "; ".join(recs) if isinstance(recs, list) else str(recs)
        parts.append("KB_RECOMMENDATIONS: " + recs[:1200])
    return "\n".join(parts)


def build_llm_mssp_report_oneshot(offense: dict, events: list[dict],
                                  kb_matches: list[dict],
                                  rule_engine_mssp: dict,
                                  model_name: str = "Qwen/Qwen2.5-0.5B-Instruct",
                                  temperature: float = 0.3,
                                  timeout_seconds: int = 240,
                                  ioc_enrichment: dict | None = None,
                                  kb_ref: dict | None = None) -> dict | None:
    """Local-LLM pass producing a structured, TECHNICAL MSSP L1 analysis grounded in
    THIS offense's fields, events and payloads. The knowledge-base reference (a prior
    analysis of the SAME use-case) is provided so the model learns the expected format,
    depth and terminology — not for historical comparison. Returns a drop-in
    mssp_report dict (analysis_lines / impact_lines / recommendations / verdict), or
    None to fall back to the rule/KB report."""
    started = time.time()
    try:
        kb_block = _kb_writeup_block(kb_ref)
        if kb_block:
            sys_msg = (
                "You are an experienced MSSP SOC L1 analyst. You are given the analyst "
                "KNOWLEDGE-BASE WRITE-UP (from prior ITSM tickets) for the SAME use case as this "
                "offense, plus this offense's fields, events and payloads. READ the KB write-up, "
                "understand its meaning and reasoning, then produce the report for THIS offense by "
                "ADAPTING that KB knowledge to this offense's real artifacts (hosts, IPs, accounts, "
                "processes, ports, actions, log source).\n"
                "RULES:\n"
                "- Reuse the KB write-up's technical reasoning and depth; do not contradict it.\n"
                "- Write short, plain-English technical bullet sentences. No JSON, no field names, "
                "no key=value pairs, no raw payload text.\n"
                "- Do NOT mention other/previous/historical/similar offenses or the knowledge base itself.\n"
                "- Ground every statement in this offense's data.\n"
                "Respond EXACTLY in this layout and nothing else:\n"
                "ANALYSIS:\n- <why the alert triggered / what is involved / behavior observed>\n"
                "IMPACT:\n- <concrete technical impact in the environment>\n"
                "RECOMMENDATIONS:\n- <technical remediation / containment / investigation step; include reviewing the relevant logs>\n"
                "VERDICT: <TP or FP or Suspicious>\n"
                "REASON: <one technical sentence>\n"
                "Use 3-5 ANALYSIS bullets, 2-4 IMPACT bullets, 3-5 RECOMMENDATIONS bullets."
            )
            user_msg = (
                "KNOWLEDGE-BASE WRITE-UP FOR THIS USE CASE (adapt this to the offense below):\n"
                + kb_block + "\n\n"
                "THIS OFFENSE — FIELDS:\n" + _fields_block(rule_engine_mssp, offense) + "\n\n"
                "THIS OFFENSE — EVENTS (with payload):\n" + _events_block(events) + "\n\n"
                "Now write the report in the exact layout above, adapting the KB write-up to this offense."
            )
        else:
            sys_msg = (
                "You are an experienced MSSP SOC L1 analyst. Write a concise, TECHNICAL analyst "
                "report for ONE QRadar offense using its fields, events and payloads.\n"
                "RULES:\n"
                "- Write short, plain-English technical bullet sentences. Do NOT output JSON, field "
                "names, key=value pairs, or raw payload text.\n"
                "- Do NOT compare to or mention any other/previous/historical/similar offenses.\n"
                "- Ground every statement in the provided fields/payload (hosts, IPs, accounts, "
                "processes, ports, actions, log source).\n"
                "Respond EXACTLY in this layout and nothing else:\n"
                "ANALYSIS:\n- <why the alert triggered / what is involved / behavior observed>\n"
                "IMPACT:\n- <concrete technical impact in the environment>\n"
                "RECOMMENDATIONS:\n- <technical remediation / containment / investigation step; include reviewing the relevant logs>\n"
                "VERDICT: <TP or FP or Suspicious>\n"
                "REASON: <one technical sentence>\n"
                "Use 3-5 ANALYSIS bullets, 2-4 IMPACT bullets, 3-5 RECOMMENDATIONS bullets."
            )
            user_msg = (
                "OFFENSE FIELDS:\n" + _fields_block(rule_engine_mssp, offense) + "\n\n"
                "EVENTS (with payload):\n" + _events_block(events) + "\n\n"
                "KNOWLEDGE-BASE REFERENCE (same use case — match its style/depth only, do not reuse its data):\n"
                + _kb_reference_block(kb_matches) + "\n\n"
                "Now write the report in the exact layout above."
            )
        parsed = None
        for temp in (temperature, 0.0):
            reply = _chat_with_timeout(
                model_name,
                [{"role": "system", "content": sys_msg},
                 {"role": "user", "content": user_msg}],
                max_new_tokens=420, temperature=temp, timeout_seconds=timeout_seconds,
            )
            parsed = _parse_sections(reply)
            if isinstance(parsed, dict) and parsed.get("analysis"):
                break
        # Base = the report we were handed (KB-template when a use-case matched, else
        # rule-engine). We overlay whatever the model produced and BACKFILL any section
        # the (small) model leaves empty from this technical base — so the report is
        # always complete while the model still drives the verdict/refinements.
        out = dict(rule_engine_mssp or {})
        base_has_analysis = bool(out.get("analysis_lines"))
        if not isinstance(parsed, dict):
            if base_has_analysis:
                out["recommendations"] = _ensure_review_logs(out.get("recommendations"), out.get("log_source"))
                if out.get("recommendations"):
                    out["recommendation_text"] = out["recommendations"][0]
                return out
            return None

        analysis = _sanitize_bullets(parsed.get("analysis"))
        impact = _sanitize_bullets(parsed.get("impact"))
        recs = _sanitize_bullets(parsed.get("recommendations"))
        if not analysis and not recs and not base_has_analysis:
            return None
        v = str(parsed.get("verdict") or "").strip()
        reason = str(parsed.get("reason") or "").strip()

        if analysis:
            out["analysis_lines"] = [{"n": i, "text": t} for i, t in enumerate(analysis, 1)]
        if impact:
            out["impact_lines"] = impact
        if recs:
            out["recommendations"] = recs
        out["recommendations"] = _ensure_review_logs(out.get("recommendations"), out.get("log_source"))
        if out.get("recommendations"):
            out["recommendation_text"] = out["recommendations"][0]
        if v in ("TP", "FP", "Suspicious"):
            out["verdict"] = v
        if reason:
            out["verdict_reason"] = reason
        out["verdict"] = out.get("verdict") or "Suspicious"
        out["verdict_reason"] = out.get("verdict_reason") or ""
        if ioc_enrichment:
            out["ioc_enrichment"] = ioc_enrichment
        out["generated_by"] = f"llm:{model_name}"
        out["llm_total_seconds"] = round(time.time() - started, 1)
        return out
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM report generation failed: %s — falling back.", e)
        return None
