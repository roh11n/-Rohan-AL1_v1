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
import os
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
# OpenRouter (cloud) inference                                                #
# --------------------------------------------------------------------------- #
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def _openrouter_chat(model_name: str, messages: list[dict], max_new_tokens: int,
                     temperature: float, api_key: str) -> str | None:
    """OpenAI-compatible chat completion via OpenRouter. Returns assistant text.

    Tries the configured model then falls back to the resilient `openrouter/free`
    auto-router if the primary provider is rate-limited/unavailable upstream.
    """
    primary = (os.environ.get("OPENROUTER_MODEL") or model_name
               or "openrouter/free").strip()
    candidates = [primary]
    if "openrouter/free" not in candidates:
        candidates.append("openrouter/free")
    try:
        import httpx  # type: ignore
    except Exception as e:  # noqa: BLE001
        logger.warning("httpx unavailable for OpenRouter: %s", e)
        return None
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://socpilot.ai",
        "X-Title": "SOCPilot",
    }
    for model in candidates:
        for attempt in range(2):
            try:
                resp = httpx.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": model,
                        "messages": messages,
                        "max_tokens": max_new_tokens,
                        "temperature": max(0.0, temperature),
                    },
                    timeout=120.0,
                )
                if resp.status_code == 429:
                    logger.warning("OpenRouter 429 for %s (attempt %d) — retrying/falling back.",
                                   model, attempt + 1)
                    time.sleep(2 + attempt * 3)
                    continue
                resp.raise_for_status()
                data = resp.json()
                choice = (data.get("choices") or [{}])[0]
                content = (choice.get("message") or {}).get("content") or ""
                content = _THINK_RE.sub("", content).strip()
                if content:
                    return content
            except Exception as e:  # noqa: BLE001
                logger.warning("OpenRouter inference error (%s): %s", model, e)
                break
    return None


# --------------------------------------------------------------------------- #
# Inference primitive                                                         #
# --------------------------------------------------------------------------- #
def _chat_once(model_name: str, messages: list[dict], max_new_tokens: int,
               temperature: float) -> str | None:
    """Single chat-format inference.

    When OPENROUTER_API_KEY is set, inference is served by the OpenRouter cloud
    API (OpenAI-compatible) using OPENROUTER_MODEL. Otherwise it falls back to the
    local HuggingFace transformers model. Returns generated text (assistant reply).
    """
    api_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if api_key:
        return _openrouter_chat(model_name, messages, max_new_tokens,
                                temperature, api_key)
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
        m = re.search(rf"(?is)\b{name}\b\s*:?\s*(.*?)(?=\b(?:{heads})\b\s*:|$)", t)
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


_ARTIFACT_KEYS = [
    ("source_ip", "source IP"), ("destination_ip", "destination IP"), ("username", "user account"),
    ("machine_identifier", "host"), ("log_source", "log source"), ("x_destination_port", "destination port"),
    ("x_protocol", "protocol"), ("x_action", "action"), ("x_process", "process"),
    ("x_parent_process", "parent process"), ("x_command_line", "command line"),
    ("x_file_hash", "file hash"), ("x_sha256", "SHA256"), ("x_md5", "MD5"), ("x_file_name", "file name"),
    ("x_file_path", "file path"), ("x_domain_url", "domain/URL"), ("x_url", "URL"),
    ("x_host", "host"), ("x_asset_name", "asset"), ("x_application", "application"),
]


def _artifacts(rule_engine_mssp: dict) -> list[tuple[str, str]]:
    """(label, value) pairs of THIS offense's concrete artifacts, from the extracted fields."""
    b = rule_engine_mssp or {}
    out, seen = [], set()
    for k, label in _ARTIFACT_KEYS:
        v = b.get(k)
        if v in (None, "", "N/A") or str(v) in seen:
            continue
        seen.add(str(v))
        out.append((label, str(v)[:160]))
    return out


def _artifact_tokens(artifacts: list[tuple[str, str]]) -> list[str]:
    toks = []
    for _, v in artifacts:
        v = v.split("@")[0].split("::")[0].strip()
        if len(v) >= 3:
            toks.append(v.lower())
    return toks


def _grounded(bullets: list[str], artifacts: list[tuple[str, str]]) -> int:
    toks = _artifact_tokens(artifacts)
    return sum(1 for b in bullets if any(t in b.lower() for t in toks))


def _lead_bullet(rule_engine_mssp: dict, offense: dict) -> str | None:
    """Deterministic, fully grounded opening sentence for THIS offense."""
    b = rule_engine_mssp or {}
    name = str(b.get("offense_name") or offense.get("description") or "").replace("\n", " ").strip()
    name = re.sub(r"\s+", " ", name)
    ls = str(b.get("log_source") or "").split("@")[0].split("::")[0].strip()
    src, dst, user, host = b.get("source_ip"), b.get("destination_ip"), b.get("username"), b.get("machine_identifier")
    if not (src or dst or user or host):
        return None
    s = f"The alert '{name}' " if name else "The alert "
    s += f"was raised by {ls} " if ls else ""
    who = []
    if host:
        who.append(f"host {host}")
    if src:
        who.append(f"source IP {src}")
    if user:
        who.append(f"user account {user}")
    s += "for " + ", ".join(who) if who else ""
    if dst:
        port = b.get("x_destination_port")
        s += f" communicating with destination {dst}" + (f" on port {port}" if port else "")
    proc = b.get("x_process")
    if proc:
        s += f"; the process involved was {proc}"
        if b.get("x_parent_process"):
            s += f" (parent {b['x_parent_process']})"
    if b.get("x_action"):
        s += f"; the device action was '{b['x_action']}'"
    if b.get("date_time"):
        s += f" at {b['date_time']}"
    return s.strip() + "."


def _kb_writeup_block(kb_ref: dict | None) -> str:
    """Learned analyst knowledge (ITSM columns) consolidated across every historical
    ticket of the SAME use case."""
    if not kb_ref:
        return ""
    n = int(kb_ref.get("ticket_count") or 1)
    parts = [f"USE CASE: {str(kb_ref.get('alert_name') or '').strip()}",
             f"(learned from {n} historical analyst ticket{'s' if n != 1 else ''})"]

    def pts(key, single, cap):
        vals = kb_ref.get(key) or []
        if not vals and kb_ref.get(single):
            v = kb_ref[single]
            vals = v if isinstance(v, list) else [v]
        return [str(v).strip() for v in vals if str(v).strip()][:cap]

    a = pts("analysis_points", "analysis", 8)
    i = pts("impact_points", "impact", 6)
    r = pts("recommendation_points", "recommendations", 8)
    if a:
        parts.append("KB_ANALYSIS (how analysts reasoned about this use case):\n" + "\n".join(f"- {x}" for x in a))
    if i:
        parts.append("KB_IMPACT:\n" + "\n".join(f"- {x}" for x in i))
    if r:
        parts.append("KB_RECOMMENDATIONS:\n" + "\n".join(f"- {x}" for x in r))
    return "\n".join(parts)


_JUNK_RE = re.compile(
    r"(?i)artifacts of this offense|use these exact values|learned knowledge|this offense\s*[—-]|"
    r"^(report|type|title|name|severity|critical severity|use case|section|layout)\s*:|"
    r"^(analysis|impact|recommendations?|verdict|reason)\s*:?\s*$")
_IMPERATIVE_RE = re.compile(
    r"(?i)^(?:[\w /-]{1,30}:\s*)?(block|isolate|disable|kill|terminate|reset|revoke|collect|decode|"
    r"hunt|review|investigate|validate|verify|update|patch|remove|quarantine|escalate|notify|"
    r"contain|monitor|preserve|interview|enable|enforce|rotate|restrict|check|confirm|run|scan|"
    r"engage|report|reimage|re-image|restore|apply|ensure)\b")
# Fabricated "we already did X" narration has no place in an L1 analysis of a new offense.
_ACTIONS_TAKEN_RE = re.compile(r"(?i)^(mitigation|remediation|actions?\s+taken|recommendations?|next steps?)\b")
# "Label: value" echoes of the artifact list (e.g. "Destination IP: 1.2.3.4", "Port Number: 443").
_ECHO_RE = re.compile(
    r"(?i)^(source|destination|dest|external|internal|remote)?\s*(ip( address)?|port( number)?|user(-agent| account|name)?|"
    r"host(name)?|log source|proxy( server)?|dns( server)?|protocol|action|process|parent process|command line|"
    r"file (hash|name|path)|sha256|md5|domain|url|asset|application|event name|time(stamp)?)\s*:\s*\S.{0,80}$")
# Reasoning-model leakage: some cloud models echo the task/their own chain-of-thought as
# plain content (not <think> tags). Drop any line that talks about the instructions itself.
_META_RE = re.compile(
    r"(?i)(\bwe need to\b|\bthe user\b|\buser (wants|said|asked)\b|\blet'?s\b|\bi (will|should|need|'ll)\b|"
    r"\bmust (explain|output|not mention|use|write|start|include|mention|name|reference|state|describe)\b|"
    r"\beach (bullet |line )?start(s|ing)? with\b|\bin every bullet\b|"
    r"\bno (json|headings?|field names|key=value|raw payload|other sections)\b|"
    r"\bonly the (analysis|impact|recommendations?) section\b|\b(analysis|impact|recommendations?) section\b|"
    r"\bartifact values\b|\bplain[- ]english\b|\bas an? (ai|assistant|language model)\b|"
    r"\bon separate lines?\b|\bwrite exactly\b|verdict\s*:\s*<|reason\s*:\s*<|<(tp|fp|one |a )|"
    r"^(okay|sure|certainly|here('| i)s|below is|based on the (instructions?|prompt)))")


def _section_bullets(reply: str | None, min_words: int = 4) -> list[str]:
    """Parse one section reply into clean bullets (tolerant of markdown/numbering)."""
    if not reply:
        return []
    t = re.sub(r"`{3}[a-zA-Z]*", "", reply).replace("*", "").replace("#", "")
    rows = []
    for ln in re.split(r"\r?\n", t):
        c = _clean_line(ln)
        if not c or _STOP_RE.match(c) or _JUNK_RE.search(c) or _META_RE.search(c):
            continue
        if re.match(r"(?i)^(analysis|impact|recommendations?|verdict|reason)\s*:", c):
            c = re.sub(r"(?i)^(analysis|impact|recommendations?)\s*:\s*", "", c).strip()
            if not c:
                continue
        rows.append(c)
    if len(rows) <= 1 and t.strip():
        blob = _clean_line(t.replace("\n", " "))
        rows = [_clean_line(x) for x in re.split(r"(?<=[.;])\s+", blob) if x.strip()]
    rows = [r for r in rows if not _META_RE.search(r)]
    rows = _sanitize_bullets(rows)
    detail_prefix = re.compile(r"(?i)^(action|detail|details|steps?)\s*:\s*")
    tagged = [(bool(detail_prefix.match(r)), detail_prefix.sub("", r)) for r in rows]
    tagged = [(d, r) for d, r in tagged if len(r.split()) >= min_words and not _ECHO_RE.match(r)]
    # Merge "Heading:" rows with an explicit "Action:" detail that follows; otherwise close them.
    merged: list[str] = []
    i = 0
    while i < len(tagged):
        _, r = tagged[i]
        if r.endswith(":") and i + 1 < len(tagged) and tagged[i + 1][0]:
            merged.append(f"{r[:-1].strip()} — {tagged[i + 1][1]}")
            i += 2
            continue
        merged.append(r[:-1].strip() + "." if r.endswith(":") else r)
        i += 1
    rows = merged
    # A truncated final bullet (max_new_tokens hit) is dropped rather than shown half-written.
    if len(rows) > 1 and not re.search(r"[.!?)\]\"']$", rows[-1].strip()):
        rows = rows[:-1]
    return rows


def _dedupe_across(primary: list[str], other: list[str]) -> list[str]:
    seen = {re.sub(r"\W+", " ", p.lower()).strip() for p in primary}
    return [o for o in other if re.sub(r"\W+", " ", o.lower()).strip() not in seen]


def _verdict_from(reply: str | None) -> tuple[str, str]:
    if not reply:
        return "", ""
    v = ""
    vm = re.search(r"(?i)\bVERDICT\b\s*:?\s*\**\s*(true\s*positive|false\s*positive|suspicious|TP|FP)", reply)
    if vm:
        vv = vm.group(1).lower()
        v = ("TP" if (vv == "tp" or "true" in vv) else "FP" if (vv == "fp" or "false" in vv) else "Suspicious")
    rm = re.search(r"(?i)\bREASON\b\s*:?\s*(.+)", reply)
    reason = _clean_line(re.split(r"\r?\n", rm.group(1))[0]) if rm else ""
    reason = reason.lstrip("*:- ").strip()
    reason = "" if (_JUNK_RE.search(reason) or _META_RE.search(reason) or "<" in reason) else reason[:600]
    return v, reason


def build_llm_mssp_report_oneshot(offense: dict, events: list[dict],
                                  kb_matches: list[dict],
                                  rule_engine_mssp: dict,
                                  model_name: str = "Qwen/Qwen2.5-0.5B-Instruct",
                                  temperature: float = 0.3,
                                  timeout_seconds: int = 240,
                                  ioc_enrichment: dict | None = None,
                                  kb_ref: dict | None = None) -> dict | None:
    """Local-LLM MSSP L1 report, generated SECTION BY SECTION (small-model friendly):
    Analysis -> Impact -> Recommendations+Verdict. When the use case matches the KB, the
    consolidated analyst knowledge (ITSM analysis/impact/recommendations across all
    tickets) is the reasoning the model must apply to THIS offense's artifacts. Every
    bullet is then grounded with the offense's real values. Falls back to the grounded
    KB/rule base for any section the model leaves empty. Returns None only when nothing
    usable exists."""
    started = time.time()
    try:
        from kb_template import build_fieldmap, fix_direction, ground_sentence
        kb_block = _kb_writeup_block(kb_ref)
        artifacts = _artifacts(rule_engine_mssp)
        art_block = "\n".join(f"- {lbl}: {val}" for lbl, val in artifacts) or "- (none extracted)"
        alert_name = str(offense.get("description") or "")
        fm = build_fieldmap(rule_engine_mssp, offense)

        if kb_block:
            role = (
                "You are an experienced MSSP SOC L1 analyst. You have the LEARNED KNOWLEDGE for this "
                "exact use case (consolidated from analysts' historical ITSM tickets). Apply that reasoning "
                "to THIS offense: same conclusions, depth and terminology, but with THIS offense's real "
                "artifacts (IPs, user, host, process, port, action, log source) written into every bullet. "
                "Never contradict the learned knowledge; never copy it without inserting this offense's values. "
                "Do NOT mention other/previous/historical tickets, offenses or the knowledge base. "
                "Plain-English technical sentences only: no JSON, no field names, no key=value, no raw payload."
            )
            context = ("LEARNED KNOWLEDGE FOR THIS USE CASE:\n" + kb_block + "\n\n")
        else:
            role = (
                "You are an experienced MSSP SOC L1 analyst writing a concise TECHNICAL report for ONE "
                "QRadar offense from its artifacts, fields, events and payloads. Name the actual IP, user, "
                "host, process, port, action or log source in every bullet. Do NOT compare to or mention any "
                "other/previous/historical offenses. Plain-English technical sentences only: no JSON, no field "
                "names, no key=value, no raw payload."
            )
            context = ("KNOWLEDGE-BASE REFERENCE (same use case — match its style/depth only, do not reuse its data):\n"
                       + _kb_reference_block(kb_matches) + "\n\n")
        context += ("ARTIFACTS OF THIS OFFENSE (use these exact values):\n" + art_block + "\n\n"
                    "OFFENSE FIELDS:\n" + _fields_block(rule_engine_mssp, offense) + "\n\n"
                    "EVENTS (with payload):\n" + _events_block(events) + "\n\n")

        def ask(task: str, max_tokens: int) -> str | None:
            for temp in (temperature, 0.0):
                r = _chat_with_timeout(
                    model_name,
                    [{"role": "system", "content": role},
                     {"role": "user", "content": context + task}],
                    max_new_tokens=max_tokens, temperature=temp, timeout_seconds=timeout_seconds)
                if r and r.strip():
                    return r
            return None

        a_reply = ask(
            "Write ONLY the ANALYSIS section: 3-4 bullets, each starting with '- ', explaining why the "
            "alert triggered, what was involved and the behaviour observed for THIS offense (use the "
            "artifact values). No other sections, no headings.", 220)
        i_reply = ask(
            "Write ONLY the IMPACT section: 2-3 bullets, each starting with '- ', stating the concrete "
            "technical/business impact of THIS activity for the affected host/user/environment. No "
            "recommendations, no other sections, no headings.", 150)
        r_reply = ask(
            "Write ONLY the RECOMMENDATIONS section: 3-5 bullets, each starting with '- ', each a "
            "specific remediation/containment/investigation action applied to THIS offense's artifacts. "
            "After the bullets, add two final lines. First line: the word VERDICT followed by a colon and "
            "one of TP, FP or Suspicious. Second line: the word REASON followed by a colon and one short "
            "technical sentence justifying the verdict.", 260)

        def polish(items):
            out_ = []
            for s in items:
                s = fix_direction(ground_sentence(s, fm), alert_name)
                if s not in out_:
                    out_.append(s)
            return out_

        analysis = _section_bullets(a_reply)
        impact = _section_bullets(i_reply)
        recs = _section_bullets(r_reply and re.split(r"(?i)\bVERDICT\b", r_reply)[0])
        # Route imperative "do X" sentences the model put in Analysis/Impact into Recommendations.
        moved = [b for b in analysis + impact if _IMPERATIVE_RE.match(b)]
        analysis = [b for b in analysis if not _IMPERATIVE_RE.match(b) and not _ACTIONS_TAKEN_RE.match(b)]
        impact = [b for b in impact if not _IMPERATIVE_RE.match(b) and not _ACTIONS_TAKEN_RE.match(b)]
        recs = recs + _dedupe_across(recs, moved)
        impact = _dedupe_across(analysis, impact)
        analysis, impact, recs = polish(analysis)[:6], polish(impact)[:4], polish(recs)[:6]
        v, reason = _verdict_from(r_reply)

        out = dict(rule_engine_mssp or {})
        base_has_analysis = bool(out.get("analysis_lines"))
        if not analysis and not recs and not base_has_analysis:
            return None

        lead = _lead_bullet(rule_engine_mssp, offense)
        if analysis:
            if lead and _grounded(analysis, artifacts) < 2:
                analysis = [lead] + analysis
            out["analysis_lines"] = [{"n": i, "text": t} for i, t in enumerate(analysis[:7], 1)]
        elif lead and base_has_analysis:
            base_txt = [ln.get("text") for ln in out["analysis_lines"] if ln.get("text")]
            if _grounded(base_txt, artifacts) < 2:
                out["analysis_lines"] = [{"n": i, "text": t} for i, t in enumerate([lead] + base_txt, 1)]
        out["llm_grounded_bullets"] = _grounded([ln["text"] for ln in out.get("analysis_lines") or []], artifacts)
        if impact:
            out["impact_lines"] = impact
        if recs:
            out["recommendations"] = recs
        out["recommendations"] = [r for r in (out.get("recommendations") or []) if str(r).strip()]
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
        if kb_ref:
            out["kb_learning"] = {
                "alert_name": kb_ref.get("alert_name"),
                "ticket_count": int(kb_ref.get("ticket_count") or 1),
                "match_score": kb_ref.get("match_score") or out.get("kb_template_score"),
                "verdict_counts": kb_ref.get("verdict_counts") or {},
            }
        out["llm_sections"] = {"analysis": bool(analysis), "impact": bool(impact), "recommendations": bool(recs)}
        out["generated_by"] = f"llm:{model_name}"
        out["llm_total_seconds"] = round(time.time() - started, 1)
        return out
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM report generation failed: %s — falling back.", e)
        return None
