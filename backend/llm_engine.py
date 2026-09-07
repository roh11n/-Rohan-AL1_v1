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


def build_llm_mssp_report_oneshot(offense: dict, events: list[dict],
                                  kb_matches: list[dict],
                                  rule_engine_mssp: dict,
                                  model_name: str = "Qwen/Qwen2.5-0.5B-Instruct",
                                  temperature: float = 0.3,
                                  timeout_seconds: int = 240) -> dict | None:
    """Single compact local-LLM pass producing the MSSP analysis. Reuses the
    rule-engine's already-extracted fields and asks the model for a SHORT JSON
    (few analysis lines) so generation stays affordable on CPU. Intended to run
    in the background. Returns a drop-in mssp_report dict, or None to fall back."""
    started = time.time()
    try:
        sys_msg = (
            "You are a SOC L1 analyst. Using the offense, its events and the knowledge-base "
            "reference (a prior incident with the SAME alert name), write the analysis for THIS "
            "offense. Reuse the reference's reasoning and verdict, but replace its artifacts with "
            "THIS offense's actual artifacts (source IP, destination IP, username, time). "
            "Return ONLY compact JSON: {\"analysis_lines\":[{\"n\":1,\"text\":\"...\"}],"
            "\"verdict\":\"TP|FP|Suspicious\",\"verdict_reason\":\"...\","
            "\"recommendations\":[\"...\"]}. Use 3-5 short analysis_lines."
        )
        user_msg = (
            "Offense:\n" + _fmt_offense(offense) + "\n"
            "Top events:\n" + _fmt_events(events, limit=3) + "\n\n"
            "Knowledge-base reference (adapt this):\n" + _weighted_kb_context(kb_matches, max_docs=2) + "\n\n"
            "Return ONLY the JSON object."
        )
        reply = _chat_with_timeout(
            model_name,
            [{"role": "system", "content": sys_msg},
             {"role": "user", "content": user_msg}],
            max_new_tokens=320, temperature=temperature, timeout_seconds=timeout_seconds,
        )
        parsed = _extract_json(reply)
        if not isinstance(parsed, dict):
            return None
        v = str(parsed.get("verdict") or "").strip()
        if v not in ("TP", "FP", "Suspicious"):
            low = v.lower()
            v = "FP" if "false" in low else ("TP" if "true" in low else "Suspicious")
        reason = str(parsed.get("verdict_reason") or "").strip()
        recs = [str(r)[:2000] for r in (parsed.get("recommendations") or []) if str(r).strip()]

        # Model's analysis lines (weak 0.5B models often leave these empty and
        # push the reasoning into verdict_reason — so synthesize when missing).
        model_lines = []
        for ln in parsed.get("analysis_lines") or []:
            if isinstance(ln, dict) and ln.get("text"):
                model_lines.append(str(ln["text"])[:2000])
            elif isinstance(ln, str) and ln.strip():
                model_lines.append(ln.strip()[:2000])
        if not model_lines and reason:
            model_lines = [s.strip() for s in re.split(r"(?<=[.;])\s+", reason) if s.strip()]
        if not model_lines and not reason:
            return None  # nothing usable from the model

        def _first(key):
            v = rule_engine_mssp.get(key.rstrip("s")) if rule_engine_mssp else None
            if v:
                return v
            arr = offense.get(key) or []
            return arr[0] if arr else None
        obs = []
        if _first("source_ips"): obs.append(f"Source IP: {_first('source_ips')}")
        if _first("destination_ips"): obs.append(f"Destination IP: {_first('destination_ips')}")
        if _first("usernames"): obs.append(f"Username: {_first('usernames')}")
        obs.append(f"Offense ID: {offense.get('qradar_offense_id') or offense.get('id')}")

        lines = [{"n": i, "text": t} for i, t in enumerate(model_lines, 1)]
        lines.append({"n": len(lines) + 1,
                      "text": "Observed artifacts in this offense — " + "; ".join(obs) + "."})

        out = dict(rule_engine_mssp or {})
        out["analysis_lines"] = lines
        out["recommendations"] = recs or out.get("recommendations") or []
        out["verdict"] = v
        out["verdict_reason"] = reason or out.get("verdict_reason") or ""
        if out.get("recommendations"):
            out["recommendation_text"] = out["recommendations"][0]
        out["generated_by"] = f"llm:{model_name}"
        out["llm_total_seconds"] = round(time.time() - started, 1)
        return out
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM one-shot pipeline failure: %s — falling back.", e)
        return None
