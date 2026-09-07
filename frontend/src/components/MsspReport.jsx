import { useMemo, useState } from "react";
import { Copy, Pencil, Save, X, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/api";

const DEFAULT_FIELDS = [
  ["offense_id", "Offense ID"],
  ["offense_name", "Offense Name"],
  ["severity", "Severity"],
  ["date_time", "Date and time"],
  ["source_ip", "Source IP"],
  ["destination_ip", "Destination IP"],
  ["username", "Username"],
  ["event_name", "Event name"],
  ["low_level_category", "Low Level Category"],
  ["error_code", "Error Code"],
  ["event_id", "Event ID"],
  ["failure_reason", "Failure Reason"],
  ["machine_identifier", "Machine Identifier"],
  ["log_source", "Log source"],
];

const EDITABLE_KEYS = new Set(DEFAULT_FIELDS.map(([k]) => k));

const asText = (r) => {
  if (!r) return "";
  const fields = (r.fields && r.fields.length) ? r.fields : DEFAULT_FIELDS;
  const lines = [];
  for (const [k, label] of fields) lines.push(`${label}: ${r[k] ?? "—"}`);
  for (const cf of (r.custom_fields || [])) lines.push(`${cf.key}: ${cf.value ?? "—"}`);
  lines.push("Analysis:");
  for (const l of (r.analysis_lines || [])) lines.push(`${l.n}. ${l.text}`);
  if (r.impact_lines && r.impact_lines.length) {
    lines.push("Impact:");
    r.impact_lines.forEach((t, i) => lines.push(`  ${i + 1}) ${t}`));
  }
  lines.push("Recommendation:");
  const recs = r.recommendations && r.recommendations.length ? r.recommendations : (r.recommendation_text ? [r.recommendation_text] : []);
  recs.forEach((rec, i) => lines.push(`  ${i + 1}) ${rec}`));
  if (r.ioc_enrichment && (r.ioc_enrichment.lines || []).length) {
    lines.push("IOC Enrichment:");
    r.ioc_enrichment.lines.forEach((t) => lines.push(`  ${t}`));
    if (r.ioc_enrichment.vt_url) lines.push(`  ${r.ioc_enrichment.vt_url}`);
  }
  if (r.vt_lookups && r.vt_lookups.length) {
    lines.push("VirusTotal Lookups:");
    r.vt_lookups.forEach((v) => {
      const res = v.result || {};
      const detail = res.error ? res.error : `MAL ${res.malicious || 0} · SUS ${res.suspicious || 0}${res.country ? " · " + res.country : ""}${res.as_owner ? " · " + res.as_owner : ""}`;
      lines.push(`  ${v.artifact_type}: ${v.value} → ${detail}`);
    });
  }
  if (r.verdict) lines.push(`Verdict: ${r.verdict} — ${r.verdict_reason || ""}`);
  if (r.analyst_notes) { lines.push("Analyst Notes:"); lines.push(r.analyst_notes); }
  return lines.join("\n");
};

export const MsspReport = ({ report, testId = "mssp-report", onFieldClick, offenseId, onUpdated }) => {
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [draft, setDraft] = useState(null);

  const editableFields = useMemo(() => {
    const raw = (report?.fields && report.fields.length) ? report.fields : DEFAULT_FIELDS;
    // Only expose fields that are known/safe to edit
    return raw.filter(([k]) => EDITABLE_KEYS.has(k));
  }, [report]);

  // Read-only view shows ALL report fields, including dynamically-discovered
  // payload fields (Source Port, Protocol, Action, Rule Name, SQL Command, …).
  const allFields = useMemo(
    () => ((report?.fields && report.fields.length) ? report.fields : DEFAULT_FIELDS),
    [report],
  );

  if (!report) {
    return (
      <div className="tactical-panel p-6 text-sm" style={{ color: "var(--tg-text-muted)" }} data-testid={`${testId}-empty`}>
        Run AI Investigation to generate the MSSP analyst report.
      </div>
    );
  }

  const startEdit = () => {
    setDraft({
      fields: Object.fromEntries(editableFields.map(([k]) => [k, report[k] ?? ""])),
      custom_fields: (report.custom_fields || []).map((c) => ({ ...c })),
      analysis_lines: (report.analysis_lines || []).map((l) => ({ ...l })),
      recommendations: [...(report.recommendations || [])],
      verdict: report.verdict || "",
      verdict_reason: report.verdict_reason || "",
      analyst_notes: report.analyst_notes || "",
    });
    setEditing(true);
  };
  const cancel = () => { setEditing(false); setDraft(null); };

  const save = async () => {
    if (!offenseId) return toast.error("Cannot save — no offense context.");
    setSaving(true);
    try {
      const r = await api.patch(`/offenses/${offenseId}/mssp-report`, {
        fields: draft.fields,
        custom_fields: draft.custom_fields,
        analysis_lines: draft.analysis_lines,
        recommendations: draft.recommendations,
        verdict: draft.verdict || null,
        verdict_reason: draft.verdict_reason || null,
        analyst_notes: draft.analyst_notes || null,
      });
      toast.success("MSSP report updated");
      setEditing(false);
      setDraft(null);
      onUpdated?.(r.data);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(asText(report));
      toast.success("MSSP report copied");
    } catch { toast.error("Copy failed"); }
  };

  const verdictColor = {
    TP: { bg: "rgba(217, 45, 32, 0.10)", border: "rgba(217, 45, 32, 0.32)", fg: "var(--tg-red)" },
    FP: { bg: "rgba(4, 106, 56, 0.10)", border: "rgba(4, 106, 56, 0.32)", fg: "var(--tg-cyan)" },
    Suspicious: { bg: "rgba(184, 134, 11, 0.10)", border: "rgba(184, 134, 11, 0.32)", fg: "var(--tg-amber)" },
  }[report.verdict] || { bg: "var(--tg-surface-2)", border: "var(--tg-border)", fg: "var(--tg-text-dim)" };

  return (
    <div className="tactical-panel p-6" data-testid={testId}>
      <div className="flex items-center justify-between mb-4 gap-3 flex-wrap">
        <div>
          <div className="text-[10px] font-mono tracking-[0.18em] uppercase" style={{ color: "var(--tg-text-muted)" }}>
            // L1 Analyst Report
          </div>
          <h3 className="font-display text-lg mt-1">MSSP Ticket Format</h3>
          {report.edited_by && !editing && (
            <div className="text-[10px] font-mono uppercase tracking-widest mt-1" style={{ color: "var(--tg-text-muted)" }}>
              Edited by <span style={{ color: "var(--tg-cyan)" }}>{report.edited_by}</span>
              {report.edited_at && ` · ${new Date(report.edited_at).toLocaleString()}`}
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          {report.generated_by && !editing && (
            <span className="tg-model" data-testid={`${testId}-source`} title={report.generated_by}>
              {report.generated_by.startsWith("kb-template")
                ? `KB Template${report.kb_template_score ? ` · ${report.kb_template_score}%` : ""}`
                : report.generated_by.startsWith("llm")
                  ? "Local LLM"
                  : "Rule Engine"}
            </span>
          )}
          {report.kb_learning && report.kb_learning.ticket_count > 0 && !editing && (
            <span className="tg-model" data-testid={`${testId}-kb-learning`}
                  title={`Learned from ${report.kb_learning.ticket_count} historical ticket(s) for use case: ${report.kb_learning.alert_name || ""}`}
                  style={{ color: "var(--tg-cyan)" }}>
              KB · {report.kb_learning.ticket_count} ticket{report.kb_learning.ticket_count === 1 ? "" : "s"}
              {report.kb_learning.match_score ? ` · ${report.kb_learning.match_score}%` : ""}
            </span>
          )}
          {report.verdict && !editing && (
            <span className="tg-sev" data-testid={`${testId}-verdict`}
                  style={{ background: verdictColor.bg, borderColor: verdictColor.border, color: verdictColor.fg }}>
              Verdict · {report.verdict}
            </span>
          )}
          {!editing && offenseId && (
            <button onClick={startEdit} className="tg-btn" data-testid={`${testId}-edit`}>
              <Pencil className="w-3 h-3" /> Edit
            </button>
          )}
          {!editing && (
            <button onClick={copy} className="tg-btn" data-testid={`${testId}-copy`}>
              <Copy className="w-3 h-3" /> Copy
            </button>
          )}
          {editing && (
            <>
              <button onClick={cancel} className="tg-btn" data-testid={`${testId}-cancel`}>
                <X className="w-3 h-3" /> Cancel
              </button>
              <button onClick={save} disabled={saving} className="tg-btn tg-btn-primary" data-testid={`${testId}-save`}>
                <Save className="w-3 h-3" /> {saving ? "Saving…" : "Save"}
              </button>
            </>
          )}
        </div>
      </div>

      <div className="font-mono text-sm space-y-2" style={{ color: "var(--tg-text)" }}>
        {(editing ? editableFields : allFields).map(([k, label]) => {
          const val = editing ? draft.fields[k] : report[k];
          const clickable = !editing && !!onFieldClick && val;
          return (
            <div key={k} className="grid grid-cols-[180px_1fr] gap-3 items-start" data-testid={`${testId}-${k}`}>
              <div style={{ color: "var(--tg-text-muted)" }}>{label}:</div>
              {editing ? (
                <input value={val || ""} onChange={(e) => setDraft({ ...draft, fields: { ...draft.fields, [k]: e.target.value } })}
                       data-testid={`${testId}-${k}-input`}
                       className="text-sm px-2 py-1 rounded-md focus:outline-none"
                       style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }} />
              ) : clickable ? (
                <button onClick={() => onFieldClick(label, val)} data-testid={`${testId}-${k}-jump`}
                        className="text-left break-all hover:underline decoration-dotted"
                        style={{ color: "var(--tg-text)" }}>
                  {val}
                </button>
              ) : (
                <div className="break-all whitespace-pre-wrap" style={{ color: "var(--tg-text)" }}>
                  {val ?? <span style={{ color: "var(--tg-text-hint)" }}>—</span>}
                </div>
              )}
            </div>
          );
        })}

        {/* Custom analyst-defined fields */}
        <div className="pt-3 mt-3" style={{ borderTop: "1px solid var(--tg-border)" }}>
          <div className="flex items-center justify-between mb-2">
            <div style={{ color: "var(--tg-text-muted)" }}>Custom Fields:</div>
            {editing && (
              <button onClick={() => setDraft({ ...draft, custom_fields: [...(draft.custom_fields || []), { key: "", value: "" }] })}
                      className="tg-btn" style={{ padding: "4px 8px" }} data-testid={`${testId}-add-custom`}>
                <Plus className="w-3 h-3" /> Add field
              </button>
            )}
          </div>
          {editing ? (
            <div className="space-y-2" data-testid={`${testId}-custom-editor`}>
              {(draft.custom_fields || []).map((cf, i) => (
                <div key={i} className="grid grid-cols-[180px_1fr_auto] gap-2 items-start" data-testid={`${testId}-custom-row-${i}`}>
                  <input value={cf.key}
                         placeholder="e.g. Client SLA"
                         onChange={(e) => {
                           const arr = [...draft.custom_fields];
                           arr[i] = { ...arr[i], key: e.target.value };
                           setDraft({ ...draft, custom_fields: arr });
                         }}
                         data-testid={`${testId}-custom-key-${i}`}
                         className="text-sm px-2 py-1 rounded-md focus:outline-none font-mono"
                         style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }} />
                  <input value={cf.value}
                         placeholder="value"
                         onChange={(e) => {
                           const arr = [...draft.custom_fields];
                           arr[i] = { ...arr[i], value: e.target.value };
                           setDraft({ ...draft, custom_fields: arr });
                         }}
                         data-testid={`${testId}-custom-value-${i}`}
                         className="text-sm px-2 py-1 rounded-md focus:outline-none"
                         style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }} />
                  <button onClick={() => setDraft({ ...draft, custom_fields: draft.custom_fields.filter((_, j) => j !== i) })}
                          className="tg-btn tg-btn-danger" style={{ padding: "4px 8px" }}
                          data-testid={`${testId}-custom-remove-${i}`}>
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
              {(!draft.custom_fields || draft.custom_fields.length === 0) && (
                <div className="text-sm" style={{ color: "var(--tg-text-hint)" }}>
                  No custom fields yet — click Add field to include values that aren't in the standard MSSP list (e.g. Client SLA, Ticket ID in XSOAR, Playbook Ref).
                </div>
              )}
            </div>
          ) : (report.custom_fields && report.custom_fields.length > 0) ? (
            <div className="space-y-2" data-testid={`${testId}-custom-fields`}>
              {report.custom_fields.map((cf, i) => (
                <div key={i} className="grid grid-cols-[180px_1fr] gap-3 items-center" data-testid={`${testId}-custom-${i}`}>
                  <div style={{ color: "var(--tg-text-muted)" }}>{cf.key}:</div>
                  <div className="break-words" style={{ color: "var(--tg-text)" }}>
                    {cf.value || <span style={{ color: "var(--tg-text-hint)" }}>—</span>}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-sm" style={{ color: "var(--tg-text-hint)" }}>
              No custom fields on this report.
            </div>
          )}
        </div>

        {/* Analysis */}
        <div className="pt-3 mt-3" style={{ borderTop: "1px solid var(--tg-border)" }}>
          <div className="flex items-center justify-between mb-2">
            <div style={{ color: "var(--tg-text-muted)" }}>Analysis:</div>
            {editing && (
              <button onClick={() => setDraft({ ...draft, analysis_lines: [...draft.analysis_lines, { n: (draft.analysis_lines.length + 1), text: "" }] })}
                      className="tg-btn" data-testid={`${testId}-add-line`} style={{ padding: "4px 8px" }}>
                <Plus className="w-3 h-3" /> Add line
              </button>
            )}
          </div>
          {editing ? (
            <ol className="space-y-2">
              {draft.analysis_lines.map((l, i) => (
                <li key={i} className="flex gap-2" data-testid={`${testId}-line-input-${i}`}>
                  <span style={{ color: "var(--tg-cyan)", fontFamily: "'JetBrains Mono', monospace" }}>{i + 1}.</span>
                  <textarea rows={2} value={l.text}
                            onChange={(e) => {
                              const arr = [...draft.analysis_lines];
                              arr[i] = { ...arr[i], text: e.target.value };
                              setDraft({ ...draft, analysis_lines: arr });
                            }}
                            className="flex-1 text-sm px-2 py-1 rounded-md focus:outline-none"
                            style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }} />
                  <button onClick={() => setDraft({ ...draft, analysis_lines: draft.analysis_lines.filter((_, j) => j !== i) })}
                          className="tg-btn tg-btn-danger" style={{ padding: "4px 8px" }}
                          data-testid={`${testId}-line-remove-${i}`}>
                    <Trash2 className="w-3 h-3" />
                  </button>
                </li>
              ))}
              {draft.analysis_lines.length === 0 && (
                <li className="text-sm" style={{ color: "var(--tg-text-hint)" }}>No analysis lines yet — click Add line.</li>
              )}
            </ol>
          ) : (
            <ol className="space-y-1.5 pl-1">
              {(report.analysis_lines || []).map((l) => (
                <li key={l.n} className="leading-relaxed" data-testid={`${testId}-line-${l.n}`} style={{ color: "var(--tg-text)" }}>
                  <span style={{ color: "var(--tg-cyan)" }}>{l.n}.</span> {l.text}
                </li>
              ))}
            </ol>
          )}
        </div>

        {/* Impact */}
        {(report.impact_lines && report.impact_lines.length > 0) && (
          <div className="pt-3 mt-3" style={{ borderTop: "1px solid var(--tg-border)" }}>
            <div className="mb-2" style={{ color: "var(--tg-text-muted)" }}>Impact:</div>
            <ul className="space-y-1.5 pl-1" data-testid={`${testId}-impact`}>
              {report.impact_lines.map((t, i) => (
                <li key={i} className="leading-relaxed flex gap-2" data-testid={`${testId}-impact-${i}`} style={{ color: "var(--tg-text)" }}>
                  <span className="shrink-0" style={{ color: "var(--tg-cyan)" }}>{i + 1})</span>
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Recommendation */}
        <div className="pt-3 mt-3" style={{ borderTop: "1px solid var(--tg-border)" }}>
          <div className="flex items-center justify-between mb-2">
            <div style={{ color: "var(--tg-text-muted)" }}>Recommendations:</div>
            {editing && (
              <button onClick={() => setDraft({ ...draft, recommendations: [...draft.recommendations, ""] })}
                      className="tg-btn" style={{ padding: "4px 8px" }} data-testid={`${testId}-add-rec`}>
                <Plus className="w-3 h-3" /> Add
              </button>
            )}
          </div>
          {editing ? (
            <ul className="space-y-2" data-testid={`${testId}-rec-list`}>
              {draft.recommendations.map((r, i) => (
                <li key={i} className="flex gap-2">
                  <span style={{ color: "var(--tg-cyan)" }}>{i + 1})</span>
                  <textarea rows={2} value={r}
                            onChange={(e) => {
                              const arr = [...draft.recommendations];
                              arr[i] = e.target.value;
                              setDraft({ ...draft, recommendations: arr });
                            }}
                            className="flex-1 text-sm px-2 py-1 rounded-md focus:outline-none"
                            style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }}
                            data-testid={`${testId}-rec-input-${i}`} />
                  <button onClick={() => setDraft({ ...draft, recommendations: draft.recommendations.filter((_, j) => j !== i) })}
                          className="tg-btn tg-btn-danger" style={{ padding: "4px 8px" }}
                          data-testid={`${testId}-rec-remove-${i}`}>
                    <Trash2 className="w-3 h-3" />
                  </button>
                </li>
              ))}
              {draft.recommendations.length === 0 && (
                <li className="text-sm" style={{ color: "var(--tg-text-hint)" }}>No recommendations yet.</li>
              )}
            </ul>
          ) : (report.recommendations && report.recommendations.length > 0) ? (
            <ul className="space-y-1.5 pl-1" data-testid={`${testId}-recommendations`}>
              {report.recommendations.map((r, i) => (
                <li key={i} className="leading-relaxed flex gap-2" data-testid={`${testId}-rec-${i}`}>
                  <span className="shrink-0" style={{ color: "var(--tg-cyan)" }}>{i + 1})</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="font-medium" style={{ color: "var(--tg-cyan)" }} data-testid={`${testId}-recommendation`}>
              {report.recommendation_text || <span style={{ color: "var(--tg-text-hint)" }}>—</span>}
            </div>
          )}
        </div>

        {/* IOC Enrichment (VirusTotal) */}
        {report.ioc_enrichment && ((report.ioc_enrichment.lines || []).length > 0 || report.ioc_enrichment.source_ip) && (
          <div className="pt-3 mt-3" style={{ borderTop: "1px solid var(--tg-border)" }} data-testid={`${testId}-ioc-enrichment`}>
            <div className="mb-2" style={{ color: "var(--tg-text-muted)" }}>IOC Enrichment:</div>
            <ul className="space-y-1.5 pl-1">
              {(report.ioc_enrichment.lines || []).map((t, i) => (
                <li key={i} className="leading-relaxed" data-testid={`${testId}-ioc-line-${i}`} style={{ color: "var(--tg-text)" }}>
                  {t}
                </li>
              ))}
            </ul>
            {report.ioc_enrichment.vt_url && (
              <a href={report.ioc_enrichment.vt_url} target="_blank" rel="noreferrer"
                 data-testid={`${testId}-ioc-vt-link`}
                 className="inline-block mt-2 text-xs font-mono hover:underline"
                 style={{ color: "var(--tg-cyan)" }}>
                VirusTotal ↗
              </a>
            )}
          </div>
        )}

        {/* VT lookups (read-only) */}
        {(report.vt_lookups && report.vt_lookups.length > 0) && (
          <div className="pt-3 mt-3" style={{ borderTop: "1px solid var(--tg-border)" }} data-testid={`${testId}-vt-lookups`}>
            <div className="mb-2" style={{ color: "var(--tg-text-muted)" }}>VirusTotal Lookups:</div>
            <ul className="space-y-1.5 pl-1">
              {report.vt_lookups.map((v, i) => {
                const res = v.result || {};
                const mal = res.malicious || 0;
                const sus = res.suspicious || 0;
                const color = res.error ? "var(--tg-text-muted)" : mal > 0 ? "var(--tg-red)" : sus > 0 ? "var(--tg-amber)" : "var(--tg-cyan)";
                return (
                  <li key={i} className="leading-relaxed flex flex-wrap gap-2 items-center" data-testid={`${testId}-vt-${i}`}>
                    <span className="tg-label">{v.artifact_type}</span>
                    <span className="font-mono break-all">{v.value}</span>
                    <span style={{ color: "var(--tg-text-muted)" }}>→</span>
                    <span style={{ color }} className="font-mono text-xs">
                      {res.error ? res.error : `MAL ${mal} · SUS ${sus}`}
                      {res.country ? ` · ${res.country}` : ""}
                      {res.as_owner ? ` · ${res.as_owner}` : ""}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        {/* Verdict */}
        <div className="pt-3 mt-3 grid grid-cols-[180px_1fr] gap-3" style={{ borderTop: "1px solid var(--tg-border)" }} data-testid={`${testId}-verdict-reason`}>
          <div style={{ color: "var(--tg-text-muted)" }}>Verdict:</div>
          {editing ? (
            <div className="flex flex-col gap-2">
              <div className="flex gap-2">
                {["", "TP", "FP", "Suspicious"].map((v) => (
                  <button key={v || "none"} onClick={() => setDraft({ ...draft, verdict: v })}
                          data-testid={`${testId}-verdict-${v || "none"}`}
                          className="tg-btn" style={{ padding: "4px 10px",
                            background: draft.verdict === v ? "rgba(4, 106, 56, 0.08)" : undefined,
                            borderColor: draft.verdict === v ? "var(--tg-cyan)" : undefined,
                            color: draft.verdict === v ? "var(--tg-cyan)" : undefined }}>
                    {v || "None"}
                  </button>
                ))}
              </div>
              <textarea rows={3} value={draft.verdict_reason}
                        onChange={(e) => setDraft({ ...draft, verdict_reason: e.target.value })}
                        placeholder="Verdict reason (why TP / FP / Suspicious)"
                        data-testid={`${testId}-verdict-reason-input`}
                        className="text-sm px-2 py-1 rounded-md focus:outline-none"
                        style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }} />
            </div>
          ) : (
            <div style={{ color: "var(--tg-text)" }} className="leading-relaxed">
              {report.verdict ? (
                <>
                  <span className="tg-sev mr-2" style={{ background: verdictColor.bg, borderColor: verdictColor.border, color: verdictColor.fg }}>
                    {report.verdict}
                  </span>
                  {report.verdict_reason || "—"}
                </>
              ) : (
                <span style={{ color: "var(--tg-text-hint)" }}>Not set</span>
              )}
            </div>
          )}
        </div>

        {/* Analyst notes */}
        <div className="pt-3 mt-3" style={{ borderTop: "1px solid var(--tg-border)" }}>
          <div className="mb-2" style={{ color: "var(--tg-text-muted)" }}>Analyst Notes:</div>
          {editing ? (
            <textarea rows={4} value={draft.analyst_notes}
                      onChange={(e) => setDraft({ ...draft, analyst_notes: e.target.value })}
                      placeholder="Additional context, containment steps taken, communications with the client, etc."
                      data-testid={`${testId}-analyst-notes-input`}
                      className="w-full text-sm px-2 py-1 rounded-md focus:outline-none"
                      style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }} />
          ) : report.analyst_notes ? (
            <div className="leading-relaxed whitespace-pre-wrap" data-testid={`${testId}-analyst-notes`} style={{ color: "var(--tg-text)" }}>
              {report.analyst_notes}
            </div>
          ) : (
            <div className="text-sm" style={{ color: "var(--tg-text-hint)" }}>No analyst notes yet — click Edit to add.</div>
          )}
        </div>
      </div>
    </div>
  );
};
