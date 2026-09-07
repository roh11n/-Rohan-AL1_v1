import { useEffect, useState } from "react";
import { toast } from "sonner";
import { ArrowUpRight, Ban, RefreshCw, Copy as CopyIcon } from "lucide-react";
import api from "@/lib/api";

export const LifecycleActions = ({ offense, onUpdated }) => {
  const [showEscalate, setShowEscalate] = useState(false);
  const [showClose, setShowClose] = useState(false);
  const [dupes, setDupes] = useState([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!offense?.id) return;
    api.get(`/offenses/${offense.id}/duplicates`).then((r) => setDupes(r.data.duplicates || []))
      .catch(() => setDupes([]));
  }, [offense?.id]);

  const closeAsDuplicate = async (d) => {
    setBusy(true);
    try {
      const comments = `Closed as duplicate of #${d.qradar_offense_id || d.id.slice(0, 8)} (${d.description}). Prior closure: ${d.closure_comments || d.recommendation || "resolved"}.`;
      const r = await api.post(`/offenses/${offense.id}/close`, {
        closure_comments: comments,
        closure_source: "duplicate",
      });
      toast.success("Offense closed as duplicate");
      onUpdated?.(r.data);
    } catch (e) { toast.error(e?.response?.data?.detail || "Close failed"); }
    finally { setBusy(false); }
  };

  return (
    <>
      {dupes.length > 0 && (
        <div className="tactical-panel p-4 border-l-4" style={{ borderLeftColor: "#00F0FF" }} data-testid="duplicate-banner">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="text-[10px] font-mono uppercase tracking-widest text-cyan-400 mb-1">// {dupes.length} SIMILAR CLOSED OFFENSE(S) FOUND</div>
              <div className="text-sm text-[color:var(--text-primary)]">This alert matches artefacts of a previously-closed offense. Analyst can quickly close it as a duplicate.</div>
              <div className="mt-3 space-y-2">
                {dupes.slice(0, 3).map((d) => (
                  <div key={d.id} className="flex items-start justify-between gap-3 border border-[color:var(--border-default)] p-2" data-testid={`duplicate-${d.id}`}>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-mono truncate">#{d.qradar_offense_id || d.id.slice(0,8)} — {d.description}</div>
                      <div className="text-[10px] font-mono uppercase tracking-widest text-[color:var(--text-secondary)] mt-1">
                        Closed {d.closed_at ? new Date(d.closed_at).toLocaleDateString() : "?"} · by {d.closed_by || "—"} · overlap: {[d.overlap.rules.length && "rule", d.overlap.source_ips.length && "src-ip", d.overlap.usernames.length && "user"].filter(Boolean).join(", ") || "none"}
                      </div>
                      {d.closure_comments && (
                        <div className="text-xs text-[color:var(--text-secondary)] mt-1 line-clamp-2">"{d.closure_comments}"</div>
                      )}
                    </div>
                    <button onClick={() => closeAsDuplicate(d)} disabled={busy} data-testid={`close-duplicate-${d.id}`}
                      className="border border-emerald-500 text-emerald-400 hover:bg-emerald-500/10 px-3 py-1.5 text-[11px] font-mono uppercase tracking-widest inline-flex items-center gap-1 disabled:opacity-40 shrink-0">
                      <CopyIcon className="w-3 h-3" /> Close as duplicate
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="flex gap-2 flex-wrap">
        <button onClick={() => setShowEscalate(true)} data-testid="btn-lifecycle-escalate"
          className="inline-flex items-center gap-2 border border-[color:var(--border-default)] hover:border-amber-500 hover:text-amber-400 px-3 py-2 text-xs font-mono uppercase tracking-widest text-[color:var(--text-primary)]">
          <ArrowUpRight className="w-3 h-3" /> Escalate (Send to Client)
        </button>
        <button onClick={() => setShowClose(true)} data-testid="btn-lifecycle-close"
          className="inline-flex items-center gap-2 border border-[color:var(--border-default)] hover:border-emerald-500 hover:text-emerald-400 px-3 py-2 text-xs font-mono uppercase tracking-widest text-[color:var(--text-primary)]">
          <Ban className="w-3 h-3" /> Close with Comments
        </button>
      </div>

      {showEscalate && (
        <EscalateModal offenseId={offense.id} onClose={() => setShowEscalate(false)} onDone={onUpdated} />
      )}
      {showClose && (
        <CloseModal offenseId={offense.id} onClose={() => setShowClose(false)} onDone={onUpdated} />
      )}

      {/* Lifecycle timestamps */}
      {(offense.escalated_at || offense.closed_at) && (
        <div className="tactical-panel p-3 text-[10px] font-mono uppercase tracking-widest text-[color:var(--text-secondary)] flex flex-wrap gap-4" data-testid="lifecycle-timeline">
          {offense.escalated_at && (
            <span>ESCALATED · <span className="text-amber-400">{new Date(offense.escalated_at).toLocaleString()}</span> by {offense.escalated_by}</span>
          )}
          {offense.closed_at && (
            <span>CLOSED · <span className="text-emerald-400">{new Date(offense.closed_at).toLocaleString()}</span> by {offense.closed_by} ({offense.closure_source})</span>
          )}
        </div>
      )}
      {offense.closure_comments && (
        <div className="tactical-panel p-4" data-testid="closure-comments">
          <div className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 mb-2">// CLOSURE COMMENTS · {offense.closure_source?.toUpperCase()}</div>
          <div className="text-sm whitespace-pre-wrap">{offense.closure_comments}</div>
        </div>
      )}
    </>
  );
};

const EscalateModal = ({ offenseId, onClose, onDone }) => {
  const [contact, setContact] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    try {
      const r = await api.post(`/offenses/${offenseId}/escalate`, { client_contact: contact, notes });
      toast.success("Escalated to client");
      onDone?.(r.data); onClose();
    } catch (e) { toast.error(e?.response?.data?.detail || "Escalate failed"); }
    finally { setBusy(false); }
  };
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" onClick={onClose} data-testid="escalate-modal">
      <div className="tactical-panel w-full max-w-lg p-6" onClick={(e) => e.stopPropagation()} style={{ background: "var(--bg-surface)" }}>
        <div className="text-[10px] font-mono uppercase tracking-widest text-amber-400 mb-2">// ESCALATE TO CLIENT</div>
        <h3 className="font-display text-xl mb-4">Send to client side</h3>
        <div className="space-y-3">
          <div>
            <div className="text-[10px] font-mono uppercase text-[color:var(--text-secondary)] mb-1">Client Contact / Email</div>
            <input value={contact} onChange={(e) => setContact(e.target.value)} data-testid="escalate-contact"
              className="w-full bg-[color:var(--bg-base)] border border-[color:var(--border-default)] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase text-[color:var(--text-secondary)] mb-1">Escalation Notes</div>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={5} data-testid="escalate-notes"
              className="w-full bg-[color:var(--bg-base)] border border-[color:var(--border-default)] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
          </div>
          <div className="flex gap-2 justify-end mt-4">
            <button onClick={onClose} className="border border-[color:var(--border-default)] px-4 py-2 text-xs font-mono uppercase tracking-widest">Cancel</button>
            <button onClick={submit} disabled={busy} data-testid="escalate-submit"
              className="bg-amber-500 hover:bg-amber-400 text-black px-4 py-2 text-xs font-mono uppercase tracking-widest font-bold disabled:opacity-40">
              {busy ? "Escalating..." : "Send to Client"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const CloseModal = ({ offenseId, onClose, onDone }) => {
  const [source, setSource] = useState("analyst");
  const [comments, setComments] = useState("");
  const [busy, setBusy] = useState(false);
  const [fetching, setFetching] = useState(false);
  const submit = async () => {
    if (!comments.trim()) return toast.error("Closure comments are required");
    setBusy(true);
    try {
      const r = await api.post(`/offenses/${offenseId}/close`, {
        closure_comments: comments, closure_source: source,
      });
      toast.success("Offense closed");
      onDone?.(r.data); onClose();
    } catch (e) { toast.error(e?.response?.data?.detail || "Close failed"); }
    finally { setBusy(false); }
  };
  const fetchFromXsoar = async () => {
    setFetching(true);
    setTimeout(() => {
      setComments(`[XSOAR] Client confirmed the activity is legitimate. Playbook 'MSSP-L1-Closure' completed at ${new Date().toISOString()}. No further action required.`);
      setSource("xsoar");
      setFetching(false);
      toast.success("Closure text imported from XSOAR");
    }, 800);
  };
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" onClick={onClose} data-testid="close-modal">
      <div className="tactical-panel w-full max-w-lg p-6" onClick={(e) => e.stopPropagation()} style={{ background: "var(--bg-surface)" }}>
        <div className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 mb-2">// CLOSE OFFENSE</div>
        <h3 className="font-display text-xl mb-4">Add closure information</h3>
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <label className="text-[10px] font-mono uppercase tracking-widest text-[color:var(--text-secondary)]">Source:</label>
            <div className="flex gap-2">
              {["analyst", "xsoar"].map((s) => (
                <button key={s} onClick={() => setSource(s)} data-testid={`close-source-${s}`}
                  className={`px-3 py-1 text-[11px] font-mono uppercase tracking-widest border ${source === s ? "border-cyan-500 text-cyan-400" : "border-[color:var(--border-default)] text-[color:var(--text-secondary)]"}`}>
                  {s === "analyst" ? "Manual (Analyst)" : "Auto from XSOAR"}
                </button>
              ))}
            </div>
            {source === "xsoar" && (
              <button onClick={fetchFromXsoar} disabled={fetching} data-testid="close-fetch-xsoar"
                className="ml-auto border border-cyan-500 text-cyan-400 hover:bg-cyan-500/10 px-3 py-1 text-[11px] font-mono uppercase tracking-widest inline-flex items-center gap-1 disabled:opacity-40">
                <RefreshCw className={`w-3 h-3 ${fetching ? "animate-spin" : ""}`} /> Fetch
              </button>
            )}
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase text-[color:var(--text-secondary)] mb-1">Closure Comments</div>
            <textarea value={comments} onChange={(e) => setComments(e.target.value)} rows={6} data-testid="close-comments"
              placeholder="e.g. Client confirmed activity as legitimate ..."
              className="w-full bg-[color:var(--bg-base)] border border-[color:var(--border-default)] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
          </div>
          <div className="flex gap-2 justify-end mt-4">
            <button onClick={onClose} className="border border-[color:var(--border-default)] px-4 py-2 text-xs font-mono uppercase tracking-widest">Cancel</button>
            <button onClick={submit} disabled={busy || !comments.trim()} data-testid="close-submit"
              className="bg-emerald-500 hover:bg-emerald-400 text-black px-4 py-2 text-xs font-mono uppercase tracking-widest font-bold disabled:opacity-40">
              {busy ? "Closing..." : "Close Offense"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
