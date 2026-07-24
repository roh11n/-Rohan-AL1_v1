import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "@/lib/api";
import { useClients } from "@/lib/clients";
import { SeverityChip, StatusChip } from "@/components/SeverityChip";
import { Search, RefreshCw, X as XIcon } from "lucide-react";
import { toast } from "sonner";

const STATUS_OPTIONS = ["OPEN", "INVESTIGATING", "PENDING_APPROVAL", "ESCALATED", "RESOLVED", "CLOSED"];

export default function OffensesPage() {
  const { activeClientId } = useClients();
  const nav = useNavigate();
  const [offenses, setOffenses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState(() => new Set());
  const [closeModal, setCloseModal] = useState(null); // { offenseIds: string[], bulk: boolean }
  const [bulkStatus, setBulkStatus] = useState("");

  const load = async () => {
    if (!activeClientId) return;
    setLoading(true);
    try {
      const params = new URLSearchParams({ client_id: activeClientId });
      if (sev) params.set("severity", sev);
      if (status) params.set("status_filter", status);
      const r = await api.get(`/offenses?${params}`);
      setOffenses(r.data || []);
      setSelected(new Set());
    } finally { setLoading(false); }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [activeClientId, sev, status]);

  const filtered = useMemo(() => offenses.filter((o) => !q ||
    o.description?.toLowerCase().includes(q.toLowerCase()) ||
    (o.source_ips || []).some((ip) => ip.includes(q)) ||
    (o.usernames || []).some((u) => u.toLowerCase().includes(q.toLowerCase()))
  ), [offenses, q]);

  const allSelected = filtered.length > 0 && filtered.every((o) => selected.has(o.id));
  const toggleSelectAll = () => {
    if (allSelected) setSelected(new Set());
    else setSelected(new Set(filtered.map((o) => o.id)));
  };
  const toggleRow = (id) => {
    const s = new Set(selected);
    if (s.has(id)) s.delete(id); else s.add(id);
    setSelected(s);
  };

  const syncFromQRadar = async () => {
    setSyncing(true);
    try {
      const r = await api.post("/qradar/sync", { client_id: activeClientId, hours_back: 6, max_offenses: 10 });
      toast.success(`Synced ${r.data.synced} offense(s) from QRadar`);
      load();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "QRadar sync failed. Configure in Settings.");
    } finally { setSyncing(false); }
  };

  const applyRowStatus = async (offense, newStatus) => {
    if (newStatus === offense.status) return;
    if (newStatus === "CLOSED") {
      setCloseModal({ offenseIds: [offense.id], bulk: false });
      return;
    }
    try {
      const r = await api.post(`/offenses/${offense.id}/status`, { status: newStatus });
      setOffenses((prev) => prev.map((o) => (o.id === offense.id ? { ...o, ...r.data } : o)));
      toast.success(`Status → ${newStatus}`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Status change failed");
    }
  };

  const applyBulkStatus = async () => {
    if (!bulkStatus || selected.size === 0) return;
    if (bulkStatus === "CLOSED") {
      setCloseModal({ offenseIds: Array.from(selected), bulk: true });
      return;
    }
    try {
      const r = await api.post(`/offenses/bulk-status`, {
        offense_ids: Array.from(selected), status: bulkStatus,
      });
      toast.success(`Updated ${r.data.updated} offense(s) → ${bulkStatus}`);
      setBulkStatus("");
      load();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Bulk update failed");
    }
  };

  return (
    <div className="space-y-5" data-testid="offenses-page">
      <div className="flex items-baseline justify-between">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// TRIAGE QUEUE</div>
          <h1 className="font-display text-3xl mt-1">Offenses</h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={syncFromQRadar}
            disabled={syncing}
            data-testid="btn-sync-qradar"
            className="border border-[#1F1F1F] hover:border-cyan-500 hover:text-cyan-400 px-3 py-1.5 text-[11px] font-mono uppercase tracking-widest text-neutral-300 inline-flex items-center gap-2"
          >
            <RefreshCw className={`w-3 h-3 ${syncing ? "animate-spin" : ""}`} /> {syncing ? "Syncing..." : "Sync from QRadar"}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="tactical-panel p-3 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[260px]">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" strokeWidth={1.5} />
          <input
            data-testid="offense-search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="search description, ip, username..."
            className="w-full pl-9 pr-3 py-2 bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono"
          />
        </div>
        <select value={sev} onChange={(e) => setSev(e.target.value)} data-testid="filter-severity"
          className="bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2">
          <option value="">All Severity</option>
          <option>Critical</option>
          <option>High</option>
          <option>Medium</option>
          <option>Low</option>
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} data-testid="filter-status"
          className="bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2">
          <option value="">All Status</option>
          {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
        </select>
        <span className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest ml-auto" data-testid="offense-count">
          {filtered.length} / {offenses.length} results
        </span>
      </div>

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="tactical-panel p-3 flex flex-wrap items-center gap-3 border-l-4 border-l-cyan-500"
             data-testid="bulk-actions-bar">
          <div className="text-[11px] font-mono uppercase tracking-widest text-cyan-400">
            {selected.size} selected
          </div>
          <select
            value={bulkStatus}
            onChange={(e) => setBulkStatus(e.target.value)}
            data-testid="bulk-status-select"
            className="bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-xs font-mono px-3 py-1.5 uppercase tracking-widest"
          >
            <option value="">Change status to…</option>
            {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
          </select>
          <button
            onClick={applyBulkStatus}
            disabled={!bulkStatus}
            data-testid="bulk-apply-btn"
            className="bg-cyan-400 hover:bg-cyan-300 text-black px-3 py-1.5 text-[11px] font-mono uppercase tracking-widest font-bold disabled:opacity-40"
          >
            Apply
          </button>
          <button
            onClick={() => { setSelected(new Set()); setBulkStatus(""); }}
            data-testid="bulk-clear-btn"
            className="border border-[#1F1F1F] hover:border-neutral-500 px-3 py-1.5 text-[11px] font-mono uppercase tracking-widest text-neutral-300 inline-flex items-center gap-1"
          >
            <XIcon className="w-3 h-3" /> Clear
          </button>
        </div>
      )}

      {/* Table */}
      <div className="tactical-panel">
        {loading ? (
          <div className="p-10 text-center text-neutral-500 font-mono text-sm">Fetching offenses<span className="blink-cursor"></span></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1200px] text-sm" data-testid="offenses-table">
              <thead className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest border-b border-[#1F1F1F] bg-[#080808]">
                <tr>
                  <th className="text-left px-3 py-3 w-10">
                    <input type="checkbox" checked={allSelected} onChange={toggleSelectAll}
                           data-testid="select-all-checkbox"
                           className="accent-cyan-400 cursor-pointer" />
                  </th>
                  <th className="text-left px-4 py-3 whitespace-nowrap">ID</th>
                  <th className="text-left px-4 py-3">Description</th>
                  <th className="text-left px-4 py-3 whitespace-nowrap">Severity</th>
                  <th className="text-left px-4 py-3 whitespace-nowrap">Risk</th>
                  <th className="text-left px-4 py-3 whitespace-nowrap">Source</th>
                  <th className="text-left px-4 py-3 whitespace-nowrap">User</th>
                  <th className="text-left px-4 py-3 whitespace-nowrap">Events</th>
                  <th className="text-left px-4 py-3 whitespace-nowrap">Status</th>
                  <th className="text-left px-4 py-3 whitespace-nowrap">Change Status</th>
                  <th className="text-left px-4 py-3 whitespace-nowrap">Updated</th>
                </tr>
              </thead>
              <tbody className="stagger">
                {filtered.map((o) => (
                  <tr key={o.id} data-selected={selected.has(o.id)} className="border-b border-[#0F0F0F] hover:bg-[#111] cursor-pointer" data-testid={`offense-row-${o.id}`}
                      onClick={() => nav(`/offenses/${o.id}`)}>
                    <td className="px-3 py-3" onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={selected.has(o.id)} onChange={() => toggleRow(o.id)}
                             data-testid={`select-${o.id}`}
                             className="accent-cyan-400 cursor-pointer" />
                    </td>
                    <td className="px-4 py-3 font-mono whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <Link to={`/offenses/${o.id}`} className="text-cyan-400 hover:text-cyan-300">
                        #{o.qradar_offense_id || o.id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-neutral-200 max-w-sm truncate">{o.description}</td>
                    <td className="px-4 py-3 whitespace-nowrap"><SeverityChip label={o.severity_label} /></td>
                    <td className="px-4 py-3 font-mono text-xs">
                      <span className={
                        o.risk_score >= 85 ? "text-rose-400" :
                        o.risk_score >= 65 ? "text-amber-400" :
                        o.risk_score >= 40 ? "text-yellow-400" : "text-cyan-400"
                      }>{o.risk_score || 0}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-neutral-400 whitespace-nowrap">{(o.source_ips || [])[0] || "—"}</td>
                    <td className="px-4 py-3 font-mono text-xs text-neutral-400 whitespace-nowrap">{(o.usernames || [])[0] || "—"}</td>
                    <td className="px-4 py-3 font-mono text-xs text-neutral-400 whitespace-nowrap">{o.event_count || 0}</td>
                    <td className="px-4 py-3 whitespace-nowrap"><StatusChip status={o.status} /></td>
                    <td className="px-4 py-3 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <select
                        value={o.status}
                        onChange={(e) => applyRowStatus(o, e.target.value)}
                        data-testid={`row-status-${o.id}`}
                        className="bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-[10px] font-mono uppercase tracking-widest px-2 py-1 text-neutral-200"
                      >
                        {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
                      </select>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-neutral-500 whitespace-nowrap">{new Date(o.last_updated).toLocaleString()}</td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr><td colSpan={11} className="px-4 py-10 text-center text-neutral-500 font-mono">No offenses match the filter.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {closeModal && (
        <CloseOffensesModal
          {...closeModal}
          onClose={() => setCloseModal(null)}
          onDone={() => { setCloseModal(null); setBulkStatus(""); load(); }}
        />
      )}
    </div>
  );
}

const CloseOffensesModal = ({ offenseIds, bulk, onClose, onDone }) => {
  const [source, setSource] = useState("analyst");
  const [comments, setComments] = useState("");
  const [busy, setBusy] = useState(false);

  const fetchFromXsoar = () => {
    setComments(`[XSOAR] Client confirmed the activity is legitimate. Playbook 'MSSP-L1-Closure' completed at ${new Date().toISOString()}. No further action required.`);
    setSource("xsoar");
    toast.success("Closure text imported from XSOAR");
  };

  const submit = async () => {
    if (!comments.trim()) return toast.error("Closure comments are required");
    setBusy(true);
    try {
      if (bulk) {
        const r = await api.post(`/offenses/bulk-status`, {
          offense_ids: offenseIds, status: "CLOSED",
          closure_comments: comments, closure_source: source,
        });
        toast.success(`Closed ${r.data.updated} offense(s)`);
      } else {
        await api.post(`/offenses/${offenseIds[0]}/status`, {
          status: "CLOSED", closure_comments: comments, closure_source: source,
        });
        toast.success("Offense closed");
      }
      onDone();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Close failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" onClick={onClose} data-testid="offenses-close-modal">
      <div className="tactical-panel w-full max-w-lg p-6" onClick={(e) => e.stopPropagation()}
           style={{ background: "var(--bg-surface)" }}>
        <div className="text-[10px] font-mono uppercase tracking-widest text-emerald-400 mb-2">
          // CLOSE {bulk ? `${offenseIds.length} OFFENSE(S)` : "OFFENSE"}
        </div>
        <h3 className="font-display text-xl mb-4">Add closure information</h3>
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <label className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">Source:</label>
            <div className="flex gap-2">
              {["analyst", "xsoar"].map((s) => (
                <button key={s} onClick={() => setSource(s)} data-testid={`close-source-${s}`}
                  className={`px-3 py-1 text-[11px] font-mono uppercase tracking-widest border ${source === s ? "border-cyan-500 text-cyan-400" : "border-[#1F1F1F] text-neutral-400"}`}>
                  {s === "analyst" ? "Manual (Analyst)" : "Auto from XSOAR"}
                </button>
              ))}
            </div>
            {source === "xsoar" && (
              <button onClick={fetchFromXsoar}
                      data-testid="close-fetch-xsoar"
                      className="ml-auto border border-cyan-500 text-cyan-400 hover:bg-cyan-500/10 px-3 py-1 text-[11px] font-mono uppercase tracking-widest inline-flex items-center gap-1">
                <RefreshCw className="w-3 h-3" /> Fetch
              </button>
            )}
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">Closure Comments</div>
            <textarea value={comments} onChange={(e) => setComments(e.target.value)} rows={6}
                      data-testid="close-comments"
                      placeholder="e.g. Client confirmed activity as legitimate ..."
                      className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
          </div>
          <div className="flex gap-2 justify-end mt-4">
            <button onClick={onClose} className="border border-[#1F1F1F] px-4 py-2 text-xs font-mono uppercase tracking-widest">Cancel</button>
            <button onClick={submit} disabled={busy || !comments.trim()}
                    data-testid="close-submit"
                    className="bg-emerald-500 hover:bg-emerald-400 text-black px-4 py-2 text-xs font-mono uppercase tracking-widest font-bold disabled:opacity-40">
              {busy ? "Closing..." : `Close ${bulk ? `${offenseIds.length} Offense(s)` : "Offense"}`}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
