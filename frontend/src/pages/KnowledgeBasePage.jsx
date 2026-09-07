import { useEffect, useState } from "react";
import api from "@/lib/api";
import { useClients } from "@/lib/clients";
import { toast } from "sonner";
import { Upload, Trash2, FileText, Database, Search, RefreshCw, PlusCircle, PenLine } from "lucide-react";

const KB_TYPES = [
  { value: "network_hierarchy", label: "Network Hierarchy" },
  { value: "use_case", label: "Use Cases / Detection Rules" },
  { value: "historical_incident", label: "Historical Incidents" },
  { value: "asset", label: "Assets / CMDB" },
  { value: "playbook", label: "Playbooks" },
];

const ALL_SCOPE = "ALL";

export default function KnowledgeBasePage() {
  const { activeClientId, clients } = useClients();
  const [scope, setScope] = useState(activeClientId || "");
  const [entries, setEntries] = useState([]);
  const [kbStatus, setKbStatus] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [kbType, setKbType] = useState("network_hierarchy");
  const [file, setFile] = useState(null);
  const [searchQ, setSearchQ] = useState("");
  const [searching, setSearching] = useState(false);
  const [searchResults, setSearchResults] = useState(null);
  // Manual "add historical data" form
  const [manual, setManual] = useState({ alert_name: "", analysis: "", verdict: "", recommendations: "" });
  const [savingManual, setSavingManual] = useState(false);

  // Keep scope in sync when the global active client first resolves.
  useEffect(() => { if (!scope && activeClientId) setScope(activeClientId); /* eslint-disable-next-line */ }, [activeClientId]);

  const load = async () => {
    if (!scope) return;
    const [r, s] = await Promise.all([
      api.get(`/kb?client_id=${scope}`),
      api.get("/kb/status"),
    ]);
    setEntries(r.data || []);
    setKbStatus(s.data);
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [scope]);

  // Auto-poll while any entry is still PROCESSING
  useEffect(() => {
    const anyProcessing = entries.some((e) => e.status === "PROCESSING");
    if (!anyProcessing) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
    /* eslint-disable-next-line */
  }, [entries]);

  const upload = async (e) => {
    e.preventDefault();
    if (!file) return toast.error("Select a file");
    setUploading(true);
    try {
      const fd = new FormData();
      fd.append("client_id", scope);
      fd.append("kb_type", kbType);
      fd.append("file", file);
      await api.post("/kb/upload", fd, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 60000,
      });
      toast.success("Upload accepted — ingestion running in background");
      setFile(null);
      load();
    } catch (e) {
      const msg = e?.response?.data?.detail || e?.message || "Upload failed";
      toast.error(msg);
    }
    finally { setUploading(false); }
  };

  const del = async (id) => {
    if (!window.confirm("Delete this KB entry?")) return;
    await api.delete(`/kb/${id}`);
    toast.success("Deleted");
    load();
  };

  const retry = async (id) => {
    if (!window.confirm("Clear this row so you can re-upload the file?")) return;
    try {
      await api.post(`/kb/${id}/retry`);
      toast.success("Row cleared. Please upload the file again.");
      load();
    } catch (e) { toast.error(e?.response?.data?.detail || "Retry failed"); }
  };

  const addManual = async (e) => {
    e.preventDefault();
    if (!manual.alert_name.trim() || !manual.analysis.trim())
      return toast.error("Alert name and analysis are required");
    setSavingManual(true);
    try {
      await api.post("/kb/manual", {
        client_id: scope,
        alert_name: manual.alert_name.trim(),
        analysis: manual.analysis.trim(),
        verdict: manual.verdict || null,
        recommendations: manual.recommendations.split("\n").map((s) => s.trim()).filter(Boolean),
        kb_type: "historical_incident",
      });
      toast.success("Historical KB entry added");
      setManual({ alert_name: "", analysis: "", verdict: "", recommendations: "" });
      load();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Failed to add entry");
    } finally { setSavingManual(false); }
  };

  const runSearch = async (e) => {
    e?.preventDefault();
    if (!searchQ.trim()) return;
    setSearching(true);
    try {
      const r = await api.post("/kb/search", {
        client_id: scope, query: searchQ, n_results: 8,
      });
      setSearchResults(r.data);
    } catch (e) { toast.error(e?.response?.data?.detail || "Search failed"); }
    finally { setSearching(false); }
  };

  const scopeOptions = [...clients.map((c) => ({ id: c.id, name: c.name })), { id: ALL_SCOPE, name: "All Tenants (global)" }];
  const scopeLabel = scope === ALL_SCOPE ? "All Tenants" : (clients.find((c) => c.id === scope)?.name || "—");

  return (
    <div className="space-y-5" data-testid="kb-page">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// TENANT KNOWLEDGE</div>
          <h1 className="font-display text-3xl mt-1">Knowledge Base</h1>
          <p className="text-neutral-400 text-sm mt-1">
            RAG corpus for <span className="text-cyan-400 font-mono">{scopeLabel}</span>. Documents & manual entries are embedded for retrieval during AI investigation.
          </p>
        </div>
        <div data-testid="kb-scope">
          <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">KB Scope</div>
          <select value={scope} onChange={(e) => setScope(e.target.value)} data-testid="kb-scope-select"
            className="bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2 min-w-[220px]">
            {scopeOptions.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
          </select>
        </div>
      </div>

      {/* Add historical data manually */}
      <form onSubmit={addManual} className="tactical-panel p-5 space-y-3" data-testid="kb-manual-form">
        <div className="flex items-center gap-2">
          <PenLine className="w-4 h-4 text-cyan-400" strokeWidth={1.5} />
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// ADD HISTORICAL DATA (MANUAL)</div>
        </div>
        <p className="text-[11px] text-neutral-500 -mt-1">
          Record a known alert's analysis once. When a future offense has the same alert name, the AI reuses this analysis as a template (swapping in the new offense's artifacts).
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">Alert / Rule Name *</div>
            <input value={manual.alert_name} onChange={(e) => setManual({ ...manual, alert_name: e.target.value })} data-testid="kb-manual-name"
              placeholder="e.g. Multiple Login Failures for Single Username"
              className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">Verdict (optional)</div>
            <select value={manual.verdict} onChange={(e) => setManual({ ...manual, verdict: e.target.value })} data-testid="kb-manual-verdict"
              className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2">
              <option value="">— none —</option>
              <option value="TP">TP (True Positive)</option>
              <option value="FP">FP (False Positive)</option>
              <option value="Suspicious">Suspicious</option>
            </select>
          </div>
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">Analysis *</div>
          <textarea rows={4} value={manual.analysis} onChange={(e) => setManual({ ...manual, analysis: e.target.value })} data-testid="kb-manual-analysis"
            placeholder="Describe the investigation & conclusion. Tip: use {source_ip}, {username}, {destination_ip}, {offense_id}, {date_time} — they get replaced with the new offense's values."
            className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">Recommendations (one per line, optional)</div>
          <textarea rows={2} value={manual.recommendations} onChange={(e) => setManual({ ...manual, recommendations: e.target.value })} data-testid="kb-manual-recs"
            placeholder={"Confirm activity with {username}\nTune the detection rule if benign"}
            className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
        </div>
        <button type="submit" disabled={savingManual} data-testid="kb-manual-submit"
          className="bg-cyan-400 hover:bg-cyan-300 text-black px-4 py-2 text-xs font-mono uppercase tracking-widest font-bold inline-flex items-center gap-2 disabled:opacity-50">
          <PlusCircle className="w-3.5 h-3.5" />{savingManual ? "Saving..." : "Add to Knowledge Base"}
        </button>
      </form>

      {/* Search preview - available to any authenticated analyst or admin */}
      <div className="tactical-panel p-4" data-testid="kb-search-preview">
        <div className="flex items-baseline justify-between mb-3">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// RETRIEVAL PREVIEW</div>
            <h3 className="font-display text-lg">Query Vector Store</h3>
          </div>
          <div className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest">Preview what the AI will retrieve during an investigation.</div>
        </div>
        <form onSubmit={runSearch} className="flex gap-2 mb-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" strokeWidth={1.5} />
            <input value={searchQ} onChange={(e) => setSearchQ(e.target.value)} data-testid="kb-search-input"
              placeholder="e.g. login failure expired password, ransomware lockbit, ..."
              className="w-full pl-9 pr-3 py-2 bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono" />
          </div>
          <button type="submit" disabled={searching || !searchQ.trim()} data-testid="kb-search-btn"
            className="bg-cyan-400 hover:bg-cyan-300 text-black px-4 py-2 text-xs font-mono uppercase tracking-widest font-bold disabled:opacity-40 inline-flex items-center gap-2">
            {searching ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            {searching ? "Searching..." : "Search"}
          </button>
        </form>
        {searchResults && (
          <div className="space-y-2" data-testid="kb-search-results">
            <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">
              {searchResults.count} passages · query: <span className="text-cyan-400 normal-case">"{searchResults.query}"</span>
            </div>
            {searchResults.matches.length === 0 && (
              <div className="text-sm text-neutral-500 font-mono py-4">No passages found. Upload documents first, then re-search.</div>
            )}
            {searchResults.matches.map((m, i) => (
              <div key={i} className="border border-[#1F1F1F] p-3" data-testid={`kb-search-result-${i}`}>
                <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-widest text-neutral-500 mb-2">
                  <span>{m.kb_type} · {m.source}</span>
                  <span>Similarity <span className="text-cyan-400">{(m.similarity * 100).toFixed(1)}%</span></span>
                </div>
                <div className="text-sm text-neutral-200 leading-relaxed font-mono break-words">{m.text}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <form onSubmit={upload} className="tactical-panel p-5 space-y-4 lg:col-span-1" data-testid="kb-upload-form">
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// UPLOAD</div>
          <div>
            <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">KB Type</div>
            <select value={kbType} onChange={(e) => setKbType(e.target.value)} data-testid="kb-type-select"
              className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2">
              {KB_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">File (CSV / XLSX / JSON / PDF / DOCX / MD)</div>
            <input type="file" onChange={(e) => setFile(e.target.files[0])} data-testid="kb-file-input"
              accept=".csv,.xlsx,.xls,.json,.pdf,.docx,.md,.txt"
              className="w-full bg-[#050505] border border-[#1F1F1F] text-sm font-mono px-3 py-2 file:bg-cyan-400 file:text-black file:border-0 file:font-mono file:uppercase file:text-[10px] file:px-3 file:py-1 file:mr-3" />
          </div>
          <button type="submit" disabled={uploading} data-testid="kb-upload-btn"
            className="w-full bg-cyan-400 hover:bg-cyan-300 text-black py-2 text-xs font-mono uppercase tracking-widest font-bold inline-flex items-center justify-center gap-2 disabled:opacity-50">
            <Upload className="w-3.5 h-3.5" />{uploading ? "Uploading..." : "Ingest to Vector Store"}
          </button>
          {kbStatus && (
            <div className="border-t border-[#1F1F1F] pt-3 text-[10px] font-mono uppercase tracking-widest text-neutral-500">
              <div className="flex items-center gap-2">
                <Database className="w-3 h-3" /> RAG Status:
                <span className={kbStatus.ready ? "text-emerald-400" : "text-amber-400"}>
                  {kbStatus.ready ? "READY" : "IDLE (will init on first use)"}
                </span>
              </div>
              {kbStatus.error && <div className="text-rose-400 mt-1 normal-case tracking-normal">{kbStatus.error}</div>}
            </div>
          )}
        </form>

        <div className="tactical-panel overflow-hidden lg:col-span-2">
          <div className="p-3 border-b border-[#1F1F1F] text-[10px] font-mono uppercase tracking-widest text-neutral-500">// KB ENTRIES · {entries.length}</div>
          <table className="w-full text-sm">
            <thead className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest border-b border-[#1F1F1F] bg-[#080808]">
              <tr>
                <th className="text-left px-3 py-2">Type</th>
                <th className="text-left px-3 py-2">Filename</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="text-left px-3 py-2">Chunks</th>
                <th className="text-left px-3 py-2">Uploaded</th>
                <th className="text-left px-3 py-2">By</th>
                <th className="text-right px-3 py-2">Actions</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {entries.map((e) => {
                const statusStyles = {
                  PROCESSING: "border-amber-500 text-amber-400 bg-amber-500/10",
                  READY: "border-emerald-500 text-emerald-400 bg-emerald-500/10",
                  FAILED: "border-rose-500 text-rose-400 bg-rose-500/10",
                }[e.status || "READY"] || "border-neutral-600 text-neutral-400";
                return (
                <tr key={e.id} className="border-b border-[#0F0F0F] hover:bg-[#111]" data-testid={`kb-row-${e.id}`}>
                  <td className="px-3 py-2 text-cyan-400 text-xs uppercase">
                    {e.kb_type}
                    {e.entry_kind === "manual" && (
                      <span className="ml-2 inline-block px-1.5 py-0.5 text-[9px] border border-cyan-500/40 text-cyan-300 tracking-widest">MANUAL{e.verdict ? ` · ${e.verdict}` : ""}</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-neutral-100 inline-flex items-center gap-2"><FileText className="w-3 h-3 text-neutral-500" />{e.filename}</td>
                  <td className="px-3 py-2">
                    <span data-testid={`kb-status-${e.id}`}
                      className={`inline-flex items-center px-2 py-0.5 text-[10px] uppercase tracking-widest border ${statusStyles}`}>
                      {e.status === "PROCESSING" && <span className="animate-pulse mr-1">●</span>}
                      {e.status || "READY"}
                    </span>
                    {e.status === "FAILED" && e.error && (
                      <div className="text-[10px] text-rose-400 mt-1 normal-case max-w-xs truncate" title={e.error}>{e.error}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-neutral-400 text-xs">{e.document_count}</td>
                  <td className="px-3 py-2 text-neutral-500 text-xs">{new Date(e.uploaded_at).toLocaleString()}</td>
                  <td className="px-3 py-2 text-neutral-500 text-xs">{e.uploaded_by}</td>
                  <td className="px-3 py-2 text-right">
                    {e.status === "FAILED" && (
                      <button onClick={() => retry(e.id)} data-testid={`kb-retry-${e.id}`}
                        className="text-amber-400 hover:text-amber-300 mr-3 text-[10px] font-mono uppercase tracking-widest">
                        Clear & Retry
                      </button>
                    )}
                    <button onClick={() => del(e.id)} data-testid={`kb-del-${e.id}`} className="text-neutral-500 hover:text-rose-400"><Trash2 className="w-3.5 h-3.5" /></button>
                  </td>
                </tr>
              );})}
              {entries.length === 0 && <tr><td colSpan={7} className="px-3 py-10 text-center text-neutral-500">No knowledge documents uploaded yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
