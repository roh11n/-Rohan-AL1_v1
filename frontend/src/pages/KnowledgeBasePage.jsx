import { useEffect, useState } from "react";
import api from "@/lib/api";
import { useClients } from "@/lib/clients";
import { toast } from "sonner";
import { Upload, Trash2, FileText, Database, Search, RefreshCw } from "lucide-react";

const KB_TYPES = [
  { value: "network_hierarchy", label: "Network Hierarchy" },
  { value: "use_case", label: "Use Cases / Detection Rules" },
  { value: "historical_incident", label: "Historical Incidents" },
  { value: "asset", label: "Assets / CMDB" },
  { value: "playbook", label: "Playbooks" },
];

export default function KnowledgeBasePage() {
  const { activeClientId, clients } = useClients();
  const [entries, setEntries] = useState([]);
  const [kbStatus, setKbStatus] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [kbType, setKbType] = useState("network_hierarchy");
  const [file, setFile] = useState(null);
  const [searchQ, setSearchQ] = useState("");
  const [searching, setSearching] = useState(false);
  const [searchResults, setSearchResults] = useState(null);

  const load = async () => {
    if (!activeClientId) return;
    const [r, s] = await Promise.all([
      api.get(`/kb?client_id=${activeClientId}`),
      api.get("/kb/status"),
    ]);
    setEntries(r.data || []);
    setKbStatus(s.data);
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [activeClientId]);

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
      fd.append("client_id", activeClientId);
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

  const runSearch = async (e) => {
    e?.preventDefault();
    if (!searchQ.trim()) return;
    setSearching(true);
    try {
      const r = await api.post("/kb/search", {
        client_id: activeClientId, query: searchQ, n_results: 8,
      });
      setSearchResults(r.data);
    } catch (e) { toast.error(e?.response?.data?.detail || "Search failed"); }
    finally { setSearching(false); }
  };

  const client = clients.find((c) => c.id === activeClientId);

  return (
    <div className="space-y-5" data-testid="kb-page">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// TENANT KNOWLEDGE</div>
        <h1 className="font-display text-3xl mt-1">Knowledge Base</h1>
        <p className="text-neutral-400 text-sm mt-1">
          Per-tenant RAG corpus for <span className="text-cyan-400 font-mono">{client?.name}</span>. Uploaded documents are chunked and embedded for retrieval during AI investigation.
        </p>
      </div>

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
                  <td className="px-3 py-2 text-cyan-400 text-xs uppercase">{e.kb_type}</td>
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
