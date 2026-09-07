import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "@/lib/api";
import { SeverityChip, StatusChip } from "@/components/SeverityChip";
import { RiskGauge } from "@/components/RiskGauge";
import { MitreMatrix } from "@/components/MitreMatrix";
import { PayloadViewer } from "@/components/PayloadViewer";
import { MsspReport } from "@/components/MsspReport";
import { LifecycleActions } from "@/components/LifecycleActions";
import { toast } from "sonner";
import { Brain, Check, X, ArrowUpRight, Ban, Ticket as TicketIcon, Loader2, ArrowLeft, Layers } from "lucide-react";

const TABS = [
  "summary", "mssp_report", "timeline", "events", "payload", "artifacts", "mitre", "similar", "kb", "recommendations",
];

export default function OffenseDetailPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const [off, setOff] = useState(null);
  const [tab, setTab] = useState("summary");
  const [loading, setLoading] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [creatingTicket, setCreatingTicket] = useState(false);
  const [highlight, setHighlight] = useState(null);
  const [llmPending, setLlmPending] = useState(false);

  const load = async () => {
    setLoading(true);
    try { const r = await api.get(`/offenses/${id}`); setOff(r.data); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, [id]);

  // Poll while the local LLM is refining the report in the background.
  useEffect(() => {
    const status = off?.ai_analysis?.llm_status;
    setLlmPending(status === "pending");
    if (status !== "pending") return;
    const t = setInterval(async () => {
      try {
        const r = await api.get(`/offenses/${id}`);
        setOff(r.data);
        const s = r.data?.ai_analysis?.llm_status;
        if (s !== "pending") {
          if (s === "done") toast.success("Local LLM finished refining the report");
          else if (s === "failed") toast.message("LLM unavailable — showing KB/rule analysis");
        }
      } catch (e) {}
    }, 5000);
    return () => clearInterval(t);
    /* eslint-disable-next-line */
  }, [off?.ai_analysis?.llm_status, id]);

  const investigate = async () => {
    setInvestigating(true);
    try {
      const r = await api.post(`/offenses/${id}/investigate`, {}, { timeout: 240000 });
      setOff(r.data);
      if (r.data?.ai_analysis?.llm_status === "pending")
        toast.success("Analysis ready — local LLM (Qwen) is refining it in the background…");
      else
        toast.success(`AI investigation complete. Risk: ${r.data.risk_score}/100`);
      setTab("mssp_report");
    } catch (e) { toast.error(e?.response?.data?.detail || "Investigation failed"); }
    finally { setInvestigating(false); }
  };

  const doAction = async (action, extra = {}) => {
    try {
      const r = await api.post(`/offenses/${id}/action`, { action, ...extra });
      setOff(r.data);
      toast.success(`Action '${action}' applied`);
    } catch (e) { toast.error(e?.response?.data?.detail || "Action failed"); }
  };

  const createTicket = async (destination = "internal") => {
    setCreatingTicket(true);
    try {
      const r = await api.post("/tickets", { offense_id: id, destination });
      toast.success("Ticket created and queued for approval");
      nav(`/tickets`);
    } catch (e) { toast.error(e?.response?.data?.detail || "Ticket creation failed"); }
    finally { setCreatingTicket(false); }
  };

  if (loading || !off) {
    return <div className="text-neutral-500 font-mono text-sm">Loading offense<span className="blink-cursor"></span></div>;
  }

  const analysis = off.ai_analysis || {};
  const iocs = off.iocs || {};

  return (
    <div className="space-y-5" data-testid="offense-detail-page">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-4 min-w-0">
          <button onClick={() => nav(-1)} data-testid="btn-back" className="text-neutral-500 hover:text-cyan-400">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div className="min-w-0">
            <div className="flex items-center gap-3 mb-1">
              <span className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">
                OFFENSE #{off.qradar_offense_id || off.id.slice(0, 8)}
              </span>
              <SeverityChip label={off.severity_label} testId="header-severity" />
              <StatusChip status={off.status} testId="header-status" />
            </div>
            <h1 className="font-display text-2xl lg:text-3xl leading-tight">{off.description}</h1>
            <div className="flex flex-wrap gap-4 text-[11px] font-mono uppercase tracking-widest text-neutral-500 mt-2">
              <span>MAGNITUDE <span className="text-neutral-100">{off.magnitude}</span></span>
              <span>CREDIBILITY <span className="text-neutral-100">{off.credibility}</span></span>
              <span>RELEVANCE <span className="text-neutral-100">{off.relevance}</span></span>
              <span>EVENTS <span className="text-neutral-100">{off.event_count}</span></span>
              <span>FLOWS <span className="text-neutral-100">{off.flow_count}</span></span>
              <span>NETWORK <span className="text-neutral-100">{off.network || "—"}</span></span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          <RiskGauge score={off.risk_score || 0} size={140} />
        </div>
      </div>

      {/* Action bar */}
      <div className="tactical-panel p-3 flex flex-wrap gap-2 items-center">
        <button
          onClick={investigate}
          disabled={investigating}
          data-testid="btn-investigate"
          className="bg-cyan-400 hover:bg-cyan-300 text-black px-4 py-2 text-xs font-mono uppercase tracking-widest font-bold inline-flex items-center gap-2 disabled:opacity-50"
        >
          {investigating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Brain className="w-3.5 h-3.5" />}
          {investigating ? "Analyzing..." : off.ai_analysis ? "Re-run AI Analysis" : "Run AI Investigation"}
        </button>
        <div className="flex-1" />
        <ActionBtn testId="btn-approve" onClick={() => doAction("approve")} icon={Check} label="Approve" color="emerald" />
        <ActionBtn testId="btn-reject" onClick={() => doAction("reject")} icon={X} label="Reject" color="rose" />
        <ActionBtn testId="btn-escalate" onClick={() => doAction("escalate")} icon={ArrowUpRight} label="Escalate L3" color="amber" />
        <ActionBtn testId="btn-close" onClick={() => doAction("close", { reason: "Closed by analyst" })} icon={Ban} label="Close" />
        <ActionBtn testId="btn-create-ticket" onClick={() => createTicket("xsoar")} icon={TicketIcon}
          label={creatingTicket ? "Creating..." : "Create Ticket"} color="cyan" disabled={creatingTicket} />
      </div>

      {/* Lifecycle actions - Open / Escalate / Close with comments + duplicate detection */}
      <LifecycleActions offense={off} onUpdated={(next) => setOff(next)} />

      {/* Tabs */}
      <div className="border-b border-[#1F1F1F] flex flex-wrap gap-6 text-[11px] font-mono uppercase tracking-widest">
        {TABS.map((t) => (
          <button
            key={t}
            data-testid={`tab-${t}`}
            onClick={() => setTab(t)}
            className={`pb-3 border-b-2 border-transparent hover:text-cyan-400 ${tab === t ? "tab-active" : "text-neutral-500"}`}
          >
            {t.replace(/_/g, " ")}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="fade-in-up">
        {llmPending && (
          <div className="mb-3 flex items-center gap-2 border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-xs font-mono text-cyan-300" data-testid="llm-pending-banner">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Local LLM (Qwen) is refining this report in the background — showing KB/rule analysis meanwhile. This updates automatically.
          </div>
        )}
        {tab === "summary" && <SummaryTab off={off} analysis={analysis} />}
        {tab === "mssp_report" && <MsspReport report={analysis.mssp_report} testId="offense-mssp-report"
            offenseId={off.id}
            onUpdated={(updatedOffense) => setOff(updatedOffense)}
            onFieldClick={(label, value) => {
              setTab("events");
              setHighlight({ label, value: String(value) });
            }} />}
        {tab === "timeline" && <TimelineTab timeline={analysis.timeline || []} />}
        {tab === "events" && <EventsTab events={off.events || []} highlight={highlight} />}
        {tab === "payload" && <PayloadTab events={off.events || []} decoded={analysis.decoded_payloads || []} />}
        {tab === "artifacts" && <ArtifactsTab off={off} setOff={setOff} />}
        {tab === "mitre" && <MitreMatrix techniques={off.mitre_techniques || []} />}
        {tab === "similar" && <SimilarTab items={off.similar_incidents || []} />}
        {tab === "kb" && <KbTab items={off.kb_matches || []} />}
        {tab === "recommendations" && <RecommendationsTab off={off} analysis={analysis} />}
      </div>
    </div>
  );
}

const ActionBtn = ({ onClick, icon: Icon, label, color, testId, disabled }) => {
  const c = {
    emerald: "hover:border-emerald-500 hover:text-emerald-400",
    rose: "hover:border-rose-500 hover:text-rose-400",
    amber: "hover:border-amber-500 hover:text-amber-400",
    cyan: "hover:border-cyan-500 hover:text-cyan-400",
  }[color] || "hover:border-cyan-500 hover:text-cyan-400";
  return (
    <button data-testid={testId} onClick={onClick} disabled={disabled}
      className={`inline-flex items-center gap-2 border border-[#1F1F1F] px-3 py-2 text-xs font-mono uppercase tracking-widest text-neutral-300 ${c} disabled:opacity-50`}>
      <Icon className="w-3 h-3" /> {label}
    </button>
  );
};

const Kv = ({ k, v }) => (
  <div className="flex justify-between border-b border-[#141414] py-2 text-sm">
    <span className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">{k}</span>
    <span className="font-mono text-neutral-200 text-right">{v || "—"}</span>
  </div>
);

const SummaryTab = ({ off, analysis }) => (
  <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
    <div className="tactical-panel p-5 lg:col-span-2">
      <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// EXECUTIVE SUMMARY</div>
      <p className="mt-3 text-neutral-200 leading-relaxed" data-testid="exec-summary">
        {analysis.executive_summary || <span className="text-neutral-500">Run AI investigation to generate summary.</span>}
      </p>
      {analysis.business_impact && (
        <div className="mt-4 border-l-2 border-cyan-500 pl-4">
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">Business Impact</div>
          <div className="text-neutral-200">{analysis.business_impact}</div>
        </div>
      )}
    </div>
    <div className="tactical-panel p-5">
      <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 mb-3">// OFFENSE METADATA</div>
      <Kv k="Offense Type" v={off.offense_type} />
      <Kv k="Rules" v={(off.rules || []).join(", ") || "—"} />
      <Kv k="Categories" v={(off.categories || []).join(", ") || "—"} />
      <Kv k="Source IPs" v={(off.source_ips || []).join(", ") || "—"} />
      <Kv k="Dest IPs" v={(off.destination_ips || []).join(", ") || "—"} />
      <Kv k="Usernames" v={(off.usernames || []).join(", ") || "—"} />
      <Kv k="Start Time" v={off.start_time ? new Date(off.start_time).toLocaleString() : "—"} />
      <Kv k="Last Updated" v={off.last_updated ? new Date(off.last_updated).toLocaleString() : "—"} />
    </div>
  </div>
);

const TimelineTab = ({ timeline }) => (
  <div className="tactical-panel p-5" data-testid="timeline-tab">
    <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 mb-4">// EVENT TIMELINE</div>
    <ol className="space-y-3 relative pl-6 before:content-[''] before:absolute before:left-2 before:top-1 before:bottom-1 before:w-px before:bg-[#1F1F1F]">
      {timeline.map((t, i) => (
        <li key={i} className="relative" data-testid={`timeline-item-${i}`}>
          <span className="absolute -left-6 top-1 w-3 h-3 bg-cyan-400 rounded-none"></span>
          <div className="text-[10px] font-mono uppercase text-cyan-400 tracking-widest">{t.ts ? new Date(t.ts).toLocaleString() : ""}</div>
          <div className="font-mono text-sm text-neutral-100">{t.label}</div>
          <div className="text-xs text-neutral-500 font-mono break-all">{t.detail}</div>
        </li>
      ))}
      {timeline.length === 0 && <li className="text-neutral-500 font-mono text-sm">No timeline available. Run investigation.</li>}
    </ol>
  </div>
);

const EventsTab = ({ events, highlight }) => {
  const hv = highlight?.value?.toLowerCase() || "";
  const matches = (e) => {
    if (!hv) return false;
    const blob = JSON.stringify(e).toLowerCase();
    return blob.includes(hv);
  };
  return (
    <div className="tactical-panel overflow-hidden" data-testid="events-tab">
      {highlight && (
        <div className="p-3 border-b border-[color:var(--border-default)] text-[10px] font-mono uppercase tracking-widest text-cyan-400" data-testid="events-highlight-banner">
          // JUMPED FROM MSSP REPORT · matching '{highlight.label}: {highlight.value}'
        </div>
      )}
      <table className="w-full text-xs">
        <thead className="text-[10px] font-mono uppercase text-[color:var(--text-secondary)] tracking-widest border-b border-[color:var(--border-default)]">
          <tr>
            <th className="text-left px-3 py-2">Event</th>
            <th className="text-left px-3 py-2">Source IP</th>
            <th className="text-left px-3 py-2">Dest IP</th>
            <th className="text-left px-3 py-2">User</th>
            <th className="text-left px-3 py-2">Log Source</th>
            <th className="text-left px-3 py-2">Category</th>
            <th className="text-left px-3 py-2">Time</th>
          </tr>
        </thead>
        <tbody className="font-mono">
          {events.map((e, i) => {
            const isMatch = matches(e);
            return (
              <tr key={i} className={`border-b border-[#0F0F0F] ${isMatch ? "bg-cyan-500/10 border-cyan-500" : "hover:bg-[color:var(--bg-hover)]"}`} data-testid={`event-row-${i}`}>
                <td className="px-3 py-2 text-[color:var(--text-primary)]">{isMatch && <span className="text-cyan-400 mr-1">►</span>}{e.event_name || e.category || "Event"}</td>
                <td className="px-3 py-2 text-amber-400">{e.sourceip || "—"}</td>
                <td className="px-3 py-2 text-[color:var(--text-secondary)]">{e.destinationip || "—"}</td>
                <td className="px-3 py-2 text-cyan-400">{e.username || "—"}</td>
                <td className="px-3 py-2 text-[color:var(--text-secondary)]">{e.log_source || "—"}</td>
                <td className="px-3 py-2 text-[color:var(--text-secondary)]">{e.category || "—"}</td>
                <td className="px-3 py-2 text-[color:var(--text-secondary)]">{e.event_time ? new Date(e.event_time).toLocaleTimeString() : "—"}</td>
              </tr>
            );
          })}
          {events.length === 0 && <tr><td colSpan={7} className="px-3 py-10 text-center text-[color:var(--text-secondary)]">No events attached.</td></tr>}
        </tbody>
      </table>
    </div>
  );
};

const PayloadTab = ({ events, decoded }) => (
  <div className="space-y-4" data-testid="payload-tab">
    {decoded?.length > 0 && (
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 mb-2">// BASE64 DECODED</div>
        {decoded.map((d, i) => (<PayloadViewer key={i} text={d} testId={`decoded-${i}`} />))}
      </div>
    )}
    <div>
      <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 mb-2">// RAW PAYLOADS</div>
      {events.map((e, i) => (
        <div key={i} className="mb-3">
          <div className="text-[10px] font-mono uppercase text-cyan-400 mb-1">{e.event_name || `event ${i}`}</div>
          <PayloadViewer text={e.decoded_payload || e.payload || "(no payload)"} testId={`payload-${i}`} />
        </div>
      ))}
    </div>
  </div>
);

const ArtifactsTab = ({ off, setOff }) => {
  const iocs = off.iocs || {};
  const vtLookups = off.vt_lookups || {};
  const [busyKey, setBusyKey] = useState(null);

  // Build unified artifact list from IOCs + offense metadata (hosts, users, machine ids)
  const rows = [];
  const push = (kind, value, vtType, color) => {
    if (!value) return;
    rows.push({ kind, value, vtType, color, key: `${vtType || kind}:${value}` });
  };
  (iocs.ipv4_external || []).forEach((v) => push("external ipv4", v, "ip", "text-amber-400"));
  (iocs.ipv4_internal || []).forEach((v) => push("internal ipv4", v, null, "text-cyan-400"));
  (off.source_ips || []).forEach((v) => {
    if (!rows.find((r) => r.value === v)) {
      const isPriv = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(v);
      push(isPriv ? "internal host" : "external host", v, isPriv ? null : "ip",
        isPriv ? "text-cyan-400" : "text-amber-400");
    }
  });
  (off.destination_ips || []).forEach((v) => {
    if (!rows.find((r) => r.value === v)) {
      const isPriv = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(v);
      push(isPriv ? "internal host" : "external host", v, isPriv ? null : "ip",
        isPriv ? "text-cyan-400" : "text-amber-400");
    }
  });
  (iocs.md5 || []).forEach((v) => push("md5", v, "hash", "text-rose-400"));
  (iocs.sha1 || []).forEach((v) => push("sha1", v, "hash", "text-rose-400"));
  (iocs.sha256 || []).forEach((v) => push("sha256", v, "hash", "text-rose-400"));
  (iocs.url || []).forEach((v) => push("url", v, "url", "text-emerald-400"));
  (iocs.domain || []).forEach((v) => push("domain", v, "domain", "text-emerald-400"));
  (iocs.email || []).forEach((v) => push("email", v, null, "text-neutral-200"));
  (iocs.registry || []).forEach((v) => push("registry", v, null, "text-purple-400"));
  (iocs.command_line || []).forEach((v) => push("command_line", v, null, "text-yellow-400"));
  (off.usernames || []).forEach((v) => push("username", v, null, "text-cyan-300"));
  // machine ids / hostnames from events
  const hosts = new Set();
  (off.events || []).forEach((e) => {
    if (e.machine_identifier) hosts.add(e.machine_identifier);
  });
  Array.from(hosts).forEach((v) => push("hostname", v, null, "text-fuchsia-400"));

  const lookup = async (row) => {
    setBusyKey(row.key);
    try {
      const r = await api.post(`/offenses/${off.id}/vt-lookup`, {
        artifact_type: row.vtType, value: row.value,
      });
      setOff(r.data.offense);
      const res = r.data.entry?.result || {};
      if (res.error) toast.warning(res.error);
      else toast.success(`VT: ${res.malicious || 0} malicious · ${res.suspicious || 0} suspicious`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "VirusTotal lookup failed");
    } finally { setBusyKey(null); }
  };

  return (
    <div className="tactical-panel overflow-hidden" data-testid="artifacts-tab">
      <table className="w-full text-xs">
        <thead className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest border-b border-[#1F1F1F] bg-[#080808]">
          <tr>
            <th className="text-left px-3 py-2 w-40">Type</th>
            <th className="text-left px-3 py-2">Value</th>
            <th className="text-left px-3 py-2 w-64">VirusTotal</th>
          </tr>
        </thead>
        <tbody className="font-mono">
          {rows.map((r) => {
            const vt = vtLookups[r.key]?.result;
            return (
              <tr key={r.key} className="border-b border-[#0F0F0F] hover:bg-[#111]" data-testid={`artifact-row-${r.key}`}>
                <td className="px-3 py-2 uppercase text-[10px] tracking-widest text-neutral-500">{r.kind}</td>
                <td className={`px-3 py-2 break-all ${r.color}`}>{r.value}</td>
                <td className="px-3 py-2">
                  {r.vtType ? (
                    vt ? (
                      vt.error ? (
                        <span className="text-neutral-500 text-[11px]" data-testid={`vt-error-${r.key}`}>{vt.error}</span>
                      ) : (
                        <span className="inline-flex items-center gap-2 text-[11px]" data-testid={`vt-result-${r.key}`}>
                          <span className={vt.malicious > 0 ? "text-rose-400" : vt.suspicious > 0 ? "text-amber-400" : "text-emerald-400"}>
                            MAL {vt.malicious || 0} · SUS {vt.suspicious || 0}
                          </span>
                          {vt.country && <span className="text-neutral-500">· {vt.country}</span>}
                          {vt.as_owner && <span className="text-neutral-500 truncate max-w-[160px]">· {vt.as_owner}</span>}
                          <button onClick={() => lookup(r)} disabled={busyKey === r.key}
                                  data-testid={`vt-refetch-${r.key}`}
                                  className="text-cyan-400 hover:text-cyan-300 underline decoration-dotted">
                            re-check
                          </button>
                        </span>
                      )
                    ) : (
                      <button onClick={() => lookup(r)} disabled={busyKey === r.key}
                              data-testid={`vt-lookup-${r.key}`}
                              className="border border-cyan-500 text-cyan-400 hover:bg-cyan-500/10 px-2 py-1 text-[10px] font-mono uppercase tracking-widest inline-flex items-center gap-1 disabled:opacity-40">
                        {busyKey === r.key ? <Loader2 className="w-3 h-3 animate-spin" /> : <Brain className="w-3 h-3" />}
                        {busyKey === r.key ? "Checking…" : "Check VirusTotal"}
                      </button>
                    )
                  ) : (
                    <span className="text-neutral-600 text-[11px]">— not applicable —</span>
                  )}
                </td>
              </tr>
            );
          })}
          {rows.length === 0 && <tr><td colSpan={3} className="px-3 py-10 text-center text-neutral-500">No artifacts extracted yet. Run AI Investigation first.</td></tr>}
        </tbody>
      </table>
    </div>
  );
};

const SimilarTab = ({ items }) => (  <div className="tactical-panel overflow-hidden" data-testid="similar-tab">
    <table className="w-full text-sm">
      <thead className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest border-b border-[#1F1F1F] bg-[#080808]">
        <tr>
          <th className="text-left px-3 py-2">Description</th>
          <th className="text-left px-3 py-2">Similarity</th>
          <th className="text-left px-3 py-2">Recommendation</th>
          <th className="text-left px-3 py-2">Was FP?</th>
        </tr>
      </thead>
      <tbody>
        {items.map((s, i) => (
          <tr key={i} className="border-b border-[#0F0F0F] hover:bg-[#111]" data-testid={`similar-row-${i}`}>
            <td className="px-3 py-2 text-neutral-200">{s.description}</td>
            <td className="px-3 py-2 font-mono text-cyan-400">{s.similarity}%</td>
            <td className="px-3 py-2 font-mono text-xs">{s.recommendation || "—"}</td>
            <td className="px-3 py-2 font-mono text-xs">{s.was_false_positive ? "YES" : "no"}</td>
          </tr>
        ))}
        {items.length === 0 && <tr><td colSpan={4} className="px-3 py-10 text-center text-neutral-500">No similar historical incidents.</td></tr>}
      </tbody>
    </table>
  </div>
);

const KbTab = ({ items }) => (
  <div className="space-y-3" data-testid="kb-tab">
    {items.length === 0 && <div className="text-neutral-500 font-mono text-sm">No knowledge base matches. Upload documents for this client.</div>}
    {items.map((m, i) => (
      <div key={i} className="tactical-panel p-4">
        <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-widest text-neutral-500 mb-2">
          <span>{m.kb_type}</span>
          <span>{m.source} · sim {(m.similarity * 100).toFixed(0)}%</span>
        </div>
        <div className="text-sm text-neutral-200 leading-relaxed font-mono">{m.text}</div>
      </div>
    ))}
  </div>
);

const RecommendationsTab = ({ off, analysis }) => (
  <div className="grid grid-cols-1 lg:grid-cols-2 gap-5" data-testid="recommendations-tab">
    <div className="tactical-panel p-5">
      <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// RECOMMENDED ACTION</div>
      <h2 className="font-display text-3xl text-cyan-400 mt-2" data-testid="rec-action">{analysis.recommended_action || off.recommendation || "—"}</h2>
      <div className="text-xs font-mono uppercase text-neutral-500 mt-1">Confidence: {analysis.confidence || off.confidence || 0}%</div>
      <div className="mt-4">
        <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">Escalation</div>
        <p className="text-sm text-neutral-200">{analysis.escalation_recommendation || "—"}</p>
      </div>
      <div className="mt-3">
        <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">Closing</div>
        <p className="text-sm text-neutral-200">{analysis.closing_recommendation || "—"}</p>
      </div>
    </div>
    <div className="tactical-panel p-5">
      <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 mb-2">// CONTAINMENT STEPS</div>
      <ol className="space-y-2">
        {(analysis.containment_steps || []).map((s, i) => (
          <li key={i} className="text-sm text-neutral-200 flex gap-3">
            <span className="font-mono text-cyan-400">{String(i + 1).padStart(2, "0")}</span>
            <span>{s}</span>
          </li>
        ))}
        {(!analysis.containment_steps || analysis.containment_steps.length === 0) && (
          <li className="text-neutral-500 font-mono text-sm">No steps generated.</li>
        )}
      </ol>
    </div>
  </div>
);
