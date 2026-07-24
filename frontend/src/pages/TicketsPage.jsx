import { useEffect, useState } from "react";
import api from "@/lib/api";
import { useClients } from "@/lib/clients";
import { toast } from "sonner";
import { Check, X, Merge, Send, Ticket as TicketIcon } from "lucide-react";
import { StatusChip, SeverityChip } from "@/components/SeverityChip";
import { MsspReport } from "@/components/MsspReport";

export default function TicketsPage() {
  const { activeClientId } = useClients();
  const [tickets, setTickets] = useState([]);
  const [selected, setSelected] = useState([]);
  const [merging, setMerging] = useState(false);
  const [expanded, setExpanded] = useState({});

  const load = async () => {
    if (!activeClientId) return;
    const r = await api.get(`/tickets?client_id=${activeClientId}`);
    setTickets(r.data || []);
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [activeClientId]);

  const approve = async (id, approved) => {
    try {
      await api.post(`/tickets/${id}/approve`, { approved });
      toast.success(approved ? "Approved & pushed to destination" : "Rejected");
      load();
    } catch (e) { toast.error(e?.response?.data?.detail || "Action failed"); }
  };

  const toggle = (id) => setSelected((s) => s.includes(id) ? s.filter((x) => x !== id) : [...s, id]);

  const merge = async () => {
    if (selected.length < 2) return toast.error("Select at least 2 tickets");
    setMerging(true);
    try {
      const r = await api.post("/tickets/merge", { ticket_ids: selected });
      toast.success("Tickets merged into new parent");
      setSelected([]);
      load();
    } catch (e) { toast.error(e?.response?.data?.detail || "Merge failed"); }
    finally { setMerging(false); }
  };

  return (
    <div className="space-y-5" data-testid="tickets-page">
      <div className="flex items-baseline justify-between">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// APPROVAL QUEUE</div>
          <h1 className="font-display text-3xl mt-1">Tickets</h1>
        </div>
        <button onClick={merge} disabled={merging || selected.length < 2} data-testid="btn-merge-tickets"
          className="border border-[#1F1F1F] hover:border-cyan-500 hover:text-cyan-400 px-4 py-2 text-xs font-mono uppercase tracking-widest text-neutral-300 inline-flex items-center gap-2 disabled:opacity-40">
          <Merge className="w-3.5 h-3.5" /> Merge Selected ({selected.length})
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 stagger">
        {tickets.map((t) => (
          <div key={t.id} className="tactical-panel p-5" data-testid={`ticket-${t.id}`}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3 min-w-0">
                <input type="checkbox" checked={selected.includes(t.id)} onChange={() => toggle(t.id)}
                  data-testid={`ticket-select-${t.id}`} className="mt-1 accent-cyan-400" />
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">#{t.id.slice(0, 8)}</span>
                    <StatusChip status={t.status} />
                    <span className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">→ {t.destination.toUpperCase()}</span>
                    {t.external_ref && <span className="text-[10px] font-mono text-emerald-400">{t.external_ref}</span>}
                  </div>
                  <div className="font-display text-lg leading-tight break-words">{t.title}</div>
                  <div className="text-sm text-neutral-400 mt-2 line-clamp-3">{t.executive_summary}</div>
                  <div className="flex flex-wrap gap-4 text-[10px] font-mono uppercase tracking-widest text-neutral-500 mt-3">
                    <span>RISK <span className="text-cyan-400">{t.risk_score}</span></span>
                    <span>MITRE <span className="text-cyan-400">{t.mitre?.length || 0}</span></span>
                    <span>IOCs <span className="text-cyan-400">{Object.values(t.iocs || {}).reduce((a, b) => a + (Array.isArray(b) ? b.length : 0), 0)}</span></span>
                    <span>CREATED BY <span className="text-neutral-300 normal-case">{t.created_by}</span></span>
                    <span>{new Date(t.created_at).toLocaleString()}</span>
                    <button data-testid={`toggle-mssp-${t.id}`}
                      onClick={() => setExpanded((e) => ({ ...e, [t.id]: !e[t.id] }))}
                      className="ml-auto text-cyan-400 hover:text-cyan-300 uppercase tracking-widest">
                      {expanded[t.id] ? "Hide" : "Show"} L1 Report
                    </button>
                  </div>
                  {expanded[t.id] && (
                    <div className="mt-4" data-testid={`ticket-mssp-${t.id}`}>
                      <MsspReport report={t.mssp_report} testId={`ticket-mssp-report-${t.id}`} />
                    </div>
                  )}
                </div>
              </div>
              {t.status === "PENDING_APPROVAL" && (
                <div className="flex flex-col gap-2 flex-shrink-0">
                  <button onClick={() => approve(t.id, true)} data-testid={`approve-${t.id}`}
                    className="bg-emerald-500 hover:bg-emerald-400 text-black px-3 py-1.5 text-[11px] font-mono uppercase tracking-widest font-bold inline-flex items-center gap-1">
                    <Check className="w-3 h-3" /> Approve & Push
                  </button>
                  <button onClick={() => approve(t.id, false)} data-testid={`reject-${t.id}`}
                    className="border border-rose-500 text-rose-400 hover:bg-rose-500/20 px-3 py-1.5 text-[11px] font-mono uppercase tracking-widest inline-flex items-center gap-1">
                    <X className="w-3 h-3" /> Reject
                  </button>
                </div>
              )}
            </div>
          </div>
        ))}
        {tickets.length === 0 && (
          <div className="tactical-panel p-10 text-center text-neutral-500 font-mono">
            <TicketIcon className="w-6 h-6 mx-auto mb-2 opacity-50" />
            No tickets yet. Investigate an offense and create a ticket.
          </div>
        )}
      </div>
    </div>
  );
}
