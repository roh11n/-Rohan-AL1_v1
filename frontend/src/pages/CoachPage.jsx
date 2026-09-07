import { useEffect, useState } from "react";
import api from "@/lib/api";
import { useAuth, hasRole } from "@/lib/auth";
import { toast } from "sonner";
import { GraduationCap, TrendingUp, TrendingDown, RotateCcw } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip } from "recharts";

export default function CoachPage() {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [resetting, setResetting] = useState(false);

  const load = async () => {
    const r = await api.get("/coach/insights");
    setData(r.data);
  };
  useEffect(() => { load(); }, []);

  const reset = async () => {
    if (!window.confirm("Reset all learned adjustments? Feedback history is preserved.")) return;
    setResetting(true);
    try {
      await api.post("/coach/reset");
      toast.success("Learned adjustments reset");
      load();
    } catch (e) { toast.error(e?.response?.data?.detail || "Reset failed"); }
    finally { setResetting(false); }
  };

  if (!data) return <div className="text-neutral-500 font-mono text-sm" data-testid="coach-loading">Loading insights...<span className="blink-cursor"></span></div>;

  const actionData = Object.entries(data.by_action || {}).map(([k, v]) => ({
    name: k,
    value: v,
    color: k === "approve" ? "#10B981" : k === "reject" ? "#F43F5E" : k === "escalate" ? "#F59E0B" : k === "close" ? "#6366F1" : "#38BDF8",
  }));
  const topAdj = [...(data.adjustments || [])].sort((a, b) => Math.abs(b.risk_delta) - Math.abs(a.risk_delta)).slice(0, 12);

  return (
    <div className="space-y-5" data-testid="coach-page">
      <div className="flex items-baseline justify-between">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// FEEDBACK LEARNING</div>
          <h1 className="font-display text-3xl mt-1 inline-flex items-center gap-3">
            <GraduationCap className="w-7 h-7 text-cyan-400" strokeWidth={1.5} />
            Analyst Coach
          </h1>
          <p className="text-neutral-400 text-sm mt-2 max-w-2xl">
            Every accept, reject, escalate or modify decision quietly nudges the risk model per detection rule.
            Over time the platform learns which of your rules are noisy versus mission-critical.
          </p>
        </div>
        {hasRole(user, ["Admin"]) && (
          <button onClick={reset} disabled={resetting} data-testid="btn-reset-coach"
            className="border border-[#1F1F1F] hover:border-rose-500 hover:text-rose-400 px-4 py-2 text-xs font-mono uppercase tracking-widest text-neutral-300 inline-flex items-center gap-2">
            <RotateCcw className="w-3.5 h-3.5" /> {resetting ? "Resetting..." : "Reset Model"}
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 stagger">
        <StatCard label="Total Feedback" value={data.total_feedback} testId="coach-total" />
        <StatCard label="Approved" value={data.by_action?.approve || 0} accent="#10B981" testId="coach-approve" />
        <StatCard label="Rejected" value={data.by_action?.reject || 0} accent="#F43F5E" testId="coach-reject" />
        <StatCard label="Escalated" value={data.by_action?.escalate || 0} accent="#F59E0B" testId="coach-escalate" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="tactical-panel p-5">
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// ACTION DISTRIBUTION</div>
          <h3 className="font-display text-lg mt-1 mb-3">Analyst Decisions</h3>
          <div style={{ width: "100%", height: 240 }}>
            <ResponsiveContainer>
              <BarChart data={actionData}>
                <XAxis dataKey="name" stroke="#4B5563" fontSize={11} />
                <YAxis stroke="#4B5563" fontSize={10} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0A0A0A", border: "1px solid #1F1F1F", fontSize: 12 }} />
                <Bar dataKey="value">
                  {actionData.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="tactical-panel p-5">
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// LEARNED RULE ADJUSTMENTS</div>
          <h3 className="font-display text-lg mt-1 mb-3">Risk-Model Tunings</h3>
          <div className="space-y-2 max-h-[280px] overflow-auto">
            {topAdj.length === 0 && <div className="text-neutral-500 font-mono text-sm">No adjustments yet — take actions on offenses to train the model.</div>}
            {topAdj.map((a, i) => (
              <div key={i} className="flex items-center justify-between border-b border-[#141414] py-2" data-testid={`adjustment-${i}`}>
                <div className="min-w-0">
                  <div className="text-sm font-mono text-neutral-100 truncate">{a.rule}</div>
                  <div className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest">
                    {a.feedback_count} signals · last: {a.last_action || "—"}
                  </div>
                </div>
                <div className={`inline-flex items-center gap-1 font-mono text-sm ml-3 ${a.risk_delta > 0 ? "text-emerald-400" : a.risk_delta < 0 ? "text-rose-400" : "text-neutral-500"}`}>
                  {a.risk_delta > 0 ? <TrendingUp className="w-3 h-3" /> : a.risk_delta < 0 ? <TrendingDown className="w-3 h-3" /> : null}
                  {a.risk_delta > 0 ? "+" : ""}{a.risk_delta}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="tactical-panel">
        <div className="p-3 border-b border-[#1F1F1F] text-[10px] font-mono uppercase tracking-widest text-neutral-500">// RECENT FEEDBACK</div>
        <table className="w-full text-sm">
          <thead className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest border-b border-[#1F1F1F] bg-[#080808]">
            <tr>
              <th className="text-left px-3 py-2">Time</th>
              <th className="text-left px-3 py-2">User</th>
              <th className="text-left px-3 py-2">Action</th>
              <th className="text-left px-3 py-2">Recommendation</th>
              <th className="text-left px-3 py-2">Risk</th>
              <th className="text-left px-3 py-2">Severity</th>
            </tr>
          </thead>
          <tbody className="font-mono text-xs">
            {(data.recent_feedback || []).map((f, i) => (
              <tr key={i} className="border-b border-[#0F0F0F] hover:bg-[#111]" data-testid={`feedback-row-${i}`}>
                <td className="px-3 py-2 text-neutral-500">{new Date(f.created_at).toLocaleString()}</td>
                <td className="px-3 py-2 text-cyan-400">{f.user}</td>
                <td className="px-3 py-2 uppercase text-neutral-200">{f.action}</td>
                <td className="px-3 py-2 text-neutral-400">{f.original_recommendation || "—"}</td>
                <td className="px-3 py-2 text-neutral-400">{f.original_risk || 0}</td>
                <td className="px-3 py-2 text-neutral-400">{f.severity_label || "—"}</td>
              </tr>
            ))}
            {(!data.recent_feedback || data.recent_feedback.length === 0) && (
              <tr><td colSpan={6} className="px-3 py-10 text-center text-neutral-500">No feedback recorded yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const StatCard = ({ label, value, accent, testId }) => (
  <div className="metric-card" data-testid={testId}>
    <div className="metric-label">{label}</div>
    <div className="metric-value" style={{ color: accent }}>{value}</div>
  </div>
);
