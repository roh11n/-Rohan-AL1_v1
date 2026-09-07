import { useEffect, useState } from "react";
import api from "@/lib/api";
import { useClients } from "@/lib/clients";
import { AreaChart, Area, ResponsiveContainer, Tooltip, XAxis, YAxis, BarChart, Bar, Cell } from "recharts";
import { ShieldAlert, Zap, Activity, TimerReset, Check, AlertTriangle } from "lucide-react";
import { Link } from "react-router-dom";

export default function DashboardPage() {
  const { activeClientId } = useClients();
  const [metrics, setMetrics] = useState(null);
  const [recent, setRecent] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    if (!activeClientId) return;
    setLoading(true);
    try {
      const [m, o] = await Promise.all([
        api.get(`/dashboard/metrics?client_id=${activeClientId}`),
        api.get(`/offenses?client_id=${activeClientId}&limit=6`),
      ]);
      setMetrics(m.data);
      setRecent(o.data || []);
    } finally { setLoading(false); }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [activeClientId]);

  if (loading || !metrics) {
    return <div className="text-neutral-500 font-mono text-sm" data-testid="dash-loading">Loading tactical view...<span className="blink-cursor"></span></div>;
  }

  const sevData = [
    { name: "Critical", value: metrics.by_severity.Critical, color: "#FF003C" },
    { name: "High", value: metrics.by_severity.High, color: "#FF8A00" },
    { name: "Medium", value: metrics.by_severity.Medium, color: "#FACC15" },
    { name: "Low", value: metrics.by_severity.Low, color: "#38BDF8" },
  ];

  return (
    <div className="space-y-6" data-testid="dashboard-page">
      <div className="flex items-baseline justify-between">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// COMMAND OVERVIEW</div>
          <h1 className="font-display text-3xl lg:text-4xl mt-1">Threat Landscape</h1>
        </div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">
          Avg Risk <span className="text-cyan-400 text-lg font-display ml-2">{metrics.average_risk}</span>
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 stagger" data-testid="metric-cards">
        <MetricCard label="Total Offenses" value={metrics.total_offenses} icon={ShieldAlert} testId="metric-total" />
        <MetricCard label="Critical" value={metrics.by_severity.Critical} icon={AlertTriangle} accent="#FF003C" testId="metric-critical" />
        <MetricCard label="High" value={metrics.by_severity.High} icon={AlertTriangle} accent="#FF8A00" testId="metric-high" />
        <MetricCard label="Pending Approval" value={metrics.pending_approval} icon={Check} accent="#A855F7" testId="metric-pending" />
        <MetricCard label="Automation Rate" value={`${metrics.automation_rate}%`} icon={Zap} accent="#00F0FF" testId="metric-automation" />
        <MetricCard label="False Positive Rate" value={`${metrics.false_positive_rate}%`} icon={Activity} testId="metric-fp" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend chart */}
        <div className="tactical-panel p-5 lg:col-span-2" data-testid="trend-panel">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// OFFENSE VOLUME · 7-DAY</div>
              <h3 className="font-display text-lg mt-1">Ingest Trend</h3>
            </div>
            <div className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest flex gap-4">
              <span>MTTA <span className="text-cyan-400 text-lg font-display ml-1">{metrics.mtta_minutes}m</span></span>
              <span>MTTR <span className="text-cyan-400 text-lg font-display ml-1">{metrics.mttr_minutes}m</span></span>
            </div>
          </div>
          <div style={{ width: "100%", height: 220 }}>
            <ResponsiveContainer>
              <AreaChart data={metrics.trend_7d}>
                <defs>
                  <linearGradient id="grad1" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00F0FF" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#00F0FF" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#4B5563" fontSize={10} tickFormatter={(d) => d?.slice(5)} />
                <YAxis stroke="#4B5563" fontSize={10} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0A0A0A", border: "1px solid #1F1F1F", fontSize: 12 }} />
                <Area type="monotone" dataKey="count" stroke="#00F0FF" strokeWidth={2} fill="url(#grad1)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity distribution */}
        <div className="tactical-panel p-5" data-testid="severity-panel">
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// DISTRIBUTION</div>
          <h3 className="font-display text-lg mt-1 mb-3">By Severity</h3>
          <div style={{ width: "100%", height: 220 }}>
            <ResponsiveContainer>
              <BarChart data={sevData} layout="vertical" margin={{ left: 8, right: 8 }}>
                <XAxis type="number" stroke="#4B5563" fontSize={10} allowDecimals={false} />
                <YAxis type="category" dataKey="name" stroke="#4B5563" fontSize={11} width={70} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: "#0A0A0A", border: "1px solid #1F1F1F", fontSize: 12 }} />
                <Bar dataKey="value" radius={[0, 0, 0, 0]}>
                  {sevData.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent offenses */}
      <div className="tactical-panel" data-testid="recent-offenses">
        <div className="flex items-center justify-between p-4 border-b border-[#1F1F1F]">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// FEED</div>
            <h3 className="font-display text-lg">Recent Offenses</h3>
          </div>
          <Link to="/offenses" className="text-[11px] font-mono uppercase tracking-widest text-cyan-400 hover:text-cyan-300" data-testid="link-view-all-offenses">View all →</Link>
        </div>
        <table className="w-full text-sm">
          <thead className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest border-b border-[#1F1F1F]">
            <tr>
              <th className="text-left px-4 py-2">ID</th>
              <th className="text-left px-4 py-2">Description</th>
              <th className="text-left px-4 py-2">Severity</th>
              <th className="text-left px-4 py-2">Source IP</th>
              <th className="text-left px-4 py-2">Rules</th>
              <th className="text-left px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody className="stagger">
            {recent.map((o) => (
              <tr key={o.id} className="border-b border-[#0F0F0F] hover:bg-[#111]">
                <td className="px-4 py-2 font-mono text-cyan-400">
                  <Link to={`/offenses/${o.id}`} data-testid={`row-offense-${o.id}`}>#{o.qradar_offense_id || o.id.slice(0, 8)}</Link>
                </td>
                <td className="px-4 py-2 text-neutral-200 max-w-md truncate">{o.description}</td>
                <td className="px-4 py-2"><SevBadge label={o.severity_label} /></td>
                <td className="px-4 py-2 font-mono text-neutral-400 text-xs">{(o.source_ips || [])[0] || "—"}</td>
                <td className="px-4 py-2 font-mono text-neutral-400 text-xs">{(o.rules || [])[0]?.slice(0, 40) || "—"}</td>
                <td className="px-4 py-2 font-mono text-xs text-neutral-400">{o.status?.replace(/_/g, " ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const MetricCard = ({ label, value, icon: Icon, accent, testId }) => (
  <div className="metric-card" data-testid={testId}>
    <div className="flex items-start justify-between">
      <div>
        <div className="metric-label">{label}</div>
        <div className="metric-value" style={{ color: accent }}>{value}</div>
      </div>
      {Icon && <Icon className="w-4 h-4 text-neutral-600" strokeWidth={1.5} />}
    </div>
  </div>
);

const SevBadge = ({ label }) => {
  const cls = { Critical: "sev-critical", High: "sev-high", Medium: "sev-medium", Low: "sev-low" }[label] || "sev-low";
  return <span className={`severity-chip ${cls}`}>{label}</span>;
};
