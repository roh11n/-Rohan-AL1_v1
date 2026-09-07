import { useEffect, useState } from "react";
import api from "@/lib/api";

export default function AuditPage() {
  const [logs, setLogs] = useState([]);
  useEffect(() => { api.get("/audit").then((r) => setLogs(r.data || [])); }, []);
  return (
    <div className="space-y-5" data-testid="audit-page">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// SYSTEM LOG</div>
        <h1 className="font-display text-3xl mt-1">Audit Logs</h1>
      </div>
      <div className="tactical-panel overflow-hidden">
        <table className="w-full text-sm">
          <thead className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest border-b border-[#1F1F1F] bg-[#080808]">
            <tr>
              <th className="text-left px-3 py-2">Time</th>
              <th className="text-left px-3 py-2">User</th>
              <th className="text-left px-3 py-2">Action</th>
              <th className="text-left px-3 py-2">Resource</th>
              <th className="text-left px-3 py-2">Resource ID</th>
              <th className="text-left px-3 py-2">Details</th>
            </tr>
          </thead>
          <tbody className="font-mono text-xs">
            {logs.map((l) => (
              <tr key={l.id} className="border-b border-[#0F0F0F] hover:bg-[#111]" data-testid={`audit-row-${l.id}`}>
                <td className="px-3 py-2 text-neutral-500">{new Date(l.timestamp).toLocaleString()}</td>
                <td className="px-3 py-2 text-cyan-400">{l.user_email}</td>
                <td className="px-3 py-2 text-neutral-200 uppercase">{l.action}</td>
                <td className="px-3 py-2 text-neutral-300">{l.resource}</td>
                <td className="px-3 py-2 text-neutral-500">{l.resource_id?.slice(0, 12) || "—"}</td>
                <td className="px-3 py-2 text-neutral-500 truncate max-w-md">{JSON.stringify(l.details).slice(0, 120)}</td>
              </tr>
            ))}
            {logs.length === 0 && <tr><td colSpan={6} className="px-3 py-10 text-center text-neutral-500">No audit entries.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
