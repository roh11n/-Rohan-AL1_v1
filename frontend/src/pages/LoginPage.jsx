import { useState } from "react";
import { useNavigate, Navigate } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { toast } from "sonner";
import { Hexagon, Zap } from "lucide-react";

export default function LoginPage() {
  const { user, login, loading } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  if (user) return <Navigate to="/" replace />;

  const submit = async (e) => {
    e.preventDefault();
    const r = await login(email, password);
    if (r.ok) {
      toast.success("Authenticated. Loading console…");
      nav("/");
    } else {
      toast.error(r.error);
    }
  };

  return (
    <div className="min-h-screen flex" data-testid="login-page"
         style={{ background: "var(--tg-bg)", color: "var(--tg-text)" }}>
      {/* Lime accent strip */}
      <div className="absolute top-0 left-0 right-0" style={{ height: 3, background: "var(--tg-lime)" }} />

      {/* Left panel */}
      <div className="hidden lg:flex flex-col justify-between w-1/2 relative p-10"
           style={{ borderRight: "1px solid var(--tg-border)", background: "var(--tg-surface)" }}>
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg flex items-center justify-center"
               style={{ background: "rgba(134, 188, 37, 0.16)" }}>
            <Hexagon className="w-5 h-5" style={{ color: "var(--tg-cyan)" }} strokeWidth={2} />
          </div>
          <span className="font-display text-lg tracking-tight">
            SOCPILOT<span style={{ color: "var(--tg-cyan)" }}>.AI</span>
          </span>
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.24em] mb-3" style={{ color: "var(--tg-text-muted)" }}>
            // Security Operations · L1 Automation
          </div>
          <h1 className="font-display text-4xl lg:text-5xl leading-[1.05] max-w-lg">
            Autonomous L1 SOC Analyst<br />
            <span style={{ color: "var(--tg-cyan)" }}>for IBM QRadar MSSP</span>
            <span className="blink-cursor" />
          </h1>
          <p className="max-w-md mt-6 leading-relaxed" style={{ color: "var(--tg-text-dim)" }}>
            Ingest offenses. Correlate events via Ariel. Enrich with per-tenant knowledge.
            Investigate with a local LLM. Recommend. Approve. Route to XSOAR / ServiceNow / Jira in seconds.
          </p>
          <div className="grid grid-cols-3 gap-6 mt-10 max-w-md">
            <Stat label="Workload cut" value="80%" />
            <Stat label="Avg MTTA" value="8m" />
            <Stat label="MITRE Mapped" value="14 tactics" />
          </div>
        </div>
        <div className="flex items-center gap-6 text-[10px] font-mono uppercase tracking-[0.2em]"
             style={{ color: "var(--tg-text-muted)" }}>
          <span>● Multi-Tenant</span>
          <span>● RAG · ChromaDB</span>
          <span>● Offline Ready</span>
        </div>
      </div>

      {/* Right panel */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-6">
        <form onSubmit={submit} className="tg-surface p-8 w-full max-w-sm space-y-5 relative"
              data-testid="login-form">
          <div className="absolute -top-3 left-6 px-2 text-[10px] font-mono uppercase tracking-[0.2em]"
               style={{ background: "var(--tg-bg)", color: "var(--tg-cyan)" }}>
            // Authenticate
          </div>

          <div>
            <div className="tg-label mb-1">Analyst Email</div>
            <input data-testid="input-email" type="email" autoComplete="email"
                   value={email} onChange={(e) => setEmail(e.target.value)}
                   className="w-full text-sm font-mono px-3 py-2 rounded-md focus:outline-none"
                   style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }} />
          </div>
          <div>
            <div className="tg-label mb-1">Password</div>
            <input data-testid="input-password" type="password" autoComplete="current-password"
                   value={password} onChange={(e) => setPassword(e.target.value)}
                   className="w-full text-sm font-mono px-3 py-2 rounded-md focus:outline-none"
                   style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }} />
          </div>
          <button data-testid="btn-login" type="submit" disabled={loading}
                  className="tg-btn tg-btn-primary w-full justify-center" style={{ padding: "10px 14px" }}>
            <Zap className="w-4 h-4" /> {loading ? "Authenticating…" : "Enter Console"}
          </button>
          <div className="pt-3 text-[10px] font-mono uppercase tracking-[0.16em]"
               style={{ color: "var(--tg-text-muted)", borderTop: "1px solid var(--tg-border)" }}>
            <div>Credentials are provisioned by your administrator.</div>
            <div className="mt-1 normal-case tracking-normal">
              First-time bootstrap password is printed once to the backend logs.
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}

const Stat = ({ label, value }) => (
  <div>
    <div className="font-display text-2xl" style={{ color: "var(--tg-cyan)" }}>{value}</div>
    <div className="text-[10px] font-mono uppercase tracking-[0.2em]" style={{ color: "var(--tg-text-muted)" }}>{label}</div>
  </div>
);
