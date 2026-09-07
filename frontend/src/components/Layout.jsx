import { NavLink, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import {
  LayoutDashboard, ShieldAlert, BookOpen, Building2, Settings as SettingsIcon,
  Users, ScrollText, TicketCheck, LogOut, Hexagon, GraduationCap, Sun, Moon
} from "lucide-react";
import { useAuth, hasRole } from "@/lib/auth";
import { useClients } from "@/lib/clients";
import { useTheme } from "@/lib/theme";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, testId: "nav-dashboard", roles: ["Admin", "SOC Manager", "L1", "L2", "L3", "ReadOnly"] },
  { to: "/offenses", label: "Offenses", icon: ShieldAlert, testId: "nav-offenses", roles: ["Admin", "SOC Manager", "L1", "L2", "L3", "ReadOnly"] },
  { to: "/tickets", label: "Tickets", icon: TicketCheck, testId: "nav-tickets", roles: ["Admin", "SOC Manager", "L1", "L2", "L3", "ReadOnly"] },
  { to: "/coach", label: "Analyst Coach", icon: GraduationCap, testId: "nav-coach", roles: ["Admin", "SOC Manager", "L1", "L2", "L3"] },
  { to: "/knowledge-base", label: "Knowledge Base", icon: BookOpen, testId: "nav-kb", roles: ["Admin", "SOC Manager", "L2", "L3"] },
  { to: "/clients", label: "Clients", icon: Building2, testId: "nav-clients", roles: ["Admin", "SOC Manager"] },
  { to: "/users", label: "Users & RBAC", icon: Users, testId: "nav-users", roles: ["Admin", "SOC Manager"] },
  { to: "/audit", label: "Audit Logs", icon: ScrollText, testId: "nav-audit", roles: ["Admin", "SOC Manager"] },
  { to: "/settings", label: "Settings", icon: SettingsIcon, testId: "nav-settings", roles: ["Admin", "SOC Manager"] },
];

const useClock = () => {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return now.toISOString().replace("T", " ").slice(0, 19) + "Z";
};

export const Layout = ({ children, title, subtitle }) => {
  const { user, logout } = useAuth();
  const { clients, activeClientId, setActive } = useClients();
  const { theme, toggle } = useTheme();
  const location = useLocation();
  const activeClient = clients.find((c) => c.id === activeClientId);
  const clock = useClock();
  const initials = (user?.name || "?").split(" ").map((s) => s[0]).slice(0, 2).join("").toUpperCase();

  return (
    <div className="min-h-screen flex" data-testid="app-layout"
         style={{ background: "var(--tg-bg)", color: "var(--tg-text)" }}>
      {/* Sidebar */}
      <aside className="w-60 flex flex-col shrink-0"
             style={{ background: "var(--tg-surface)", borderRight: "1px solid var(--tg-border)" }}
             data-testid="sidebar">
        <div className="px-4 py-5 flex items-center gap-3"
             style={{ borderBottom: "1px solid var(--tg-border)" }}>
          <div className="w-8 h-8 rounded-lg flex items-center justify-center"
               style={{ background: "rgba(134, 188, 37, 0.16)" }}>
            <Hexagon className="w-4 h-4" style={{ color: "var(--tg-cyan)" }} strokeWidth={2} />
          </div>
          <div>
            <div className="font-display text-sm tracking-tight" style={{ color: "var(--tg-text)" }}>
              SOCPILOT<span style={{ color: "var(--tg-cyan)" }}>.AI</span>
            </div>
            <div className="text-[10px] font-mono uppercase tracking-widest" style={{ color: "var(--tg-text-muted)" }}>
              MSSP L1 Console
            </div>
          </div>
        </div>
        <div className="px-4 pt-4 pb-1 text-[10px] font-mono tracking-[0.2em] uppercase"
             style={{ color: "var(--tg-text-muted)" }}>
          // Operations
        </div>
        <nav className="flex-1 py-1" aria-label="Primary">
          {nav.filter((n) => hasRole(user, n.roles)).map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"}
                     data-testid={n.testId}
                     className={({ isActive }) => `sidebar-item ${isActive ? "active" : ""}`}>
              <n.icon className="w-4 h-4" strokeWidth={1.7} />
              <span>{n.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="p-3" style={{ borderTop: "1px solid var(--tg-border)" }}>
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full flex items-center justify-center font-display text-sm"
                 style={{ background: "rgba(4, 106, 56, 0.10)", color: "var(--tg-cyan)" }}>
              {initials}
            </div>
            <div className="min-w-0">
              <div className="text-sm truncate" data-testid="header-user-name" style={{ color: "var(--tg-text)" }}>
                {user?.name}
              </div>
              <div className="text-[10px] font-mono uppercase tracking-widest" style={{ color: "var(--tg-cyan)" }}>
                {user?.role}
              </div>
            </div>
          </div>
          <button data-testid="btn-logout" onClick={logout}
                  className="tg-btn mt-3 w-full justify-center" style={{ padding: "6px 10px" }}>
            <LogOut className="w-3 h-3" /> Logout
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Lime accent strip */}
        <div style={{ height: "3px", background: "var(--tg-lime)" }} />
        <header className="h-16 px-6 flex items-center justify-between sticky top-0 z-10"
                style={{ background: "var(--tg-surface)", borderBottom: "1px solid var(--tg-border)" }}>
          <div className="flex items-center gap-4 min-w-0">
            <div>
              {title && <div className="font-display text-base" style={{ color: "var(--tg-text)" }}>{title}</div>}
              {subtitle && (
                <div className="text-[10px] font-mono tracking-[0.18em] uppercase" style={{ color: "var(--tg-text-muted)" }}>
                  // {subtitle}
                </div>
              )}
              {!title && (
                <div className="flex items-center gap-2 min-w-0">
                  <span className="tg-label" style={{ color: "var(--tg-text-muted)" }}>Tenant</span>
                  <select data-testid="client-selector"
                          value={activeClientId || ""}
                          onChange={(e) => setActive(e.target.value)}
                          className="text-sm font-mono px-3 py-1.5 rounded-md focus:outline-none"
                          style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }}>
                    {clients.map((c) => (
                      <option key={c.id} value={c.id}>{c.code} · {c.name}</option>
                    ))}
                  </select>
                  {activeClient && (
                    <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: "var(--tg-text-muted)" }}>
                      {activeClient.industry}
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="inline-flex items-center gap-2 text-[10px] font-mono tracking-[0.18em] uppercase"
                 style={{ color: "var(--tg-text-muted)" }}>
              <span className="w-2 h-2 rounded-full tg-pulse" style={{ background: "var(--tg-lime)" }} />
              <span>Live · {clock}</span>
            </div>
            <button onClick={toggle} data-testid="theme-toggle" className="tg-btn" style={{ padding: "6px 10px" }} aria-label="toggle theme">
              {theme === "dark" ? <Sun className="w-3 h-3" /> : <Moon className="w-3 h-3" />}
              {theme === "dark" ? "Light" : "Dark"}
            </button>
            <span className="text-[10px] font-mono tracking-[0.18em] uppercase" style={{ color: "var(--tg-text-muted)" }}>
              PATH: <span style={{ color: "var(--tg-cyan)" }}>{location.pathname}</span>
            </span>
          </div>
        </header>
        <div className="flex-1 overflow-auto p-6" data-testid="page-content">
          <div className="fade-in-up">{children}</div>
        </div>
      </main>
    </div>
  );
};
