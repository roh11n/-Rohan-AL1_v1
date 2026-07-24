import { useEffect, useState } from "react";
import api from "@/lib/api";
import { toast } from "sonner";
import { Save, Server, Bot, Ticket, MessageSquare, Mail, TestTube2, Workflow, Cloud, Send, Radar } from "lucide-react";

const EMPTY_INT = { enabled: false, url: "", token: "", username: "", project_key: "", webhook_url: "" };

export default function SettingsPage() {
  const [data, setData] = useState(null);
  const [tab, setTab] = useState("qradar");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  const load = async () => {
    const r = await api.get("/settings");
    // ensure sub-objects present
    const d = r.data || {};
    d.qradar = d.qradar || {};
    d.llm = d.llm || {};
    d.threat_intel = d.threat_intel || {
      virustotal_enabled: false, virustotal_api_key: "", virustotal_api_keys: "",
      abuseipdb_enabled: false, abuseipdb_api_key: "",
      misp_enabled: false, misp_url: "", misp_api_key: "", misp_verify_ssl: false,
    };
    for (const k of ["xsoar", "servicenow", "jira", "freshservice", "slack", "teams", "email"]) {
      d[k] = { ...EMPTY_INT, ...(d[k] || {}) };
    }
    setData(d);
  };
  useEffect(() => { load(); }, []);

  const save = async () => {
    setSaving(true);
    try {
      const payload = { ...data };
      delete payload.qradar?.api_token_masked;
      await api.put("/settings", payload);
      toast.success("Settings saved");
      load();
    } catch (e) { toast.error(e?.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };

  const testQRadar = async () => {
    setTesting(true);
    try {
      const r = await api.post("/qradar/test");
      if (r.data.ok) toast.success("QRadar connection OK");
      else toast.error(`Failed: ${r.data.error}`);
    } catch (e) { toast.error("Test failed"); }
    finally { setTesting(false); }
  };

  if (!data) return <div className="text-neutral-500 font-mono text-sm">Loading settings<span className="blink-cursor"></span></div>;

  const TABS = [
    { id: "qradar", label: "QRadar", icon: Server },
    { id: "llm", label: "Local LLM", icon: Bot },
    { id: "threat_intel", label: "Threat Intel", icon: Radar },
    { id: "xsoar", label: "Cortex XSOAR", icon: Workflow },
    { id: "servicenow", label: "ServiceNow", icon: Cloud },
    { id: "jira", label: "Jira", icon: Ticket },
    { id: "freshservice", label: "Freshservice", icon: Ticket },
    { id: "slack", label: "Slack", icon: Send },
    { id: "teams", label: "Teams", icon: MessageSquare },
    { id: "email", label: "Email", icon: Mail },
  ];

  return (
    <div className="space-y-5" data-testid="settings-page">
      <div className="flex items-baseline justify-between">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// SYSTEM CONFIG</div>
          <h1 className="font-display text-3xl mt-1">Settings</h1>
        </div>
        <button onClick={save} disabled={saving} data-testid="btn-save-settings"
          className="bg-cyan-400 hover:bg-cyan-300 text-black px-4 py-2 text-xs font-mono uppercase tracking-widest font-bold inline-flex items-center gap-2">
          <Save className="w-3.5 h-3.5" /> {saving ? "Saving..." : "Save Changes"}
        </button>
      </div>

      <div className="grid grid-cols-12 gap-5">
        <div className="col-span-12 md:col-span-3 tactical-panel py-2">
          {TABS.map((t) => (
            <button key={t.id} onClick={() => setTab(t.id)} data-testid={`settings-tab-${t.id}`}
              className={`w-full flex items-center gap-2 text-left px-4 py-2 text-sm font-mono ${tab === t.id ? "text-cyan-400 bg-[#111]" : "text-neutral-400 hover:text-cyan-400 hover:bg-[#0F0F0F]"}`}>
              <t.icon className="w-4 h-4" /> {t.label}
            </button>
          ))}
        </div>
        <div className="col-span-12 md:col-span-9 tactical-panel p-6">
          {tab === "qradar" && (
            <div className="space-y-4" data-testid="qradar-settings">
              <SectionHeader title="IBM QRadar" hint="SEC Token auth, API v12+" />
              <TextField label="Host URL (e.g. https://qradar.acme.local)" val={data.qradar.host} on={(v) => setData({ ...data, qradar: { ...data.qradar, host: v } })} testId="qradar-host" />
              <TextField label="API SEC Token" val={data.qradar.api_token} on={(v) => setData({ ...data, qradar: { ...data.qradar, api_token: v } })} type="password" testId="qradar-token" />
              <div className="grid grid-cols-3 gap-4">
                <TextField label="API Version" val={data.qradar.api_version} on={(v) => setData({ ...data, qradar: { ...data.qradar, api_version: v } })} testId="qradar-version" />
                <TextField label="Domain ID (optional)" val={data.qradar.domain_id ?? ""} on={(v) => setData({ ...data, qradar: { ...data.qradar, domain_id: v ? parseInt(v) : null } })} testId="qradar-domain" />
                <TextField label="Processor ID (optional)" val={data.qradar.processor_id ?? ""} on={(v) => setData({ ...data, qradar: { ...data.qradar, processor_id: v ? parseInt(v) : null } })} testId="qradar-processor" />
              </div>
              <Toggle label="Verify SSL certificates" checked={data.qradar.verify_ssl} onChange={(v) => setData({ ...data, qradar: { ...data.qradar, verify_ssl: v } })} testId="qradar-ssl" />
              <button onClick={testQRadar} disabled={testing} data-testid="btn-test-qradar"
                className="border border-[#1F1F1F] hover:border-cyan-500 hover:text-cyan-400 px-4 py-2 text-xs font-mono uppercase tracking-widest text-neutral-300 inline-flex items-center gap-2">
                <TestTube2 className="w-3.5 h-3.5" /> {testing ? "Testing..." : "Test Connection"}
              </button>
            </div>
          )}

          {tab === "llm" && (
            <div className="space-y-4" data-testid="llm-settings">
              <SectionHeader title="Local LLM (Hugging Face)" hint="Runs offline on CPU. Model downloads on first use." />
              <div className="grid grid-cols-2 gap-4">
                <SelectField label="Provider" val={data.llm.provider} on={(v) => setData({ ...data, llm: { ...data.llm, provider: v } })} testId="llm-provider"
                  options={[{ value: "local", label: "HuggingFace (local)" }, { value: "ollama", label: "Ollama endpoint" }, { value: "huggingface", label: "HF Inference API" }]} />
                <TextField label="Model Name" val={data.llm.model_name} on={(v) => setData({ ...data, llm: { ...data.llm, model_name: v } })} testId="llm-model" />
              </div>
              <TextField label="Endpoint URL (Ollama / HF API)" val={data.llm.endpoint_url} on={(v) => setData({ ...data, llm: { ...data.llm, endpoint_url: v } })} testId="llm-endpoint" />
              <TextField label="API Token (optional)" val={data.llm.api_token} on={(v) => setData({ ...data, llm: { ...data.llm, api_token: v } })} type="password" testId="llm-token" />
              <div className="grid grid-cols-2 gap-4">
                <TextField label="Max Tokens" val={data.llm.max_tokens} on={(v) => setData({ ...data, llm: { ...data.llm, max_tokens: parseInt(v || "0") } })} testId="llm-max" />
                <TextField label="Temperature" val={data.llm.temperature} on={(v) => setData({ ...data, llm: { ...data.llm, temperature: parseFloat(v || "0") } })} testId="llm-temp" />
              </div>
              <Toggle label="Enable local LLM narrative augmentation" checked={data.llm.enable_llm} onChange={(v) => setData({ ...data, llm: { ...data.llm, enable_llm: v } })} testId="llm-enable" />
              <div className="text-[11px] font-mono text-neutral-500 border-l-2 border-cyan-500 pl-3 py-1">
                Rule-based SOC engine always runs. LLM augments the executive summary when enabled — first call may take several minutes to download the model.
              </div>
            </div>
          )}

          {tab === "threat_intel" && (
            <div className="space-y-6" data-testid="threat_intel-settings">
              <SectionHeader title="Threat Intelligence" hint="Live reputation lookups during AI investigation. Keys are redacted after save." />
              <div className="tactical-panel p-4 space-y-3">
                <div className="text-[10px] font-mono uppercase tracking-widest text-cyan-400">// VIRUSTOTAL</div>
                <Toggle label="Enable VirusTotal lookups for IPs, hashes, domains" checked={data.threat_intel.virustotal_enabled}
                  onChange={(v) => setData({ ...data, threat_intel: { ...data.threat_intel, virustotal_enabled: v } })} testId="ti-vt-enable" />
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <div className="tg-label">VirusTotal API Keys (one per line — auto-rotated with failover on 429/401)</div>
                    {data.threat_intel.virustotal_api_keys_count > 0 && (
                      <button type="button"
                              onClick={() => setData({ ...data, threat_intel: { ...data.threat_intel, virustotal_api_keys: "__CLEAR__" } })}
                              data-testid="ti-vt-keys-clear"
                              className="tg-btn tg-btn-danger" style={{ padding: "3px 8px" }}>
                        Clear saved
                      </button>
                    )}
                  </div>
                  <textarea rows={4} value={data.threat_intel.virustotal_api_keys === "__CLEAR__" ? "" : (data.threat_intel.virustotal_api_keys || "")}
                    placeholder={data.threat_intel.virustotal_api_keys === "__CLEAR__"
                      ? "Saved keys will be removed on Save."
                      : data.threat_intel.virustotal_api_keys_count
                        ? `${data.threat_intel.virustotal_api_keys_count} key(s) saved — paste again to replace, leave blank to keep`
                        : "paste one API key per line…"}
                    onChange={(e) => setData({ ...data, threat_intel: { ...data.threat_intel, virustotal_api_keys: e.target.value } })}
                    data-testid="ti-vt-keys"
                    className="w-full text-sm font-mono px-3 py-2 rounded-md focus:outline-none"
                    style={{ background: "var(--tg-surface-2)", border: "1px solid var(--tg-border)", color: "var(--tg-text)" }} />
                  {data.threat_intel.virustotal_api_keys_masked && data.threat_intel.virustotal_api_keys_masked.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2" data-testid="ti-vt-keys-saved">
                      {data.threat_intel.virustotal_api_keys_masked.map((m, i) => (
                        <span key={i} className="tg-model">{m}</span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="text-[11px]" style={{ color: "var(--tg-text-muted)" }}>
                  Legacy single-key field (kept for back-compat) — new deployments should use the list above:
                </div>
                <TextField label="VirusTotal API Key (legacy single)" val={data.threat_intel.virustotal_api_key}
                  on={(v) => setData({ ...data, threat_intel: { ...data.threat_intel, virustotal_api_key: v } })} type="password" testId="ti-vt-key" />
                {data.threat_intel.virustotal_api_key_masked && (
                  <div className="text-[10px] font-mono uppercase tracking-widest" style={{ color: "var(--tg-cyan)" }}>Saved: {data.threat_intel.virustotal_api_key_masked}</div>
                )}
              </div>
              <div className="tactical-panel p-4 space-y-3">
                <div className="text-[10px] font-mono uppercase tracking-widest text-cyan-400">// ABUSEIPDB</div>
                <Toggle label="Enable AbuseIPDB reputation for external IPs" checked={data.threat_intel.abuseipdb_enabled}
                  onChange={(v) => setData({ ...data, threat_intel: { ...data.threat_intel, abuseipdb_enabled: v } })} testId="ti-abuse-enable" />
                <TextField label="AbuseIPDB API Key" val={data.threat_intel.abuseipdb_api_key}
                  on={(v) => setData({ ...data, threat_intel: { ...data.threat_intel, abuseipdb_api_key: v } })} type="password" testId="ti-abuse-key" />
                {data.threat_intel.abuseipdb_api_key_masked && (
                  <div className="text-[10px] font-mono text-emerald-400 uppercase tracking-widest">Saved: {data.threat_intel.abuseipdb_api_key_masked}</div>
                )}
              </div>
              <div className="tactical-panel p-4 space-y-3">
                <div className="text-[10px] font-mono uppercase tracking-widest text-cyan-400">// MISP</div>
                <Toggle label="Enable MISP correlation" checked={data.threat_intel.misp_enabled}
                  onChange={(v) => setData({ ...data, threat_intel: { ...data.threat_intel, misp_enabled: v } })} testId="ti-misp-enable" />
                <TextField label="MISP URL (e.g. https://misp.acme.local)" val={data.threat_intel.misp_url}
                  on={(v) => setData({ ...data, threat_intel: { ...data.threat_intel, misp_url: v } })} testId="ti-misp-url" />
                <TextField label="MISP API Key" val={data.threat_intel.misp_api_key}
                  on={(v) => setData({ ...data, threat_intel: { ...data.threat_intel, misp_api_key: v } })} type="password" testId="ti-misp-key" />
                {data.threat_intel.misp_api_key_masked && (
                  <div className="text-[10px] font-mono text-emerald-400 uppercase tracking-widest">Saved: {data.threat_intel.misp_api_key_masked}</div>
                )}
                <Toggle label="Verify SSL certificate" checked={data.threat_intel.misp_verify_ssl}
                  onChange={(v) => setData({ ...data, threat_intel: { ...data.threat_intel, misp_verify_ssl: v } })} testId="ti-misp-ssl" />
              </div>
              <div className="text-[11px] font-mono text-neutral-500 border-l-2 border-cyan-500 pl-3 py-1">
                Enrichment runs during "Run AI Investigation". Malicious verdicts add up to +25 to the risk score and are surfaced in the AI Analysis tab.
              </div>
            </div>
          )}

          {["xsoar", "servicenow", "jira", "freshservice", "slack", "teams", "email"].includes(tab) && (
            <IntegrationForm
              tab={tab}
              data={data[tab]}
              onChange={(v) => setData({ ...data, [tab]: v })}
            />
          )}
        </div>
      </div>
    </div>
  );
}

const SectionHeader = ({ title, hint }) => (
  <div>
    <h2 className="font-display text-xl">{title}</h2>
    <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 mt-1">{hint}</div>
  </div>
);

const TextField = ({ label, val, on, type = "text", testId }) => (
  <div>
    <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">{label}</div>
    <input value={val ?? ""} onChange={(e) => on(e.target.value)} type={type} data-testid={testId}
      className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
  </div>
);

const SelectField = ({ label, val, on, options, testId }) => (
  <div>
    <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">{label}</div>
    <select value={val} onChange={(e) => on(e.target.value)} data-testid={testId}
      className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2">
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  </div>
);

const Toggle = ({ label, checked, onChange, testId }) => (
  <label className="flex items-center gap-3 cursor-pointer" data-testid={testId}>
    <div className={`w-10 h-5 relative border ${checked ? "border-cyan-500 bg-cyan-500/20" : "border-[#1F1F1F] bg-[#050505]"}`}>
      <div className={`w-4 h-4 absolute top-0.5 transition-all ${checked ? "left-5 bg-cyan-400" : "left-0.5 bg-neutral-600"}`} />
    </div>
    <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="sr-only" />
    <span className="text-sm text-neutral-300 font-mono">{label}</span>
  </label>
);

const IntegrationForm = ({ tab, data, onChange }) => {
  const titles = {
    xsoar: "Cortex XSOAR", servicenow: "ServiceNow", jira: "Jira", freshservice: "Freshservice",
    slack: "Slack", teams: "Microsoft Teams", email: "Email (SMTP)"
  };
  const hints = {
    xsoar: "Palo Alto XSOAR incidents endpoint + API key",
    servicenow: "ServiceNow instance URL + basic auth or OAuth",
    jira: "Cloud Jira URL + API token, project key",
    freshservice: "Freshservice domain + API key",
    slack: "Incoming Webhook URL for notifications",
    teams: "Teams incoming webhook",
    email: "SMTP server + credentials",
  };
  return (
    <div className="space-y-4" data-testid={`${tab}-settings`}>
      <SectionHeader title={titles[tab]} hint={hints[tab]} />
      <Toggle label="Enable integration" checked={data.enabled} onChange={(v) => onChange({ ...data, enabled: v })} testId={`${tab}-enable`} />
      <TextField label="URL / Instance / Webhook" val={data.url} on={(v) => onChange({ ...data, url: v })} testId={`${tab}-url`} />
      <div className="grid grid-cols-2 gap-4">
        <TextField label="Username / Email" val={data.username} on={(v) => onChange({ ...data, username: v })} testId={`${tab}-username`} />
        <TextField label="API Token / Password" val={data.token} on={(v) => onChange({ ...data, token: v })} type="password" testId={`${tab}-token`} />
      </div>
      {(tab === "jira" || tab === "servicenow") && (
        <TextField label="Project / Table Key" val={data.project_key} on={(v) => onChange({ ...data, project_key: v })} testId={`${tab}-project`} />
      )}
      <div className="text-[11px] font-mono text-neutral-500 border-l-2 border-cyan-500 pl-3 py-1">
        Integration is a UI stub. Tickets pushed here will be marked with mock reference IDs for demonstration.
      </div>
    </div>
  );
};
