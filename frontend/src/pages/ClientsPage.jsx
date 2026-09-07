import { useEffect, useState } from "react";
import api from "@/lib/api";
import { useClients } from "@/lib/clients";
import { toast } from "sonner";
import { Plus, Trash2, Building2 } from "lucide-react";

export default function ClientsPage() {
  const { clients, refresh } = useClients();
  const [form, setForm] = useState({ name: "", code: "", industry: "", contact_email: "", description: "" });
  const [creating, setCreating] = useState(false);

  useEffect(() => { refresh(); /* eslint-disable-next-line */ }, []);

  const submit = async (e) => {
    e.preventDefault();
    setCreating(true);
    try {
      await api.post("/clients", form);
      toast.success("Client created");
      setForm({ name: "", code: "", industry: "", contact_email: "", description: "" });
      refresh();
    } catch (e) { toast.error(e?.response?.data?.detail || "Create failed"); }
    finally { setCreating(false); }
  };

  const del = async (id) => {
    if (!window.confirm("Delete client and ALL its offenses/KB?")) return;
    try {
      await api.delete(`/clients/${id}`);
      toast.success("Deleted");
      refresh();
    } catch (e) { toast.error(e?.response?.data?.detail || "Delete failed"); }
  };

  return (
    <div className="space-y-5" data-testid="clients-page">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// MULTI-TENANT</div>
        <h1 className="font-display text-3xl mt-1">Clients / Tenants</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <form onSubmit={submit} className="tactical-panel p-5 space-y-3" data-testid="client-form">
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// NEW CLIENT</div>
          <Field label="Name" val={form.name} on={(v) => setForm({ ...form, name: v })} testId="client-name" />
          <Field label="Code" val={form.code} on={(v) => setForm({ ...form, code: v.toUpperCase() })} testId="client-code" />
          <Field label="Industry" val={form.industry} on={(v) => setForm({ ...form, industry: v })} testId="client-industry" />
          <Field label="Contact Email" val={form.contact_email} on={(v) => setForm({ ...form, contact_email: v })} testId="client-contact" />
          <Field label="Description" val={form.description} on={(v) => setForm({ ...form, description: v })} testId="client-desc" />
          <button type="submit" disabled={creating} data-testid="btn-create-client"
            className="w-full bg-cyan-400 hover:bg-cyan-300 text-black py-2 text-xs font-mono uppercase tracking-widest font-bold inline-flex items-center justify-center gap-2 disabled:opacity-50">
            <Plus className="w-3.5 h-3.5" /> Create Client
          </button>
        </form>

        <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4 stagger">
          {clients.map((c) => (
            <div key={c.id} className="tactical-panel p-5 relative" data-testid={`client-card-${c.id}`}>
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Building2 className="w-4 h-4 text-cyan-400" strokeWidth={1.5} />
                    <div className="font-mono text-xs uppercase tracking-widest text-cyan-400">{c.code}</div>
                  </div>
                  <h3 className="font-display text-xl mt-1">{c.name}</h3>
                  <div className="text-xs font-mono text-neutral-500 mt-1">{c.industry}</div>
                </div>
                <button onClick={() => del(c.id)} data-testid={`del-client-${c.id}`} className="text-neutral-500 hover:text-rose-400">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
              <p className="text-neutral-400 text-sm mt-3 leading-relaxed">{c.description}</p>
              <div className="mt-3 text-[10px] font-mono uppercase tracking-widest text-neutral-500">
                CONTACT · <span className="text-neutral-300 normal-case">{c.contact_email || "—"}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

const Field = ({ label, val, on, testId }) => (
  <div>
    <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">{label}</div>
    <input value={val} onChange={(e) => on(e.target.value)} data-testid={testId}
      className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
  </div>
);
