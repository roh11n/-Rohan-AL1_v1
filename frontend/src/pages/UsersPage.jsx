import { useEffect, useState } from "react";
import api from "@/lib/api";
import { toast } from "sonner";
import { Plus, Trash2, User as UserIcon } from "lucide-react";

const ROLES = ["Admin", "SOC Manager", "L1", "L2", "L3", "ReadOnly"];

export default function UsersPage() {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ email: "", name: "", password: "", role: "L1" });
  const [creating, setCreating] = useState(false);

  const load = async () => {
    const r = await api.get("/users");
    setUsers(r.data || []);
  };
  useEffect(() => { load(); }, []);

  const create = async (e) => {
    e.preventDefault();
    setCreating(true);
    try {
      await api.post("/users", form);
      toast.success("User created");
      setForm({ email: "", name: "", password: "", role: "L1" });
      load();
    } catch (e) { toast.error(e?.response?.data?.detail || "Create failed"); }
    finally { setCreating(false); }
  };

  const del = async (id) => {
    if (!window.confirm("Delete user?")) return;
    await api.delete(`/users/${id}`);
    toast.success("Deleted");
    load();
  };

  const toggleActive = async (u) => {
    await api.put(`/users/${u.id}`, { active: !u.active });
    load();
  };

  return (
    <div className="space-y-5" data-testid="users-page">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// ACCESS CONTROL</div>
        <h1 className="font-display text-3xl mt-1">Users & RBAC</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <form onSubmit={create} className="tactical-panel p-5 space-y-3" data-testid="user-form">
          <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500">// NEW USER</div>
          <Field label="Email" val={form.email} on={(v) => setForm({ ...form, email: v })} testId="user-email" />
          <Field label="Full Name" val={form.name} on={(v) => setForm({ ...form, name: v })} testId="user-name" />
          <Field label="Password" val={form.password} on={(v) => setForm({ ...form, password: v })} type="password" testId="user-password" />
          <div>
            <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">Role</div>
            <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} data-testid="user-role"
              className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2">
              {ROLES.map((r) => <option key={r}>{r}</option>)}
            </select>
          </div>
          <button type="submit" disabled={creating} data-testid="btn-create-user"
            className="w-full bg-cyan-400 hover:bg-cyan-300 text-black py-2 text-xs font-mono uppercase tracking-widest font-bold inline-flex items-center justify-center gap-2 disabled:opacity-50">
            <Plus className="w-3.5 h-3.5" /> Create User
          </button>
        </form>

        <div className="lg:col-span-2 tactical-panel overflow-hidden">
          <table className="w-full text-sm">
            <thead className="text-[10px] font-mono uppercase text-neutral-500 tracking-widest border-b border-[#1F1F1F] bg-[#080808]">
              <tr>
                <th className="text-left px-3 py-2">Email</th>
                <th className="text-left px-3 py-2">Name</th>
                <th className="text-left px-3 py-2">Role</th>
                <th className="text-left px-3 py-2">Active</th>
                <th className="text-left px-3 py-2">Created</th>
                <th className="text-right px-3 py-2">Actions</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {users.map((u) => (
                <tr key={u.id} className="border-b border-[#0F0F0F] hover:bg-[#111]" data-testid={`user-row-${u.email}`}>
                  <td className="px-3 py-2 text-neutral-200 inline-flex items-center gap-2"><UserIcon className="w-3 h-3 text-cyan-400" />{u.email}</td>
                  <td className="px-3 py-2 text-neutral-400 text-xs">{u.name}</td>
                  <td className="px-3 py-2"><span className="px-2 py-0.5 border border-cyan-500 text-cyan-400 text-[10px] uppercase tracking-widest">{u.role}</span></td>
                  <td className="px-3 py-2">
                    <button onClick={() => toggleActive(u)} data-testid={`toggle-active-${u.email}`}
                      className={`text-[10px] font-mono uppercase tracking-widest ${u.active ? "text-emerald-400" : "text-neutral-500"}`}>
                      {u.active ? "● ACTIVE" : "○ DISABLED"}
                    </button>
                  </td>
                  <td className="px-3 py-2 text-neutral-500 text-xs">{new Date(u.created_at).toLocaleDateString()}</td>
                  <td className="px-3 py-2 text-right">
                    <button onClick={() => del(u.id)} data-testid={`del-user-${u.email}`} className="text-neutral-500 hover:text-rose-400">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

const Field = ({ label, val, on, type = "text", testId }) => (
  <div>
    <div className="text-[10px] font-mono uppercase text-neutral-500 mb-1">{label}</div>
    <input value={val} onChange={(e) => on(e.target.value)} type={type} data-testid={testId} required
      className="w-full bg-[#050505] border border-[#1F1F1F] focus:border-cyan-500 focus:outline-none text-sm font-mono px-3 py-2" />
  </div>
);
