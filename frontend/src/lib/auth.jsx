import { createContext, useContext, useEffect, useState } from "react";
import api from "@/lib/api";

const AuthCtx = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem("socpilot_user");
    return raw ? JSON.parse(raw) : null;
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (localStorage.getItem("socpilot_token") && !user) {
      api.get("/auth/me").then((r) => {
        setUser(r.data);
        localStorage.setItem("socpilot_user", JSON.stringify(r.data));
      }).catch(() => {});
    }
  // eslint-disable-next-line
  }, []);

  const login = async (email, password) => {
    setLoading(true);
    try {
      const r = await api.post("/auth/login", { email, password });
      localStorage.setItem("socpilot_token", r.data.access_token);
      localStorage.setItem("socpilot_user", JSON.stringify(r.data.user));
      setUser(r.data.user);
      window.dispatchEvent(new Event("socpilot_login"));
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e?.response?.data?.detail || "Login failed" };
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem("socpilot_token");
    localStorage.removeItem("socpilot_user");
    setUser(null);
    window.location.href = "/login";
  };

  return (
    <AuthCtx.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthCtx.Provider>
  );
};

export const useAuth = () => useContext(AuthCtx);

export const hasRole = (user, allowed) => {
  if (!user) return false;
  return allowed.includes(user.role);
};
