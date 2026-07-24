import { createContext, useContext, useEffect, useState } from "react";
import api from "@/lib/api";

const ClientCtx = createContext(null);

export const ClientProvider = ({ children }) => {
  const [clients, setClients] = useState([]);
  const [activeClientId, setActiveClientId] = useState(
    () => localStorage.getItem("socpilot_active_client") || ""
  );

  const refresh = async () => {
    if (!localStorage.getItem("socpilot_token")) return;
    try {
      const r = await api.get("/clients");
      setClients(r.data || []);
      if (!activeClientId && r.data?.length) {
        const first = r.data[0].id;
        setActiveClientId(first);
        localStorage.setItem("socpilot_active_client", first);
      }
    } catch (e) {}
  };

  useEffect(() => {
    refresh();
    const handler = () => refresh();
    window.addEventListener("socpilot_login", handler);
    return () => window.removeEventListener("socpilot_login", handler);
    /* eslint-disable-next-line */
  }, []);

  const setActive = (id) => {
    setActiveClientId(id);
    localStorage.setItem("socpilot_active_client", id);
  };

  return (
    <ClientCtx.Provider value={{ clients, activeClientId, setActive, refresh }}>
      {children}
    </ClientCtx.Provider>
  );
};

export const useClients = () => useContext(ClientCtx);
