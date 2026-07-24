import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "sonner";
import { AuthProvider, useAuth } from "@/lib/auth";
import { ClientProvider } from "@/lib/clients";
import { ThemeProvider } from "@/lib/theme";
import { Layout } from "@/components/Layout";
import LoginPage from "@/pages/LoginPage";
import DashboardPage from "@/pages/DashboardPage";
import OffensesPage from "@/pages/OffensesPage";
import OffenseDetailPage from "@/pages/OffenseDetailPage";
import KnowledgeBasePage from "@/pages/KnowledgeBasePage";
import ClientsPage from "@/pages/ClientsPage";
import SettingsPage from "@/pages/SettingsPage";
import UsersPage from "@/pages/UsersPage";
import AuditPage from "@/pages/AuditPage";
import TicketsPage from "@/pages/TicketsPage";
import CoachPage from "@/pages/CoachPage";
import "@/App.css";

const Protected = ({ children }) => {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
};

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <ThemeProvider>
          <AuthProvider>
            <ClientProvider>
            <Toaster theme="dark" position="top-right" toastOptions={{
              style: { background: "#0A0A0A", border: "1px solid #1F1F1F", color: "#F3F4F6", fontFamily: "'JetBrains Mono', monospace", fontSize: 12 },
            }} />
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/" element={<Protected><DashboardPage /></Protected>} />
              <Route path="/offenses" element={<Protected><OffensesPage /></Protected>} />
              <Route path="/offenses/:id" element={<Protected><OffenseDetailPage /></Protected>} />
              <Route path="/tickets" element={<Protected><TicketsPage /></Protected>} />
              <Route path="/coach" element={<Protected><CoachPage /></Protected>} />
              <Route path="/knowledge-base" element={<Protected><KnowledgeBasePage /></Protected>} />
              <Route path="/clients" element={<Protected><ClientsPage /></Protected>} />
              <Route path="/users" element={<Protected><UsersPage /></Protected>} />
              <Route path="/settings" element={<Protected><SettingsPage /></Protected>} />
              <Route path="/audit" element={<Protected><AuditPage /></Protected>} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </ClientProvider>
        </AuthProvider>
        </ThemeProvider>
      </BrowserRouter>
    </div>
  );
}

export default App;
