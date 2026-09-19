import { Navigate, Route, Routes, Link } from "react-router-dom";
import { roleAtLeast, useAuth } from "./auth/AuthContext";
import { LoginPage } from "./pages/LoginPage";
import { ChangePasswordPage } from "./pages/ChangePasswordPage";
import { OverviewPage } from "./pages/OverviewPage";
import { CasesPage } from "./pages/CasesPage";
import { CaseDetailPage } from "./pages/CaseDetailPage";
import { ApprovalQueuePage } from "./pages/ApprovalQueuePage";
import { AdminPage } from "./pages/AdminPage";

function Shell({ children }: { children: React.ReactNode }) {
  const { role, logout } = useAuth();
  return (
    <div className="layout">
      <nav className="nav">
        <strong>RCA Dashboard</strong>
        <Link to="/">Overview</Link>
        <Link to="/cases">Cases</Link>
        {roleAtLeast(role, "approver") && (
          <Link to="/approvals">Approvals</Link>
        )}
        {roleAtLeast(role, "admin") && <Link to="/admin">Admin</Link>}
        <button className="btn" style={{ marginTop: "1rem" }} onClick={logout}>
          Logout
        </button>
      </nav>
      <main className="main">{children}</main>
    </div>
  );
}

function RequireAuth({
  children,
  minRole = "viewer",
}: {
  children: React.ReactNode;
  minRole?: string;
}) {
  const { token, role, mustChangePassword } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  if (mustChangePassword) return <Navigate to="/change-password" replace />;
  if (!roleAtLeast(role, minRole)) return <Navigate to="/" replace />;
  return <Shell>{children}</Shell>;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/change-password" element={<ChangePasswordPage />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <OverviewPage />
          </RequireAuth>
        }
      />
      <Route
        path="/cases"
        element={
          <RequireAuth>
            <CasesPage />
          </RequireAuth>
        }
      />
      <Route
        path="/cases/:id"
        element={
          <RequireAuth>
            <CaseDetailPage />
          </RequireAuth>
        }
      />
      <Route
        path="/approvals"
        element={
          <RequireAuth minRole="approver">
            <ApprovalQueuePage />
          </RequireAuth>
        }
      />
      <Route
        path="/admin"
        element={
          <RequireAuth minRole="admin">
            <AdminPage />
          </RequireAuth>
        }
      />
    </Routes>
  );
}
