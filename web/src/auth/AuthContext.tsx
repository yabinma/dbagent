import React, { createContext, useContext, useMemo, useState } from "react";
import { ApiClient } from "../api/client";

type AuthState = {
  token: string | null;
  role: string | null;
  mustChangePassword: boolean;
  login: (u: string, p: string) => Promise<void>;
  logout: () => void;
  clearMustChange: () => void;
  api: ApiClient;
};

const AuthCtx = createContext<AuthState | null>(null);
const TOKEN_KEY = "rca_dashboard_token";
const ROLE_KEY = "rca_dashboard_role";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(
    () => localStorage.getItem(TOKEN_KEY)
  );
  const [role, setRole] = useState<string | null>(
    () => localStorage.getItem(ROLE_KEY)
  );
  const [mustChangePassword, setMustChange] = useState(false);

  const api = useMemo(
    () => new ApiClient(() => token),
    [token]
  );

  const value: AuthState = {
    token,
    role,
    mustChangePassword,
    api,
    async login(username, password) {
      const res = await api.login(username, password);
      setToken(res.token);
      setRole(res.role);
      setMustChange(!!res.must_change_password);
      localStorage.setItem(TOKEN_KEY, res.token);
      localStorage.setItem(ROLE_KEY, res.role);
    },
    logout() {
      setToken(null);
      setRole(null);
      setMustChange(false);
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(ROLE_KEY);
    },
    clearMustChange() {
      setMustChange(false);
    },
  };

  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

export function roleAtLeast(role: string | null, min: string): boolean {
  const rank: Record<string, number> = { viewer: 1, approver: 2, admin: 3 };
  return (rank[role || ""] || 0) >= (rank[min] || 99);
}
