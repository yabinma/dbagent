import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { AuthProvider } from "./auth/AuthContext";

function renderApp(route: string) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe("App routing + role-gated navigation", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    localStorage.clear();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    // Default: empty list endpoints succeed
    fetchMock.mockImplementation(async (url: string) => {
      const path = String(url);
      if (path.includes("/metrics/summary")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({
            open_cases: 2,
            pending_approvals: 1,
            closed_in_window: 0,
            avg_rounds: 1.5,
            avg_cost_usd: 0.2,
          }),
        };
      }
      if (path.includes("/investigations/") && path.includes("/iterations")) {
        return { status: 200, ok: true, json: async () => ({ items: [] }) };
      }
      if (path.includes("/llm-calls")) {
        return { status: 200, ok: true, json: async () => ({ items: [] }) };
      }
      if (path.includes("/investigations/") && !path.endsWith("/investigations")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({
            investigation_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            platform_key: "presto-us1",
            status: "OPEN",
            severity: "high",
            created_at: null,
            rca_compact: "oom",
            spent: { rounds: 1, cost_usd: 0.1 },
            budget: {},
            rca_report: { root_cause: { summary: "oom" } },
            related_events: [],
            executions: [],
          }),
        };
      }
      if (path.includes("/investigations")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({
            items: [
              {
                investigation_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                platform_key: "presto-us1",
                status: "OPEN",
                severity: "high",
                created_at: null,
                rca_compact: "oom",
                spent: { cost_usd: 0.1 },
                budget: {},
              },
            ],
          }),
        };
      }
      if (path.includes("/approvals")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({
            items: [
              {
                approval_id: "appr-1",
                investigation_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                kind: "raw_command",
                subject: { command: "cat /x" },
                age_seconds: 5,
                created_at: null,
              },
            ],
          }),
        };
      }
      if (path.includes("/platforms")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({
            items: [
              {
                platform_key: "presto-us1",
                status: "pending_credentials",
                deployment: "k8s",
                bootstrap_ca_fingerprint: "sha256:abc",
                credential_guidance: "mount secret",
              },
            ],
          }),
        };
      }
      return { status: 200, ok: true, json: async () => ({}) };
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("redirects unauthenticated users to /login", async () => {
    renderApp("/");
    await waitFor(() => expect(screen.getByText("Sign in")).toBeInTheDocument());
  });

  it("viewer sees Overview/Cases but not Approvals/Admin", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "viewer");
    renderApp("/");
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument()
    );
    expect(screen.getByRole("link", { name: "Cases" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Approvals" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Admin" })).toBeNull();
    await waitFor(() =>
      expect(screen.getByText(/Open cases:/)).toHaveTextContent("2")
    );
  });

  it("approver sees Approvals link and can open queue", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "approver");
    renderApp("/approvals");
    await waitFor(() =>
      expect(screen.getByText("Approval queue")).toBeInTheDocument()
    );
    expect(await screen.findByTestId("approval-card")).toBeInTheDocument();
    expect(screen.getByText("Approvals")).toBeInTheDocument();
  });

  it("admin can open Admin page with bootstrap + pending guidance", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "admin");
    renderApp("/admin");
    await waitFor(() =>
      expect(screen.getByText("Administration")).toBeInTheDocument()
    );
    expect(screen.getByTestId("ca-fingerprint")).toHaveTextContent("sha256:abc");
    expect(screen.getByTestId("pending-credentials-guide")).toHaveTextContent(
      "presto-us1"
    );
  });

  it("viewer is redirected away from /admin", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "viewer");
    renderApp("/admin");
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument()
    );
    expect(screen.queryByText("Administration")).toBeNull();
  });

  it("renders Cases list", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "viewer");
    renderApp("/cases");
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Cases" })).toBeInTheDocument()
    );
    await waitFor(() => expect(screen.getByText("presto-us1")).toBeInTheDocument());
  });

  it("renders Case detail with timeline + LLM traces", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "viewer");
    renderApp("/cases/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    await waitFor(() =>
      expect(screen.getByTestId("llm-trace-viewer")).toBeInTheDocument()
    );
    expect(screen.getByTestId("round-timeline")).toBeInTheDocument();
    expect(screen.getByTestId("rca-panel")).toBeInTheDocument();
  });

  it("forces password change after login with must_change_password", async () => {
    fetchMock.mockImplementation(async (url: string) => {
      if (String(url).includes("/auth/login")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({
            token: "new",
            role: "admin",
            expires_at: "x",
            must_change_password: true,
          }),
        };
      }
      return { status: 200, ok: true, json: async () => ({}) };
    });
    renderApp("/login");
    await waitFor(() => expect(screen.getByText("Sign in")).toBeInTheDocument());
    const inputs = document.querySelectorAll("input");
    fireEvent.change(inputs[0], { target: { value: "admin" } });
    fireEvent.change(inputs[1], { target: { value: "password-long" } });
    fireEvent.click(screen.getByRole("button", { name: /login/i }));
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Change password" })).toBeInTheDocument()
    );
  });

  it("logout clears session and returns to login", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "admin");
    renderApp("/");
    await waitFor(() => expect(screen.getByText("Logout")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Logout"));
    await waitFor(() => expect(screen.getByText("Sign in")).toBeInTheDocument());
  });
});
