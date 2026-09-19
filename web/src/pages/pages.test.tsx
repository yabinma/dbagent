import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "../auth/AuthContext";
import { LoginPage } from "./LoginPage";
import { ChangePasswordPage } from "./ChangePasswordPage";
import { OverviewPage } from "./OverviewPage";
import { CasesPage } from "./CasesPage";
import { CaseDetailPage } from "./CaseDetailPage";
import { ApprovalQueuePage } from "./ApprovalQueuePage";
import { AdminPage } from "./AdminPage";
import { RoundTimeline } from "../components/RoundTimeline";

describe("pages (FP-M4-15 / FP-M4-16)", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    localStorage.clear();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it("LoginPage submits credentials and surfaces errors", async () => {
    fetchMock.mockResolvedValueOnce({
      status: 401,
      ok: false,
      statusText: "Unauthorized",
      json: async () => ({
        error: { code: "unauthorized", message: "bad credentials" },
      }),
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>
    );
    const inputs = document.querySelectorAll("input");
    fireEvent.change(inputs[0], { target: { value: "admin" } });
    fireEvent.change(inputs[1], { target: { value: "wrong" } });
    fireEvent.click(screen.getByRole("button", { name: /login/i }));
    await waitFor(() =>
      expect(screen.getByText("bad credentials")).toBeInTheDocument()
    );

    fetchMock.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({
        token: "t",
        role: "admin",
        expires_at: "x",
        must_change_password: false,
      }),
    });
    fireEvent.click(screen.getByRole("button", { name: /login/i }));
    await waitFor(() =>
      expect(localStorage.getItem("rca_dashboard_token")).toBe("t")
    );
  });

  it("LoginPage redirects when already authenticated", () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "viewer");
    render(
      <MemoryRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>
    );
    // Navigate to / replaces content; Login form should not stay
    expect(screen.queryByText("Sign in")).toBeNull();
  });

  it("ChangePasswordPage requires token and handles success/error", async () => {
    // no token → redirect
    render(
      <MemoryRouter>
        <AuthProvider>
          <ChangePasswordPage />
        </AuthProvider>
      </MemoryRouter>
    );
    expect(screen.queryByText("Change password")).toBeNull();

    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "admin");
    fetchMock.mockResolvedValueOnce({
      status: 400,
      ok: false,
      statusText: "Bad",
      json: async () => ({
        error: { code: "bad_request", message: "too short" },
      }),
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <ChangePasswordPage />
        </AuthProvider>
      </MemoryRouter>
    );
    expect(screen.getByText("Change password")).toBeInTheDocument();
    const inputs = document.querySelectorAll("input");
    fireEvent.change(inputs[0], { target: { value: "old" } });
    fireEvent.change(inputs[1], { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: /update/i }));
    await waitFor(() => expect(screen.getByText("too short")).toBeInTheDocument());

    fetchMock.mockResolvedValueOnce({ status: 204, ok: true, json: async () => ({}) });
    fireEvent.click(screen.getByRole("button", { name: /update/i }));
    await waitFor(() => expect(screen.queryByText("Change password")).toBeNull());
  });

  it("OverviewPage loads metrics and handles failure", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "viewer");
    fetchMock.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({
        open_cases: 3,
        pending_approvals: 2,
        closed_in_window: 1,
        avg_rounds: 2,
        avg_cost_usd: 0.5,
      }),
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <OverviewPage />
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() =>
      expect(screen.getByText(/Open cases:/)).toHaveTextContent("3")
    );

    fetchMock.mockResolvedValueOnce({
      status: 500,
      ok: false,
      statusText: "err",
      json: async () => ({}),
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <OverviewPage />
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() =>
      expect(screen.getAllByText(/Loading metrics/).length).toBeGreaterThan(0)
    );
  });

  it("CasesPage lists investigations and handles empty error path", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "viewer");
    fetchMock.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({
        items: [
          {
            investigation_id: "11111111-1111-1111-1111-111111111111",
            platform_key: "p1",
            status: "OPEN",
            severity: "high",
            created_at: null,
            rca_compact: null,
            spent: {},
            budget: {},
          },
        ],
      }),
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <CasesPage />
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("p1")).toBeInTheDocument());
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("CaseDetailPage loads detail, timeline, and LLM traces", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "viewer");
    fetchMock.mockImplementation(async (url: string) => {
      const u = String(url);
      if (u.includes("/iterations")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({
            items: [
              {
                round: 1,
                plan: {},
                rca_output: null,
                cost_usd: 0.1,
                duration_ms: 12,
                evidence: [
                  {
                    evidence_id: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
                    tool_name: "presto_cluster_info",
                    summary: "ok",
                  },
                ],
              },
            ],
          }),
        };
      }
      if (u.includes("/llm-calls")) {
        return {
          status: 200,
          ok: true,
          json: async () => ({
            items: [
              {
                call_id: "c1",
                agent_role: "rca",
                model: "gpt",
                cost_usd: 0.01,
                latency_ms: 40,
              },
            ],
          }),
        };
      }
      return {
        status: 200,
        ok: true,
        json: async () => ({
          investigation_id: "22222222-2222-2222-2222-222222222222",
          platform_key: "presto-us1",
          status: "OPEN",
          severity: "high",
          created_at: null,
          rca_compact: "compact",
          spent: { rounds: 2, cost_usd: 0.2 },
          budget: {},
          rca_report: { root_cause: { summary: "full" } },
          related_events: [],
          executions: [],
        }),
      };
    });
    render(
      <MemoryRouter initialEntries={["/cases/22222222-2222-2222-2222-222222222222"]}>
        <AuthProvider>
          <Routes>
            <Route path="/cases/:id" element={<CaseDetailPage />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() =>
      expect(screen.getByTestId("llm-trace-viewer")).toHaveTextContent("rca")
    );
    expect(screen.getByTestId("round-timeline")).toHaveTextContent("Round 1");
    expect(screen.getByTestId("round-timeline")).toHaveTextContent(
      "presto_cluster_info"
    );
  });

  it("CaseDetailPage shows Loading when fetch fails", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "viewer");
    fetchMock.mockResolvedValue({
      status: 404,
      ok: false,
      statusText: "nf",
      json: async () => ({ error: { code: "not_found", message: "gone" } }),
    });
    render(
      <MemoryRouter initialEntries={["/cases/missing"]}>
        <AuthProvider>
          <Routes>
            <Route path="/cases/:id" element={<CaseDetailPage />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Loading…")).toBeInTheDocument());
  });

  it("ApprovalQueuePage lists cards, decides, and reloads", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "approver");
    let n = 0;
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      const u = String(url);
      if (u.includes("/decision")) {
        return { status: 204, ok: true, json: async () => ({}) };
      }
      if (u.includes("/approvals")) {
        n += 1;
        if (n > 1) {
          return { status: 200, ok: true, json: async () => ({ items: [] }) };
        }
        return {
          status: 200,
          ok: true,
          json: async () => ({
            items: [
              {
                approval_id: "ap1",
                investigation_id: "inv1xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                kind: "remediation",
                subject: { action: "restart" },
                age_seconds: 3,
                created_at: null,
              },
            ],
          }),
        };
      }
      return { status: 200, ok: true, json: async () => ({}) };
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <ApprovalQueuePage />
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() =>
      expect(screen.getByTestId("approval-card")).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId("approve-btn"));
    await waitFor(() =>
      expect(screen.getByText("No pending approvals.")).toBeInTheDocument()
    );
  });

  it("AdminPage lists platforms and default credential guidance", async () => {
    localStorage.setItem("rca_dashboard_token", "t");
    localStorage.setItem("rca_dashboard_role", "admin");
    fetchMock.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({
        items: [
          {
            platform_key: "p-pending",
            status: "pending_credentials",
            deployment: "swarm",
          },
          {
            platform_key: "p-online",
            status: "online",
            deployment: "k8s",
            bootstrap_ca_fingerprint: "sha256:fp",
          },
        ],
      }),
    });
    render(
      <MemoryRouter>
        <AuthProvider>
          <AdminPage />
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() =>
      expect(screen.getByTestId("pending-credentials-guide")).toHaveTextContent(
        "p-pending"
      )
    );
    expect(screen.getByTestId("pending-credentials-guide")).toHaveTextContent(
      "platform-credentials"
    );
    expect(screen.getByTestId("ca-fingerprint")).toHaveTextContent("sha256:fp");
    expect(screen.getByText("p-online")).toBeInTheDocument();
  });
});

describe("RoundTimeline", () => {
  it("renders rounds with and without evidence", () => {
    render(
      <RoundTimeline
        items={[
          {
            round: 1,
            plan: {},
            rca_output: null,
            cost_usd: null,
            duration_ms: null,
            evidence: [],
          },
          {
            round: 2,
            plan: {},
            rca_output: null,
            cost_usd: 1,
            duration_ms: 5,
            evidence: [
              {
                evidence_id: "abcd1234-0000-0000-0000-000000000000",
                tool_name: "tool_a",
                summary: "s",
              },
            ],
          },
        ]}
      />
    );
    const el = screen.getByTestId("round-timeline");
    expect(el).toHaveTextContent("Round 1");
    expect(el).toHaveTextContent("Evidence: —");
    expect(el).toHaveTextContent("tool_a");
  });
});
