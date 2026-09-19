/** Typed fetch client for Appendix D dashboard-api. */

export type ApiError = {
  error: { code: string; message: string; detail?: Record<string, unknown> };
};

declare global {
  interface Window {
    __DBAGENT_CONFIG__?: { apiBaseUrl?: string };
  }
}

function baseUrl(): string {
  return (
    (typeof window !== "undefined" && window.__DBAGENT_CONFIG__?.apiBaseUrl) ||
    "/api/v1"
  );
}

export class ApiClient {
  constructor(private getToken: () => string | null) {}

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers || {});
    headers.set("Content-Type", "application/json");
    const token = this.getToken();
    if (token) headers.set("Authorization", `Bearer ${token}`);
    const res = await fetch(`${baseUrl()}${path}`, { ...init, headers });
    if (res.status === 204) return undefined as T;
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = body as ApiError;
      throw Object.assign(new Error(err.error?.message || res.statusText), {
        status: res.status,
        code: err.error?.code,
        body: err,
      });
    }
    return body as T;
  }

  login(username: string, password: string) {
    return this.request<{
      token: string;
      role: string;
      expires_at: string;
      must_change_password: boolean;
    }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  }

  changePassword(old_password: string, new_password: string) {
    return this.request<void>("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ old_password, new_password }),
    });
  }

  listInvestigations(params?: Record<string, string>) {
    const q = params ? "?" + new URLSearchParams(params).toString() : "";
    return this.request<{ items: InvestigationSummary[] }>(`/investigations${q}`);
  }

  getInvestigation(id: string) {
    return this.request<InvestigationDetail>(`/investigations/${id}`);
  }

  getIterations(id: string) {
    return this.request<{ items: IterationRow[] }>(`/investigations/${id}/iterations`);
  }

  listApprovals() {
    return this.request<{ items: ApprovalItem[] }>("/approvals?pending=true");
  }

  decideApproval(
    id: string,
    decision: "approved" | "denied" | "need_more",
    comment?: string
  ) {
    return this.request(`/approvals/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision, comment }),
    });
  }

  listPlatforms() {
    return this.request<{ items: PlatformItem[] }>("/platforms");
  }

  metricsSummary() {
    return this.request<Record<string, unknown>>("/metrics/summary");
  }

  listLlmCalls(investigationId: string) {
    return this.request<{ items: LlmCallItem[] }>(
      `/llm-calls?investigation_id=${encodeURIComponent(investigationId)}`
    );
  }
}

export type InvestigationSummary = {
  investigation_id: string;
  platform_key: string;
  status: string;
  severity: string;
  created_at: string | null;
  rca_compact: string | null;
  spent: { rounds?: number; cost_usd?: number };
  budget: Record<string, unknown>;
};

export type InvestigationDetail = InvestigationSummary & {
  rca_report: Record<string, unknown>;
  related_events: unknown[];
  executions: unknown[];
};

export type IterationRow = {
  round: number;
  plan: unknown;
  rca_output: Record<string, unknown> | null;
  cost_usd: number | null;
  duration_ms: number | null;
  evidence: { evidence_id: string; tool_name: string; summary: string | null }[];
};

export type ApprovalItem = {
  approval_id: string;
  investigation_id: string;
  kind: string;
  subject: Record<string, unknown>;
  age_seconds: number;
  created_at: string | null;
};

export type PlatformItem = {
  platform_key: string;
  status: string;
  deployment: string;
  display_name?: string;
  credential_guidance?: string;
  bootstrap_ca_fingerprint?: string;
};

export type LlmCallItem = {
  call_id: string;
  agent_role: string;
  model: string;
  cost_usd: number | null;
  latency_ms: number | null;
  prompt_url?: string | null;
  response_url?: string | null;
};
