import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";

describe("ApiClient (Bearer + uniform error envelope)", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    delete window.__RCA_CONFIG__;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("injects Authorization Bearer when a token is present", async () => {
    fetchMock.mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({ items: [] }),
    });
    const client = new ApiClient(() => "secret-token");
    await client.listInvestigations();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/investigations");
    expect(init.headers.get("Authorization")).toBe("Bearer secret-token");
    expect(init.headers.get("Content-Type")).toBe("application/json");
  });

  it("omits Authorization when token is null", async () => {
    fetchMock.mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({ token: "t", role: "viewer", expires_at: "x", must_change_password: false }),
    });
    const client = new ApiClient(() => null);
    await client.login("u", "p");
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.has("Authorization")).toBe(false);
    expect(JSON.parse(init.body)).toEqual({ username: "u", password: "p" });
  });

  it("maps error envelope to thrown Error with status/code/body", async () => {
    fetchMock.mockResolvedValue({
      status: 401,
      ok: false,
      statusText: "Unauthorized",
      json: async () => ({
        error: { code: "unauthorized", message: "bad credentials" },
      }),
    });
    const client = new ApiClient(() => null);
    await expect(client.login("u", "bad")).rejects.toMatchObject({
      message: "bad credentials",
      status: 401,
      code: "unauthorized",
    });
  });

  it("returns undefined on 204 (change-password)", async () => {
    fetchMock.mockResolvedValue({
      status: 204,
      ok: true,
      json: async () => {
        throw new Error("no body");
      },
    });
    const client = new ApiClient(() => "tok");
    await expect(client.changePassword("old", "new-password-12")).resolves.toBeUndefined();
  });

  it("uses window.__RCA_CONFIG__.apiBaseUrl when set", async () => {
    window.__RCA_CONFIG__ = { apiBaseUrl: "https://api.example/v1" };
    fetchMock.mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({ items: [] }),
    });
    const client = new ApiClient(() => "t");
    await client.listPlatforms();
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.example/v1/platforms");
  });

  it("covers investigation/approval/metrics/llm helpers", async () => {
    fetchMock.mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({ items: [], open_cases: 1 }),
    });
    const client = new ApiClient(() => "t");
    await client.listInvestigations({ status: "OPEN" });
    await client.getInvestigation("id-1");
    await client.getIterations("id-1");
    await client.listApprovals();
    await client.decideApproval("a1", "approved", "ok");
    await client.metricsSummary();
    await client.listLlmCalls("id-1");
    const urls = fetchMock.mock.calls.map((c) => c[0] as string);
    expect(urls).toEqual(
      expect.arrayContaining([
        "/api/v1/investigations?status=OPEN",
        "/api/v1/investigations/id-1",
        "/api/v1/investigations/id-1/iterations",
        "/api/v1/approvals?pending=true",
        "/api/v1/approvals/a1/decision",
        "/api/v1/metrics/summary",
        "/api/v1/llm-calls?investigation_id=id-1",
      ])
    );
  });

  it("falls back to statusText when error body has no message", async () => {
    fetchMock.mockResolvedValue({
      status: 500,
      ok: false,
      statusText: "Internal Server Error",
      json: async () => {
        throw new Error("not json");
      },
    });
    const client = new ApiClient(() => "t");
    await expect(client.metricsSummary()).rejects.toMatchObject({
      message: "Internal Server Error",
      status: 500,
    });
  });
});
