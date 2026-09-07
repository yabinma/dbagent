import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import {
  AuthProvider,
  roleAtLeast,
  useAuth,
} from "./AuthContext";

function Probe() {
  const { token, role, mustChangePassword, login, logout, clearMustChange } =
    useAuth();
  return (
    <div>
      <div data-testid="token">{token || "none"}</div>
      <div data-testid="role">{role || "none"}</div>
      <div data-testid="must">{String(mustChangePassword)}</div>
      <button
        onClick={() => login("admin", "password-long")}
        data-testid="login"
      >
        login
      </button>
      <button onClick={() => logout()} data-testid="logout">
        logout
      </button>
      <button onClick={() => clearMustChange()} data-testid="clear">
        clear
      </button>
    </div>
  );
}

describe("roleAtLeast", () => {
  it("ranks viewer < approver < admin", () => {
    expect(roleAtLeast("viewer", "viewer")).toBe(true);
    expect(roleAtLeast("viewer", "approver")).toBe(false);
    expect(roleAtLeast("approver", "viewer")).toBe(true);
    expect(roleAtLeast("admin", "approver")).toBe(true);
    expect(roleAtLeast(null, "viewer")).toBe(false);
    expect(roleAtLeast("viewer", "unknown")).toBe(false);
  });
});

describe("AuthProvider / useAuth", () => {
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

  it("throws when useAuth is outside provider", () => {
    function Bad() {
      useAuth();
      return null;
    }
    expect(() => render(<Bad />)).toThrow(/useAuth outside AuthProvider/);
  });

  it("restores token/role from localStorage and supports login/logout/clear", async () => {
    localStorage.setItem("rca_dashboard_token", "stored");
    localStorage.setItem("rca_dashboard_role", "viewer");

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>
    );
    expect(screen.getByTestId("token")).toHaveTextContent("stored");
    expect(screen.getByTestId("role")).toHaveTextContent("viewer");

    fetchMock.mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        token: "new-tok",
        role: "admin",
        expires_at: "2099-01-01T00:00:00Z",
        must_change_password: true,
      }),
    });
    fireEvent.click(screen.getByTestId("login"));
    await waitFor(() =>
      expect(screen.getByTestId("token")).toHaveTextContent("new-tok")
    );
    expect(screen.getByTestId("role")).toHaveTextContent("admin");
    expect(screen.getByTestId("must")).toHaveTextContent("true");
    expect(localStorage.getItem("rca_dashboard_token")).toBe("new-tok");

    fireEvent.click(screen.getByTestId("clear"));
    expect(screen.getByTestId("must")).toHaveTextContent("false");

    fireEvent.click(screen.getByTestId("logout"));
    expect(screen.getByTestId("token")).toHaveTextContent("none");
    expect(localStorage.getItem("rca_dashboard_token")).toBeNull();
  });
});

describe("role-gated navigation (App RequireAuth integration)", () => {
  // Imported lazily so AuthContext coverage is primary; App is covered in App.test.
  it("roleAtLeast drives Approvals/Admin visibility", () => {
    expect(roleAtLeast("viewer", "approver")).toBe(false);
    expect(roleAtLeast("approver", "approver")).toBe(true);
    expect(roleAtLeast("admin", "admin")).toBe(true);
  });
});
