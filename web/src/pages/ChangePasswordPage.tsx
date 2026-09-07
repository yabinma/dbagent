import { FormEvent, useState } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export function ChangePasswordPage() {
  const { token, api, clearMustChange } = useAuth();
  const [oldPassword, setOld] = useState("");
  const [newPassword, setNew] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  if (!token) return <Navigate to="/login" replace />;
  if (done) return <Navigate to="/" replace />;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.changePassword(oldPassword, newPassword);
      clearMustChange();
      setDone(true);
    } catch (err: any) {
      setError(err.message || "change failed");
    }
  }

  return (
    <div className="card login">
      <h1>Change password</h1>
      <p className="muted">Required on first login.</p>
      <form onSubmit={onSubmit}>
        <label>Current password</label>
        <input
          type="password"
          value={oldPassword}
          onChange={(e) => setOld(e.target.value)}
        />
        <label>New password</label>
        <input
          type="password"
          value={newPassword}
          onChange={(e) => setNew(e.target.value)}
        />
        {error && <p className="error">{error}</p>}
        <button className="btn primary" type="submit">
          Update
        </button>
      </form>
    </div>
  );
}
