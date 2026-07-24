import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { InvestigationSummary } from "../api/client";
import { useAuth } from "../auth/AuthContext";

export function CasesPage() {
  const { api } = useAuth();
  const [items, setItems] = useState<InvestigationSummary[]>([]);

  useEffect(() => {
    api.listInvestigations().then((r) => setItems(r.items)).catch(() => setItems([]));
  }, [api]);

  return (
    <div>
      <h1>Cases</h1>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Platform</th>
              <th>Status</th>
              <th>Summary</th>
              <th>Cost</th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.investigation_id}>
                <td>
                  <Link to={`/cases/${c.investigation_id}`}>
                    {c.investigation_id.slice(0, 8)}…
                  </Link>
                </td>
                <td>{c.platform_key}</td>
                <td>{c.status}</td>
                <td>{c.rca_compact || "—"}</td>
                <td>${c.spent?.cost_usd ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
