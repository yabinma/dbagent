import { useEffect, useState } from "react";
import { useAuth } from "../auth/AuthContext";

export function OverviewPage() {
  const { api } = useAuth();
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    api.metricsSummary().then(setMetrics).catch(() => setMetrics(null));
  }, [api]);

  return (
    <div>
      <h1>Overview</h1>
      <div className="card">
        {metrics ? (
          <ul>
            <li>Open cases: {String(metrics.open_cases)}</li>
            <li>Pending approvals: {String(metrics.pending_approvals)}</li>
            <li>Closed in window: {String(metrics.closed_in_window)}</li>
            <li>Avg rounds: {String(metrics.avg_rounds)}</li>
            <li>Avg cost: ${String(metrics.avg_cost_usd)}</li>
          </ul>
        ) : (
          <p className="muted">Loading metrics…</p>
        )}
      </div>
    </div>
  );
}
