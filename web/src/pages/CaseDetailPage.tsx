import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  InvestigationDetail,
  IterationRow,
  LlmCallItem,
} from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { RcaPanel } from "../components/RcaPanel";
import { RoundTimeline } from "../components/RoundTimeline";

export function CaseDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { api } = useAuth();
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [iters, setIters] = useState<IterationRow[]>([]);
  const [traces, setTraces] = useState<LlmCallItem[]>([]);

  useEffect(() => {
    if (!id) return;
    api.getInvestigation(id).then(setDetail).catch(() => setDetail(null));
    api.getIterations(id).then((r) => setIters(r.items)).catch(() => setIters([]));
    api.listLlmCalls(id).then((r) => setTraces(r.items)).catch(() => setTraces([]));
  }, [api, id]);

  if (!detail) return <p className="muted">Loading…</p>;

  return (
    <div>
      <h1>Case {detail.investigation_id.slice(0, 8)}…</h1>
      <div className="card">
        <div>Status: {detail.status}</div>
        <div>Platform: {detail.platform_key}</div>
        <div>
          Spent: rounds={detail.spent?.rounds ?? 0} cost=$
          {detail.spent?.cost_usd ?? 0}
        </div>
      </div>
      <RcaPanel compact={detail.rca_compact} full={detail.rca_report} />
      <RoundTimeline items={iters} />
      <div className="card" data-testid="llm-trace-viewer">
        <h3>LLM traces</h3>
        <ul>
          {traces.map((t) => (
            <li key={t.call_id}>
              {t.agent_role} · {t.model} · ${t.cost_usd ?? 0} · {t.latency_ms ?? "—"}
              ms
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
