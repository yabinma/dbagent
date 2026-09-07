import { IterationRow } from "../api/client";

export function RoundTimeline({ items }: { items: IterationRow[] }) {
  return (
    <div className="card" data-testid="round-timeline">
      <h3>Timeline</h3>
      {items.map((it) => (
        <div key={it.round} style={{ marginBottom: "1rem" }}>
          <strong>Round {it.round}</strong>
          <div className="muted">
            cost=${it.cost_usd ?? "—"} · {it.duration_ms ?? "—"}ms
          </div>
          <div>
            Evidence:{" "}
            {(it.evidence || [])
              .map((e) => `${e.tool_name} (${e.evidence_id.slice(0, 8)})`)
              .join(", ") || "—"}
          </div>
        </div>
      ))}
    </div>
  );
}
