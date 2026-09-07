import { useState } from "react";

/** Compact/Details toggle (D13) — both payloads already in the response. */
export function RcaPanel({
  compact,
  full,
}: {
  compact: string | null | undefined;
  full: Record<string, unknown> | null | undefined;
}) {
  const [details, setDetails] = useState(false);
  return (
    <div className="card" data-testid="rca-panel">
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <h3>RCA</h3>
        <button
          className="btn"
          data-testid="details-toggle"
          onClick={() => setDetails((d) => !d)}
        >
          {details ? "Compact" : "Details"}
        </button>
      </div>
      {!details ? (
        <p data-testid="rca-compact">{compact || "—"}</p>
      ) : (
        <pre data-testid="rca-full" style={{ whiteSpace: "pre-wrap" }}>
          {JSON.stringify(full || {}, null, 2)}
        </pre>
      )}
    </div>
  );
}
