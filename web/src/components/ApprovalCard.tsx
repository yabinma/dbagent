import { useState } from "react";
import { ApprovalItem } from "../api/client";

export function ApprovalCard({
  item,
  onDecide,
}: {
  item: ApprovalItem;
  onDecide: (
    id: string,
    decision: "approved" | "denied" | "need_more",
    comment?: string
  ) => Promise<void>;
}) {
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);

  async function act(decision: "approved" | "denied" | "need_more") {
    setBusy(true);
    try {
      await onDecide(item.approval_id, decision, comment || undefined);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" data-testid="approval-card">
      <div>
        <strong>{item.kind}</strong> · case {item.investigation_id.slice(0, 8)}…
      </div>
      <pre style={{ fontSize: "0.85rem" }}>
        {JSON.stringify(item.subject, null, 2)}
      </pre>
      <textarea
        data-testid="approval-comment"
        placeholder="Comment (required for need_more)"
        value={comment}
        onChange={(e) => setComment(e.target.value)}
      />
      <div>
        <button
          className="btn primary"
          disabled={busy}
          data-testid="approve-btn"
          onClick={() => act("approved")}
        >
          Approve
        </button>
        <button
          className="btn danger"
          disabled={busy}
          data-testid="deny-btn"
          onClick={() => act("denied")}
        >
          Deny
        </button>
        <button
          className="btn"
          disabled={busy}
          data-testid="need-more-btn"
          onClick={() => act("need_more")}
        >
          Need more
        </button>
      </div>
    </div>
  );
}
