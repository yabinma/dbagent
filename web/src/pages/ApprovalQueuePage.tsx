import { useCallback, useEffect, useState } from "react";
import { ApprovalItem } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { ApprovalCard } from "../components/ApprovalCard";

export function ApprovalQueuePage() {
  const { api } = useAuth();
  const [items, setItems] = useState<ApprovalItem[]>([]);

  const reload = useCallback(() => {
    api.listApprovals().then((r) => setItems(r.items)).catch(() => setItems([]));
  }, [api]);

  useEffect(() => {
    reload();
  }, [reload]);

  return (
    <div>
      <h1>Approval queue</h1>
      {items.length === 0 && <p className="muted">No pending approvals.</p>}
      {items.map((item) => (
        <ApprovalCard
          key={item.approval_id}
          item={item}
          onDecide={async (id, decision, comment) => {
            await api.decideApproval(id, decision, comment);
            reload();
          }}
        />
      ))}
    </div>
  );
}
