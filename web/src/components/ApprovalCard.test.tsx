import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApprovalCard } from "./ApprovalCard";

const item = {
  approval_id: "a1",
  investigation_id: "inv-1",
  kind: "raw_command",
  subject: { command: "cat /x" },
  age_seconds: 10,
  created_at: null,
};

describe("ApprovalCard actions (FP-M4-15)", () => {
  it("fires approve/deny/need_more with comment", async () => {
    const onDecide = vi.fn().mockResolvedValue(undefined);
    render(<ApprovalCard item={item} onDecide={onDecide} />);
    fireEvent.change(screen.getByTestId("approval-comment"), {
      target: { value: "please dig deeper" },
    });
    fireEvent.click(screen.getByTestId("approve-btn"));
    await waitFor(() =>
      expect(onDecide).toHaveBeenCalledWith("a1", "approved", "please dig deeper")
    );
    fireEvent.click(screen.getByTestId("deny-btn"));
    await waitFor(() =>
      expect(onDecide).toHaveBeenCalledWith("a1", "denied", "please dig deeper")
    );
    fireEvent.click(screen.getByTestId("need-more-btn"));
    await waitFor(() =>
      expect(onDecide).toHaveBeenCalledWith(
        "a1",
        "need_more",
        "please dig deeper"
      )
    );
  });
});
