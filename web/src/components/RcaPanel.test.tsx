import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RcaPanel } from "./RcaPanel";

describe("RcaPanel compact/Details toggle (FP-M4-15 / D13)", () => {
  it("shows compact by default and full on Details toggle", () => {
    render(
      <RcaPanel
        compact="worker oom one-liner"
        full={{ root_cause: { summary: "full oom detail" }, confidence: 0.95 }}
      />
    );
    expect(screen.getByTestId("rca-compact")).toHaveTextContent(
      "worker oom one-liner"
    );
    expect(screen.queryByTestId("rca-full")).toBeNull();
    fireEvent.click(screen.getByTestId("details-toggle"));
    expect(screen.getByTestId("rca-full")).toHaveTextContent("full oom detail");
    fireEvent.click(screen.getByTestId("details-toggle"));
    expect(screen.getByTestId("rca-compact")).toBeInTheDocument();
  });
});
