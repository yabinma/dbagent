import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BootstrapTokenPanel } from "./BootstrapTokenPanel";
import { PendingCredentialsGuide } from "./PendingCredentialsGuide";

describe("Admin surfaces (FP-M4-16)", () => {
  it("renders pending-credentials guidance", () => {
    render(
      <PendingCredentialsGuide
        platformKey="presto-us1"
        guidance="Mount Secret at /etc/dbagent-probe/platform-credentials"
      />
    );
    expect(screen.getByTestId("pending-credentials-guide")).toHaveTextContent(
      "presto-us1"
    );
    expect(screen.getByTestId("pending-credentials-guide")).toHaveTextContent(
      "platform-credentials"
    );
  });

  it("renders CA fingerprint when available, hint otherwise", () => {
    const { rerender } = render(
      <BootstrapTokenPanel fingerprint="sha256:abc123" />
    );
    expect(screen.getByTestId("ca-fingerprint")).toHaveTextContent(
      "sha256:abc123"
    );
    rerender(<BootstrapTokenPanel fingerprint={null} />);
    expect(screen.getByTestId("ca-fingerprint-hint")).toHaveTextContent(
      "probe-gateway"
    );
  });
});
