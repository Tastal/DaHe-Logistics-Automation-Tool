import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { JobItem } from "../../app/contracts";
import { AuditResults } from "./AuditResults";

function item(reviewReason: string): JobItem {
  return {
    workItemId: reviewReason,
    recordVersion: 1,
    waybillNumber: "TEST-001",
    vehicleNumber: "TEST-TRUCK",
    status: "waiting_user",
    currentStage: "audit.compare",
    businessOutcome: "awaiting_review",
    isTerminalOutcome: false,
    platformLoadingNet: "32.70",
    platformUnloadingNet: "32.70",
    ticketLoadingNet: null,
    ticketUnloadingNet: null,
    decision: null,
    reviewReason,
  };
}

describe("AuditResults", () => {
  it.each([
    ["ticket_weight_format_suspicious", "磅单净重格式异常"],
    ["ocr_weight_disagreement", "两次识别的净重不一致"],
  ])("shows a business label for %s", (reason, label) => {
    render(<AuditResults items={[item(reason)]} />);

    expect(screen.getByText(label)).toBeVisible();
    expect(screen.queryByText(reason)).toBeNull();
  });
});
