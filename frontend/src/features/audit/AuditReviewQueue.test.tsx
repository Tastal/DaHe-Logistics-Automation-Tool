import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AuditReviewItem, SettlementWorkspaceResult } from "../../api/auditContracts";
import type { AppServices } from "../../app/contracts";
import { AuditReviewQueue } from "./AuditReviewQueue";
import { ToastProvider } from "../../components/Toast";

function reviewItem(overrides: Partial<AuditReviewItem> = {}): AuditReviewItem {
  return {
    workItemId: "item-1",
    jobId: "job-1",
    waybillId: "OFFLINE-003",
    vehicleNumber: "匿名车辆-003",
    recordVersion: 1,
    status: "waiting_user",
    businessOutcome: "awaiting_review",
    decision: "review",
    reviewReason: "numeric_mismatch",
    diagnosticCode: null,
    platformLoadingNet: "30.00",
    platformUnloadingNet: "29.80",
    ticketLoadingNet: "30.00",
    ticketUnloadingNet: "29.70",
    loadingImageSha256: null,
    unloadingImageSha256: null,
    runMode: "operational",
    availableActions: {
      confirm_normal: { visible: true, enabled: true, reason: null },
      confirm_problem: { visible: true, enabled: true, reason: null },
    },
    timeline: [],
    reviewActions: [],
    fieldIssues: {
      loading_ticket: { hasIssue: false },
      loading_ocr_weight: { hasIssue: false },
      loading_platform_weight: { hasIssue: false },
      unloading_ticket: { hasIssue: false },
      unloading_ocr_weight: { hasIssue: false },
      unloading_platform_weight: { hasIssue: false },
    },
    reviewHighlightRoles: ["loading", "unloading"],
    ...overrides,
  };
}

function workspace(items = [reviewItem()]): SettlementWorkspaceResult {
  return {
    latestFetch: {
      createdAt: "2026-08-07T09:00:00Z",
      updatedAt: "2026-08-07T09:02:00Z",
      status: "complete",
      isComplete: true,
      phaseLabel: "已完成",
      progressCurrent: items.length,
      progressTotal: items.length,
      fetchedCount: items.length,
      recognizedCount: items.length,
      technicalFailureCount: 0,
      phase: "complete",
      metadataChecked: items.length,
      reused: 0,
      imagesDownloaded: items.length * 2,
      ocrCompleted: items.length,
      ocrImagesCompleted: items.length * 2,
      ocrImagesTotal: items.length * 2,
      finalized: items.length,
    },
    items,
    counts: {
      all: items.length,
      waiting_review: items.filter((item) => item.businessOutcome === "awaiting_review").length,
      confirmed_problem: items.filter((item) => item.businessOutcome === "confirmed_problem").length,
      normal_ready: items.filter((item) => item.businessOutcome === "normal_ready").length,
    },
  };
}

function services(result = workspace()): AppServices {
  return {
    loadSettlementWorkspace: vi.fn(async () => result),
    startPlatformBusinessRead: vi.fn(),
    runJobAction: vi.fn(),
    dismissAuditProblem: vi.fn(async () => reviewItem({
      businessOutcome: "normal_ready",
      status: "succeeded",
      recordVersion: 2,
    })),
    confirmAuditProblem: vi.fn(async () => reviewItem({
      businessOutcome: "confirmed_problem",
      status: "succeeded",
      recordVersion: 2,
    })),
    loadReadySettlementWaybillNumbers: vi.fn(async () => ["YD-001", "YD-002"]),
    prepareSettlementFilterHandoff: vi.fn(async () => ({
      count: 2,
      matchedCount: 2,
      missingCount: 0,
      message: "已在成丰打开 2 条可结算运单。",
    })),
  } as unknown as AppServices;
}

describe("freight settlement workspace", () => {
  it("reloads the latest workspace when the SSE revision changes", async () => {
    const loadSettlementWorkspace = vi
      .fn()
      .mockResolvedValueOnce(workspace([]))
      .mockResolvedValueOnce(workspace([reviewItem()]));
    const api = {
      ...services(workspace([])),
      loadSettlementWorkspace,
    } as AppServices;
    const { rerender } = render(
      <AuditReviewQueue services={api} workspaceRevision={0} />,
    );

    expect(await screen.findByText("本次没有可结算运单")).toBeVisible();
    rerender(<AuditReviewQueue services={api} workspaceRevision={1} />);

    expect(await screen.findByText("OFFLINE-003")).toBeVisible();
    expect(loadSettlementWorkspace).toHaveBeenCalledTimes(2);
  });

  it("shows only the latest fetch without batch or start-audit controls", async () => {
    render(<AuditReviewQueue services={services()} />);

    expect(await screen.findByText("OFFLINE-003")).toBeVisible();
    expect(screen.queryByRole("combobox", { name: "审核批次" })).toBeNull();
    expect(screen.queryByRole("button", { name: "开始审核" })).toBeNull();
    expect(screen.getByRole("status", { name: "已完成 1/1" })).toBeVisible();
  });

  it("expands every waybill with two ticket areas and direct decisions", async () => {
    const second = reviewItem({ workItemId: "item-2", waybillId: "OFFLINE-004" });
    render(<AuditReviewQueue services={services(workspace([reviewItem(), second]))} />);

    await screen.findByText("OFFLINE-004");
    const records = document.querySelectorAll(".settlement-waybill");
    expect(records).toHaveLength(2);
    for (const record of Array.from(records)) {
      expect(within(record as HTMLElement).getByLabelText("装货磅单")).toBeVisible();
      expect(within(record as HTMLElement).getByLabelText("卸货磅单")).toBeVisible();
      expect(within(record as HTMLElement).getByRole("button", { name: "确认无误" })).toBeVisible();
      expect(within(record as HTMLElement).getByRole("button", { name: "异常" })).toBeVisible();
    }
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("keeps the only authoritative counts in the filter row", async () => {
    const items = [
      reviewItem(),
      reviewItem({ workItemId: "problem", businessOutcome: "confirmed_problem" }),
      reviewItem({ workItemId: "normal", businessOutcome: "normal_ready" }),
    ];
    const { container } = render(<AuditReviewQueue services={services(workspace(items))} />);

    expect(await screen.findByRole("button", { name: "全部 3" })).toBeVisible();
    expect(screen.getByRole("button", { name: "待核对 1" })).toBeVisible();
    expect(screen.getByRole("button", { name: "问题运单 1" })).toBeVisible();
    expect(screen.getByRole("button", { name: "可结算 1" })).toBeVisible();
    expect(container.querySelector(".workspace-summary")).toBeNull();
  });

  it("marks only recognition weights even if legacy issue flags are present", async () => {
    const result = workspace([
      reviewItem({
        loadingImageSha256: "a".repeat(64),
        unloadingImageSha256: "b".repeat(64),
        fieldIssues: {
          loading_ticket: { hasIssue: true },
          loading_ocr_weight: { hasIssue: false },
          loading_platform_weight: { hasIssue: false },
          unloading_ticket: { hasIssue: false },
          unloading_ocr_weight: { hasIssue: true },
          unloading_platform_weight: { hasIssue: true },
        },
        reviewHighlightRoles: ["unloading"],
      }),
    ]);
    const { container } = render(<AuditReviewQueue services={services(result)} />);

    expect(await screen.findByText("OFFLINE-003")).toBeVisible();
    expect(container.querySelector('[aria-label="装货磅单"]')).not.toHaveClass("has-error");
    expect(container.querySelector('[aria-label="卸货磅单"]')).not.toHaveClass("has-error");
    const unloading = container.querySelector('[aria-label="卸货磅单"]');
    expect(unloading?.querySelectorAll(".settlement-weights .is-error")).toHaveLength(1);
    expect(within(unloading as HTMLElement).getByText("识别").parentElement).toHaveClass("is-error");
    expect(within(unloading as HTMLElement).getByText("平台").parentElement).not.toHaveClass("is-error");
    expect(within(unloading as HTMLElement).getByText("识别")).toBeVisible();
    expect(within(unloading as HTMLElement).getByText("平台")).toBeVisible();
    expect(screen.queryByText("识别净重")).toBeNull();
    expect(screen.queryByText("平台净重")).toBeNull();
  });

  it("falls back to both recognition weights for an unlocated review issue", async () => {
    const { container } = render(<AuditReviewQueue services={services()} />);

    expect(await screen.findByText("OFFLINE-003")).toBeVisible();
    const errors = container.querySelectorAll(".settlement-weights .is-error");
    expect(errors).toHaveLength(2);
    expect(Array.from(errors).every((node) => node.querySelector("dt")?.textContent === "识别")).toBe(true);
  });

  it("submits an immediate problem decision with the current record version", async () => {
    const api = services();
    render(
      <ToastProvider>
        <AuditReviewQueue services={api} />
      </ToastProvider>,
    );
    await userEvent.click(await screen.findByRole("button", { name: "异常" }));

    await waitFor(() => expect(api.confirmAuditProblem).toHaveBeenCalledWith("item-1", {
      expectedRecordVersion: 1,
    }));
  });

  it("shows a real empty state for a completed zero-item fetch", async () => {
    render(<AuditReviewQueue services={services(workspace([]))} />);

    expect(await screen.findByText("本次没有可结算运单")).toBeVisible();
    expect(screen.queryByText("OFFLINE-003")).toBeNull();
  });

  it("copies and opens only the current ready waybill set", async () => {
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const ready = reviewItem({
      businessOutcome: "normal_ready",
      status: "succeeded",
      availableActions: {
        confirm_normal: { visible: true, enabled: false, reason: null },
        confirm_problem: { visible: true, enabled: true, reason: null },
      },
    });
    const api = services(workspace([ready]));
    render(
      <ToastProvider>
        <AuditReviewQueue services={api} />
      </ToastProvider>,
    );

    await userEvent.click(await screen.findByRole("button", { name: "复制运单号" }));
    expect(api.loadReadySettlementWaybillNumbers).toHaveBeenCalledTimes(1);
    expect(writeText).toHaveBeenCalledWith("YD-001\nYD-002");

    await userEvent.click(screen.getByRole("button", { name: "打开成丰筛选" }));
    expect(api.prepareSettlementFilterHandoff).toHaveBeenCalledTimes(1);
    expect(await screen.findByText("已在成丰打开 2 条可结算运单。")).toBeVisible();
  });
});
