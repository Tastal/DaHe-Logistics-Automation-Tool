import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { JobSummary } from "../../app/contracts";
import {
  BusinessFilterTabs,
  BusinessOperationBar,
  BusinessProgress,
} from "./BusinessWorkspace";

function job(action: "pause" | "resume"): JobSummary {
  return {
    jobId: "job-1",
    taskType: "settlement_capture",
    jobKind: "business",
    displayName: "运费结算数据获取",
    scopeLabel: "运费结算数据获取",
    runMode: "operational",
    jobStatus: action === "pause" ? "running" : "paused",
    statusLabel: action === "pause" ? "处理中" : "已暂停",
    currentStage: "settlement_capture.read",
    currentStageLabel: "正在读取运单",
    activeStageLabels: [],
    activeResources: [],
    waitingReason: null,
    latestCheckpointLabel: null,
    progressLabel: "正在读取运单",
    diagnosticCode: null,
    recordVersion: 1,
    counts: { total: 10, processed: 3, remaining: 7, waitingUser: 0, failed: 0 },
    actions: {
      pause: {
        visible: action === "pause",
        enabled: action === "pause",
        reason: null,
        label: "暂停",
        expectedRecordVersion: 1,
      },
      resume: {
        visible: action === "resume",
        enabled: action === "resume",
        reason: null,
        label: "继续",
        expectedRecordVersion: 1,
      },
      cancel: {
        visible: true,
        enabled: true,
        reason: null,
        label: "取消",
        expectedRecordVersion: 1,
      },
    },
  };
}

describe("shared business workspace", () => {
  it.each([
    ["pause", "暂停"],
    ["resume", "继续"],
  ] as const)("uses one toggle position for %s", async (action, label) => {
    const onAction = vi.fn();
    render(
      <BusinessOperationBar
        job={job(action)}
        onStart={vi.fn()}
        onAction={onAction}
      />,
    );

    expect(screen.getByRole("button", { name: label })).toBeVisible();
    expect(screen.queryByRole("button", { name: label === "暂停" ? "继续" : "暂停" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: label }));
    expect(onAction).toHaveBeenCalledWith(action);
  });

  it("uses one progress status and one shared filter row", () => {
    render(
      <>
        <BusinessProgress progress={{
          phase: "download",
          label: "已复用 6 条，正在下载 2/4",
          current: 2,
          total: 4,
          error: false,
        }} />
        <BusinessFilterTabs
          items={[
            { id: "all", label: "全部", count: 10 },
            { id: "review", label: "待核对", count: 2 },
          ]}
          value="all"
          onChange={vi.fn()}
        />
      </>,
    );

    expect(screen.getAllByRole("status")).toHaveLength(1);
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "2");
    expect(screen.getByRole("button", { name: "全部 10" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "待核对 2" })).toBeVisible();
  });

  it("freezes a terminal zero-result duration", () => {
    vi.useFakeTimers();
    render(<BusinessProgress progress={{
      phase: "complete",
      label: "已完成 0/0",
      current: 0,
      total: 0,
      error: false,
      isTerminal: true,
      elapsedSeconds: 18,
      estimateState: "complete",
    }} />);

    expect(screen.getByText(/用时 00:18/)).toBeVisible();
    vi.advanceTimersByTime(5_000);
    expect(screen.getByText(/用时 00:18/)).toBeVisible();
    vi.useRealTimers();
  });

});
