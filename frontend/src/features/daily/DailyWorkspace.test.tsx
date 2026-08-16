import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type {
  AppServices,
  DailyItem,
  DailyItemsResult,
  DailyReportRecord,
} from "../../app/contracts";
import { ToastProvider } from "../../components/Toast";
import { DailyWorkspace } from "./DailyWorkspace";
import {
  businessDateForShanghaiClock,
  selectInitialBusinessDate,
} from "./businessDate";

describe("Daily workspace", () => {
  const item: DailyItem = {
    platformWaybillId: "platform-1",
    waybillNumber: "YD-001",
    vehicleNumber: "陕A12345",
    loadingTicket: { sha256: "a".repeat(64), url: "/api/v1/evidence/loading" },
    unloadingTicket: { sha256: "b".repeat(64), url: "/api/v1/evidence/unloading" },
    machineFields: {
      loading_net_tonnes: "33.08",
      loading_time: "2026-08-05T18:57:54+08:00",
      unloading_net_tonnes: "33.04",
      unloading_time: "2026-08-05T19:42:27+08:00",
    },
    effectiveFields: {
      loading_net_tonnes: "33.08",
      loading_time: "2026-08-05T18:57:54+08:00",
      unloading_net_tonnes: "33.04",
      unloading_time: "2026-08-05T19:42:00+08:00",
    },
    fieldSources: {
      loading_net_tonnes: "machine",
      loading_time: "machine",
      unloading_net_tonnes: "machine",
      unloading_time: "machine",
    },
    fieldIssues: {
      loading_net_tonnes: { hasIssue: false, message: null },
      loading_time: { hasIssue: false, message: null },
      unloading_net_tonnes: { hasIssue: false, message: null },
      unloading_time: { hasIssue: false, message: null },
    },
    reviewState: "reviewed",
    materializedAt: "2026-08-05T20:07:00+08:00",
    timePrefill: {
      loadingDate: "2026-08-05",
      unloadingDate: "2026-08-05",
    },
    recordVersion: 1,
    updatedAt: "2026-08-05T20:07:00+08:00",
  };

  function result(
    businessDate: string,
    items: DailyItem[],
  ): DailyItemsResult {
    const needsReview = items.filter(
      (entry) => entry.reviewState === "needs_review",
    ).length;
    return {
      businessDate,
      contractSubjectCode: "shanxi_guienbo",
      items,
      counts: {
        all: items.length,
        needsReview,
        reviewed: items.length - needsReview,
      },
      sourceJobId: null,
      sourceRecordVersion: 0,
      captureMode: "batch_v1",
      visiblePrefixCount: items.length,
      onlineCaptureComplete: true,
    };
  }

  const reportSettings = {
    shippingMine: "金鸡滩煤矿",
    coalType: "兖矿陕动四号（5600）",
    unloadingPlace: "象道货22",
    queryPlaceKeyword: "榆林",
    outputDirectory: "C:\\reports",
    confirmed: false,
    recordVersion: 0,
    captureStartTime: "14:00",
    captureEndMode: "system_current_time" as const,
    captureFixedEndDayOffset: 1 as const,
    captureFixedEndTime: "14:30",
    captureRangeCoversReportWindow: true,
  };

  const reportRecord: DailyReportRecord = {
    contractSubjectCode: "shanxi_guienbo",
    reportId: "report-1",
    businessDate: "2026-08-05",
    status: "confirmed",
    fileName: "装卸车明细-山西贵恩博-2026-08-05.xlsx",
    fileSha256: "c".repeat(64),
    dataSnapshotSha256: "d".repeat(64),
    outputDirectory: "C:\\reports",
    rowCount: 1,
    candidateCount: 1,
    windowExcludedCount: 0,
    missingEffectiveTimeCount: 0,
    loadingNetTotal: "33.08",
    recordVersion: 1,
    createdAt: "2026-08-05T20:10:00+08:00",
    confirmedAt: "2026-08-05T20:10:00+08:00",
    stale: false,
  };

  it("uses the 14:00 Shanghai business boundary for the default date", () => {
    expect(businessDateForShanghaiClock(new Date("2026-08-11T05:59:00Z"))).toBe("2026-08-10");
    expect(businessDateForShanghaiClock(new Date("2026-08-11T06:00:00Z"))).toBe("2026-08-11");
  });

  it("replaces a stored future business date with the current business date", () => {
    expect(selectInitialBusinessDate("2026-08-11", "2026-08-10")).toBe("2026-08-10");
    expect(selectInitialBusinessDate("2026-08-09", "2026-08-10")).toBe("2026-08-09");
  });

  it("starts an independent daily business read for the selected date", async () => {
    const start = vi.fn(async () => ({
      created: true,
      attached: false,
      job: {} as never,
    }));
    const services = {
      startPlatformBusinessRead: start,
    } as unknown as AppServices;
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-01");
    render(<DailyWorkspace services={services} jobs={[]} />);
    const user = userEvent.setup();
    expect(screen.getByRole("button", { name: /2026年8月1日/ })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "启动" }));

    expect(start).toHaveBeenCalledWith({
      businessScope: "daily",
      businessDate: "2026-08-01",
      contractSubjectCode: "shanxi_guienbo",
      expectedRecordVersion: 0,
    });
    expect(screen.getByRole("status", { name: "尚未启动" })).toBeVisible();
  });

  it("does not render a fake export action", () => {
    render(<DailyWorkspace services={{} as AppServices} jobs={[]} />);
    expect(screen.queryByRole("button", { name: /导出/ })).not.toBeInTheDocument();
  });

  it("enables direct report generation after all records are reviewed with stored unconfirmed settings", async () => {
    const createReport = vi.fn(async () => reportRecord);
    const services = {
      loadDailyItems: vi.fn(async () => result("2026-08-05", [item])),
      loadDailyReportSettings: vi.fn(async () => ({ ...reportSettings, recordVersion: 1 })),
      findDailyReport: vi.fn(async () => null),
      createDailyReport: createReport,
    } as unknown as AppServices;
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-05");
    render(
      <ToastProvider>
        <DailyWorkspace services={services} jobs={[]} productionReadOnly />
      </ToastProvider>,
    );
    const user = userEvent.setup();

    const button = await screen.findByRole("button", { name: "生成报表" });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);

    await waitFor(() => expect(createReport).toHaveBeenCalledWith(
      "2026-08-05",
      1,
      "shanxi_guienbo",
    ));
  });

  it("materializes built-in default report settings within the first generate click", async () => {
    const createReport = vi.fn(async () => reportRecord);
    const saveSettings = vi.fn(async () => ({
      ...reportSettings,
      confirmed: true,
      recordVersion: 1,
    }));
    const services = {
      loadDailyItems: vi.fn(async () => result("2026-08-05", [item])),
      loadDailyReportSettings: vi.fn(async () => reportSettings),
      findDailyReport: vi.fn(async () => null),
      createDailyReport: createReport,
      saveDailyReportSettings: saveSettings,
    } as unknown as AppServices;
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-05");
    render(
      <ToastProvider>
        <DailyWorkspace services={services} jobs={[]} productionReadOnly />
      </ToastProvider>,
    );
    const user = userEvent.setup();

    const button = await screen.findByRole("button", { name: "生成报表" });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);

    await waitFor(() => expect(saveSettings).toHaveBeenCalledWith({
      shippingMine: reportSettings.shippingMine,
      coalType: reportSettings.coalType,
      unloadingPlace: reportSettings.unloadingPlace,
      queryPlaceKeyword: reportSettings.queryPlaceKeyword,
      outputDirectory: reportSettings.outputDirectory,
      confirmed: true,
      expectedRecordVersion: 0,
      captureStartTime: reportSettings.captureStartTime,
      captureEndMode: reportSettings.captureEndMode,
      captureFixedEndDayOffset: reportSettings.captureFixedEndDayOffset,
      captureFixedEndTime: reportSettings.captureFixedEndTime,
    }));
    expect(createReport).toHaveBeenCalledWith("2026-08-05", 1, "shanxi_guienbo");
  });

  it("keeps report generation disabled while the current business day still needs review", async () => {
    const unresolved = { ...item, reviewState: "needs_review" as const };
    const services = {
      loadDailyItems: vi.fn(async () => result("2026-08-05", [unresolved])),
      loadDailyReportSettings: vi.fn(async () => ({ ...reportSettings, recordVersion: 1 })),
      findDailyReport: vi.fn(async () => null),
      createDailyReport: vi.fn(async () => reportRecord),
    } as unknown as AppServices;
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-05");
    render(
      <ToastProvider>
        <DailyWorkspace services={services} jobs={[]} productionReadOnly />
      </ToastProvider>,
    );

    const button = await screen.findByRole("button", { name: "生成报表" });
    await waitFor(() => expect(button).toBeDisabled());
  });

  it("does not disguise a failed daily load as a genuinely empty business day", async () => {
    const services = {
      loadDailyItems: vi.fn(async () => {
        throw new Error("装卸车明细读取失败");
      }),
    } as unknown as AppServices;

    render(<DailyWorkspace services={services} jobs={[]} />);

    expect(await screen.findByRole("status", { name: "装卸车明细读取失败" })).toBeVisible();
    expect(screen.queryByText("该业务日暂无已保存的装卸车明细。")).toBeNull();
  });

  it("saves every unresolved field including an unchanged explicit blank", async () => {
    const unresolved = {
      ...item,
      reviewState: "needs_review" as const,
      effectiveFields: { ...item.effectiveFields, unloading_time: null },
      fieldIssues: {
        ...item.fieldIssues,
        unloading_time: { hasIssue: true, message: "该字段尚未确认" },
      },
    };
    const reviewed = {
      ...unresolved,
      recordVersion: 2,
      reviewState: "reviewed" as const,
      fieldSources: { ...unresolved.fieldSources, unloading_time: "manual" as const },
      fieldIssues: {
        ...unresolved.fieldIssues,
        unloading_time: { hasIssue: false, message: null },
      },
    };
    const save = vi.fn(async () => ({
      businessDate: "2026-08-05",
      item: reviewed,
      counts: { all: 1, needsReview: 0, reviewed: 1 },
    }));
    const services = {
      loadDailyItems: vi.fn(async () => result("2026-08-05", [unresolved])),
      saveDailyItemRevision: save,
    } as unknown as AppServices;
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-05");
    render(<DailyWorkspace services={services} jobs={[]} />);
    const user = userEvent.setup();

    const saveButton = await screen.findByRole("button", { name: "保存" });
    expect(saveButton).toBeEnabled();
    await user.click(saveButton);

    await waitFor(() => expect(save).toHaveBeenCalledWith(
      "platform-1",
      "2026-08-05",
      1,
      { unloading_time: null },
      "shanxi_guienbo",
    ));
  });

  it("clears the previous business day immediately and ignores its late response", async () => {
    let resolveSecond: (value: DailyItemsResult) => void = () => undefined;
    const second = new Promise<DailyItemsResult>((resolve) => {
      resolveSecond = resolve;
    });
    const load = vi
      .fn<([businessDate]: [string]) => Promise<DailyItemsResult>>()
      .mockResolvedValueOnce(result("2026-08-05", [item]))
      .mockReturnValueOnce(second);
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-05");
    render(<DailyWorkspace services={{ loadDailyItems: load } as unknown as AppServices} jobs={[]} />);
    const user = userEvent.setup();
    expect(await screen.findByText("YD-001")).toBeVisible();

    await user.click(screen.getByRole("button", { name: /2026年8月5日/ }));
    await user.click(
      screen.getAllByRole("button", { name: "6" }).find(
        (button) => !button.classList.contains("outside"),
      )!,
    );

    expect(screen.queryByText("YD-001")).toBeNull();
    expect(screen.getByRole("status", { name: "正在读取该业务日" })).toBeVisible();
    expect(screen.getByRole("button", { name: "全部 0" })).toBeVisible();
    resolveSecond(result("2026-08-06", []));
    expect(await screen.findByText("该业务日暂无已保存的装卸车明细。")).toBeVisible();
  });

  it("does not apply a completed save after the operator changes business date", async () => {
    const unresolved = {
      ...item,
      reviewState: "needs_review" as const,
      effectiveFields: { ...item.effectiveFields, unloading_time: null },
      fieldIssues: {
        ...item.fieldIssues,
        unloading_time: { hasIssue: true, message: "该字段尚未确认" },
      },
    };
    let resolveSave: (value: Awaited<ReturnType<NonNullable<AppServices["saveDailyItemRevision"]>>>) => void = () => undefined;
    const save = vi.fn(() => new Promise((resolve) => { resolveSave = resolve; }));
    const load = vi.fn(async (businessDate: string) =>
      businessDate === "2026-08-05"
        ? result(businessDate, [unresolved])
        : result(businessDate, []));
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-05");
    render(
      <ToastProvider>
        <DailyWorkspace services={{ loadDailyItems: load, saveDailyItemRevision: save } as unknown as AppServices} jobs={[]} />
      </ToastProvider>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "保存" }));
    await user.click(screen.getByRole("button", { name: /2026年8月5日/ }));
    await user.click(
      screen.getAllByRole("button", { name: "6" }).find(
        (button) => !button.classList.contains("outside"),
      )!,
    );
    resolveSave({
      businessDate: "2026-08-05",
      contractSubjectCode: "shanxi_guienbo",
      item: { ...unresolved, reviewState: "reviewed", recordVersion: 2 },
      counts: { all: 1, needsReview: 0, reviewed: 1 },
    });

    expect(await screen.findByText("该业务日暂无已保存的装卸车明细。")).toBeVisible();
    expect(screen.queryByText("YD-001")).toBeNull();
  });

  it("opens the full image viewer and closes it with Escape", async () => {
    const services = {
      loadDailyItems: vi.fn(async () => ({
        businessDate: "2026-08-05",
        items: [item],
        counts: { all: 1, needsReview: 0, reviewed: 1 },
      })),
    } as unknown as AppServices;
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-05");
    render(<DailyWorkspace services={services} jobs={[]} />);
    const user = userEvent.setup();

    const ticketImage = await screen.findByRole("img", { name: "装货磅单" });
    expect(ticketImage.getAttribute("src")).toContain("client_version=");
    await user.click(await screen.findByRole("button", { name: "装货磅单" }));
    expect(screen.getByRole("dialog", { name: "装货磅单" })).toBeVisible();
    expect(screen.getByRole("button", { name: "向左旋转" })).toBeVisible();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "装货磅单" })).not.toBeInTheDocument();
  });

  it("keeps showing offline OCR progress after the platform parent job succeeds", async () => {
    const services = {
      loadDailyItems: vi.fn(async () => ({
        businessDate: "2026-08-05",
        items: [item],
        counts: { all: 1, needsReview: 0, reviewed: 1 },
      })),
      loadPlatformBusinessReadProgress: vi.fn(async () => ({
        jobId: "daily-job",
        sourceJobId: "daily-job",
        total: 10,
        fetched: 10,
        recognized: 3,
        missingFields: 0,
        technicalFailed: 0,
        committedBatches: 1,
        visiblePrefixCount: 3,
        onlineCaptureComplete: true,
        reviewJob: null,
      })),
    } as unknown as AppServices;
    const jobs = [{
      jobId: "daily-job",
      taskType: "daily",
      scopeLabel: "装卸车明细 2026-08-05",
      jobStatus: "succeeded",
      statusLabel: "已完成",
      progressLabel: "已完成",
      counts: { total: 1, processed: 1, remaining: 0, waitingUser: 0, failed: 0 },
      actions: {},
      recordVersion: 1,
      updatedAt: "2026-08-05T20:07:00+08:00",
    }] as never;
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-05");
    render(
      <DailyWorkspace services={services} jobs={jobs} />,
    );

    expect(
      await screen.findByRole("status", { name: "正在离线审核 3/10" }),
    ).toBeVisible();
    expect(screen.queryByRole("status", { name: "已完成 0/10" })).toBeNull();
  });

  it("shows the visible vehicle prefix while the review job is still running", async () => {
    const liveProgress = {
        jobId: "daily-job",
        phase: "offline_review",
        label: "正在离线审核",
        current: 3,
        total: 10,
        fetched: 10,
        recognized: 3,
        missingFields: 0,
        technicalFailed: 0,
        committedBatches: 0,
        startedAt: "2026-08-05T20:00:00+08:00",
        phaseStartedAt: "2026-08-05T20:00:12+08:00",
        updatedAt: "2026-08-05T20:00:18+08:00",
        finishedAt: null,
        elapsedSeconds: 18,
        estimatedRemainingSeconds: 42,
        estimateState: "estimated",
        isTerminal: false,
        sourceJobId: "daily-job",
        sourceRecordVersion: 1,
        captureMode: "whole_run_v1",
        visiblePrefixCount: 3,
        onlineCaptureComplete: true,
        reviewJob: null,
      } as const;
    const services = {
      loadDailyItems: vi.fn(async () => result("2026-08-05", [item])),
      loadPlatformBusinessReadProgress: vi.fn(async () => liveProgress),
      subscribePlatformBusinessReadProgress: vi.fn((_jobId, onProgress) => {
        queueMicrotask(() => onProgress(liveProgress));
        return () => undefined;
      }),
    } as unknown as AppServices;
    const jobs = [{
      jobId: "daily-job",
      taskType: "daily",
      scopeLabel: "装卸车明细 2026-08-05",
      jobStatus: "running",
      statusLabel: "运行中",
      currentStage: "offline_review",
      currentStageLabel: "正在离线审核",
      progressLabel: "正在离线审核",
      counts: { total: 10, processed: 3, remaining: 7, waitingUser: 0, failed: 0 },
      actions: {},
      recordVersion: 1,
      updatedAt: "2026-08-05T20:00:18+08:00",
    }] as never;
    localStorage.setItem("dahe:last-daily-business-date", "2026-08-05");
    render(<DailyWorkspace services={services} jobs={jobs} />);

    expect(await screen.findByText(/正在离线审核 3\/10/)).toBeVisible();
  });
});
