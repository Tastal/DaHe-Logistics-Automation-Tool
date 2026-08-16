import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AuditReviewItem } from "../api/auditContracts";
import {
  App,
  ApiVersionMismatchError,
  type AppServices,
  type ConsoleSnapshot,
} from "./App";

const emptySnapshot: ConsoleSnapshot = {
  eventCursor: 0,
  jobs: [],
  resources: [],
  startActions: {
    start_audit: {
      visible: true,
      enabled: true,
      reason: null,
      label: "开始审核",
      expectedRecordVersion: 0,
    },
  },
};

function auditItem(): AuditReviewItem {
  return {
    workItemId: "item-1",
    jobId: "job-1",
    waybillId: "WB-20260728-001",
    vehicleNumber: "陕A12345",
    recordVersion: 4,
    status: "waiting_user",
    businessOutcome: "awaiting_review",
    decision: "review",
    reviewReason: "numeric_mismatch",
    diagnosticCode: null,
    platformLoadingNet: "32.80",
    platformUnloadingNet: "32.60",
    ticketLoadingNet: "32.70",
    ticketUnloadingNet: "32.60",
    loadingImageSha256: "a".repeat(64),
    unloadingImageSha256: "b".repeat(64),
    runMode: "shadow",
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
    reviewHighlightRoles: ["unloading"],
  };
}

function services(overrides: Partial<AppServices> = {}): AppServices {
  return {
    bootstrap: vi.fn().mockResolvedValue({
      applicationVersion: "1.0.0",
      csrfToken: "csrf-test",
      lockedSetReviewEnabled: false,
    }),
    loadSnapshot: vi.fn().mockResolvedValue(emptySnapshot),
    loadResources: vi.fn().mockResolvedValue([]),
    loadJobItems: vi.fn().mockResolvedValue([]),
    createAuditJob: vi.fn().mockResolvedValue({
      created: true,
      job: {
        jobId: "job-1",
        taskType: "audit",
        jobKind: "business",
        displayName: "离线审核批次",
        scopeLabel: "离线审核批次",
        runMode: "shadow",
        jobStatus: "queued",
        statusLabel: "等待开始",
        currentStage: "audit.snapshot",
        currentStageLabel: "准备运单",
        activeStageLabels: [],
        activeResources: [],
        waitingReason: null,
        latestCheckpointLabel: null,
        progressLabel: "正在建立审核任务",
        diagnosticCode: null,
        recordVersion: 1,
        counts: {
          total: 1,
          processed: 0,
          remaining: 1,
          waitingUser: 0,
          failed: 0,
        },
        actions: {},
      },
    }),
    createFixtureJob: vi.fn().mockRejectedValue(new Error("not configured")),
    subscribe: vi.fn().mockReturnValue(() => undefined),
    runJobAction: vi.fn().mockResolvedValue(undefined),
    startPlatformBusinessRead: vi.fn().mockResolvedValue({
      created: true,
      attached: false,
      job: {} as never,
    }),
    loadSettlementWorkspace: vi.fn().mockResolvedValue({
      latestFetch: null,
      items: [],
      counts: {
        all: 0,
        waiting_review: 0,
        confirmed_problem: 0,
        normal_ready: 0,
      },
    }),
    loadAuditWorkspaceItems: vi.fn().mockResolvedValue({
      items: [],
      counts: {
        all: 0,
        waiting_review: 0,
        confirmed_problem: 0,
        normal_ready: 0,
      },
    }),
    loadAuditItem: vi.fn().mockImplementation(async () => auditItem()),
    loadWaybillHistory: vi.fn().mockResolvedValue([]),
    loadDiagnostics: vi.fn().mockResolvedValue({
      generatedAt: "2026-07-28T09:00:00Z",
      health: [
        {
          id: "database",
          label: "数据存储",
          status: "normal",
          summary: "运行正常",
        },
      ],
      recentIssues: [],
    }),
    ...overrides,
  };
}

describe("B version application shell", () => {
  it("shows only the version confirmed by backend readiness", async () => {
    const loadReadinessVersion = vi.fn().mockResolvedValue("1.1.4");
    render(<App services={services({ loadReadinessVersion })} />);

    expect(screen.queryByLabelText(/当前版本/)).toBeNull();
    const versions = await screen.findAllByLabelText("当前版本 v1.1.4");
    expect(versions).toHaveLength(2);
    expect(versions.every((version) => version.textContent === "v1.1.4")).toBe(true);
    expect(
      versions.every((version) =>
        version.parentElement?.classList.contains("product-title-stack"),
      ),
    ).toBe(true);
    expect(
      versions.every((version) =>
        version.previousElementSibling?.textContent === "大禾物流自动化平台",
      ),
    ).toBe(true);
    expect(loadReadinessVersion).toHaveBeenCalledOnce();
  });

  it("keeps the console available when readiness identity is unavailable", async () => {
    const loadReadinessVersion = vi.fn().mockRejectedValue(new Error("offline"));
    render(<App services={services({ loadReadinessVersion })} />);

    expect(await screen.findByRole("navigation", { name: "主导航" })).toBeVisible();
    expect(screen.queryByLabelText(/当前版本/)).toBeNull();
    expect(screen.queryByText("操作台暂时无法加载")).toBeNull();
  });

  it("shows three business entries and four icon-only utilities", async () => {
    const user = userEvent.setup();
    render(<App services={services({
      checkForUpdates: vi.fn(),
      shutdownApplication: vi.fn(),
    })} />);

    const navigation = await screen.findByRole("navigation", {
      name: "主导航",
    });
    expect(
      within(navigation)
        .getAllByRole("button")
        .map((button) => button.getAttribute("aria-label") ?? button.textContent),
    ).toEqual([
      "山西贵恩博",
      "上海晋亿晟",
      "运费结算",
      "装卸车明细",
      "派单",
      "系统设置",
      "历史数据",
      "版本更新",
      "退出程序",
    ]);
    expect(within(navigation).getByRole("status", { name: "成丰平台连接状态：连接异常" })).toBeVisible();
    expect(screen.getByRole("button", { name: "启动" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "开始审核" })).toBeNull();
    expect(screen.queryByRole("combobox", { name: "审核批次" })).toBeNull();
    expect(screen.queryByText("今日工作")).toBeNull();
    expect(screen.queryByText("人工复核")).toBeNull();

    await user.click(within(navigation).getByRole("button", { name: "派单" }));
    expect(screen.getByRole("heading", { name: "派单" })).toBeVisible();
    expect(screen.queryByRole("button", { name: /开始|导出|保存/ })).toBeNull();
  });

  it("renders one latest business projection instead of internal audit batches", async () => {
    const loadSettlementWorkspace = vi.fn().mockResolvedValue({
      latestFetch: {
        createdAt: "2026-08-07T09:00:00Z",
        updatedAt: "2026-08-07T09:02:00Z",
        status: "complete",
        isComplete: true,
        phaseLabel: "已完成",
        progressCurrent: 1,
        progressTotal: 1,
        fetchedCount: 1,
        recognizedCount: 1,
        technicalFailureCount: 0,
      },
      items: [auditItem()],
      counts: {
        all: 1,
        waiting_review: 1,
        confirmed_problem: 0,
        normal_ready: 0,
      },
    });
    const oldAuditWorkspace = vi.fn().mockResolvedValue({
      items: [],
      counts: {
        all: 0,
        waiting_review: 0,
        confirmed_problem: 0,
        normal_ready: 0,
      },
    });
    const commonJob = {
      jobKind: "business" as const,
      runMode: "shadow" as const,
      jobStatus: "failed",
      statusLabel: "本任务处理失败",
      currentStage: "processing",
      currentStageLabel: "正在处理",
      activeStageLabels: [],
      activeResources: [],
      waitingReason: null,
      latestCheckpointLabel: null,
      progressLabel: "系统处理失败",
      diagnosticCode: "TEST-DIAGNOSTIC",
      recordVersion: 1,
      counts: {
        total: 1,
        processed: 1,
        remaining: 0,
        waitingUser: 0,
        failed: 1,
      },
      actions: {},
    };
    const mixedSnapshot: ConsoleSnapshot = {
      ...emptySnapshot,
      jobs: [
        {
          ...commonJob,
          jobId: "capture-job",
          taskType: "settlement_capture",
          displayName: "运费结算数据获取",
          scopeLabel: "运费结算数据获取",
        },
        {
          ...commonJob,
          jobId: "audit-job",
          taskType: "audit",
          displayName: "运费结算",
          scopeLabel: "运费结算",
        },
      ],
    };

    render(
      <App
        services={services({
          loadSnapshot: vi.fn().mockResolvedValue(mixedSnapshot),
          loadAuditWorkspaceItems: oldAuditWorkspace,
          loadSettlementWorkspace,
        })}
      />,
    );

    expect(await screen.findByText("WB-20260728-001")).toBeVisible();
    expect(screen.queryByRole("combobox", { name: "审核批次" })).toBeNull();
    await waitFor(() => expect(loadSettlementWorkspace).toHaveBeenCalledWith("all", "shanxi_guienbo"));
    expect(oldAuditWorkspace).not.toHaveBeenCalled();
  });

  it("prevents a repeated fetch while the create request is pending", async () => {
    const user = userEvent.setup();
    const startPlatformBusinessRead = vi.fn(() => new Promise<never>(() => undefined));
    render(<App services={services({ startPlatformBusinessRead })} />);
    const start = await screen.findByRole("button", { name: "启动" });

    await user.dblClick(start);

    expect(startPlatformBusinessRead).toHaveBeenCalledOnce();
    expect(startPlatformBusinessRead).toHaveBeenCalledWith({
      businessScope: "settlement",
      contractSubjectCode: "shanxi_guienbo",
      expectedRecordVersion: 0,
    });
    expect(start).toBeDisabled();
  });

  it("renders settlement evidence without weight editing controls", async () => {
    const item = auditItem();
    render(
      <App
        services={services({
          loadSettlementWorkspace: vi.fn().mockResolvedValue({
            latestFetch: {
              createdAt: "2026-08-07T09:00:00Z",
              updatedAt: "2026-08-07T09:02:00Z",
              status: "complete",
              isComplete: true,
              phaseLabel: "已完成",
              progressCurrent: 1,
              progressTotal: 1,
              fetchedCount: 1,
              recognizedCount: 1,
              technicalFailureCount: 0,
            },
            items: [item],
            counts: {
              all: 1,
              waiting_review: 1,
              confirmed_problem: 0,
              normal_ready: 0,
            },
          }),
        })}
      />,
    );

    expect(await screen.findByText("WB-20260728-001")).toBeVisible();
    expect(await screen.findByText("32.70 t")).toBeVisible();
    expect(await screen.findByText("32.80 t")).toBeVisible();
    expect(screen.getByRole("button", { name: "确认无误" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "异常" })).toBeEnabled();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByText("修改净重")).toBeNull();
  });

  it("puts technical information in System diagnostics", async () => {
    const user = userEvent.setup();
    const appServices = services();
    render(<App services={appServices} />);

    await user.click(await screen.findByRole("button", { name: "系统设置" }));

    expect(await screen.findByText("数据存储")).toBeVisible();
    expect(screen.getByText("运行正常")).toBeVisible();
    expect(screen.getByRole("button", { name: "导出诊断" })).toBeVisible();
    expect(screen.getByRole("button", { name: "打开目录" })).toBeVisible();
    expect(screen.getByRole("button", { name: "复制摘要" })).toBeVisible();
  });

  it("confirms local shutdown and leaves a stable exited page", async () => {
    const user = userEvent.setup();
    const shutdownApplication = vi.fn().mockResolvedValue(undefined);
    render(<App services={services({ shutdownApplication })} />);

    await user.click(await screen.findByRole("button", { name: "退出程序" }));
    expect(screen.getByRole("dialog", { name: "退出大禾物流自动化平台？" })).toBeVisible();
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "退出程序" }));

    await waitFor(() => expect(shutdownApplication).toHaveBeenCalledOnce());
    expect(await screen.findByRole("heading", { name: "程序已退出" })).toBeVisible();
    expect(screen.getByText("可以关闭此页面。再次使用时，请从桌面打开“大禾物流自动化平台”。")).toBeVisible();
  });

  it("shows one update icon before exit and installs only after confirmation", async () => {
    const user = userEvent.setup();
    const checkForUpdates = vi.fn().mockResolvedValue({
      state: "available",
      currentVersion: "1.0.0",
      availableVersion: "1.1.3",
      updateAvailable: true,
      checkedAt: "2026-08-14T12:00:00+00:00",
      errorCode: null,
    });
    const installUpdate = vi.fn().mockResolvedValue({
      state: "installing",
      currentVersion: "1.0.0",
      availableVersion: "1.0.0",
      updateAvailable: true,
      checkedAt: "2026-08-10T12:00:00+00:00",
      errorCode: null,
    });
    render(
      <App
        services={services({
          shutdownApplication: vi.fn().mockResolvedValue(undefined),
          loadUpdateStatus: vi.fn().mockResolvedValue({
            state: "available",
            currentVersion: "1.0.0",
            availableVersion: "1.0.0",
            updateAvailable: true,
            checkedAt: "2026-08-10T12:00:00+00:00",
            errorCode: null,
          }),
          checkForUpdates,
          installUpdate,
        })}
      />,
    );

    const updateButton = await screen.findByRole("button", {
      name: "有新版本 1.0.0，版本更新",
    });
    const exitButton = screen.getByRole("button", { name: "退出程序" });
    expect(
      updateButton.compareDocumentPosition(exitButton) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();

    await user.click(updateButton);
    expect(installUpdate).not.toHaveBeenCalled();
    await waitFor(() => expect(checkForUpdates).toHaveBeenCalledOnce());
    expect(
      await screen.findByRole("heading", { name: "安装 1.1.3 更新？" }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "安装更新" }));
    await waitFor(() => expect(installUpdate).toHaveBeenCalledOnce());
  });

  it("keeps local package import reachable when online update is unavailable", async () => {
    const user = userEvent.setup();
    const importUpdatePackage = vi.fn().mockResolvedValue({
      state: "available",
      currentVersion: "1.0.0",
      availableVersion: "1.1.0",
      updateAvailable: true,
      checkedAt: "2026-08-14T00:00:00+00:00",
      errorCode: null,
    });
    render(
      <App
        services={services({
          checkForUpdates: vi.fn().mockResolvedValue({
            state: "failed",
            currentVersion: "1.0.0",
            availableVersion: null,
            updateAvailable: false,
            checkedAt: "2026-08-14T00:00:00+00:00",
            errorCode: "update_check_failed",
          }),
          importUpdatePackage,
          installUpdate: vi.fn(),
        })}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "版本更新" }));
    expect(screen.getByRole("heading", { name: "软件更新" })).toBeVisible();
    expect(screen.getByRole("button", { name: "检查更新" })).toBeVisible();
    expect(screen.getByRole("button", { name: "导入更新包" })).toBeDisabled();
  });

  it("blocks the console when frontend and backend versions differ", async () => {
    render(
      <App
        services={services({
          bootstrap: vi.fn().mockRejectedValue(new ApiVersionMismatchError()),
        })}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "操作台版本不一致" }),
    ).toBeVisible();
    expect(screen.queryByRole("button", { name: "开始审核" })).toBeNull();
  });

  it("subscribes only after loading the confirmed snapshot cursor", async () => {
    const subscribe = vi.fn().mockReturnValue(() => undefined);
    const loadSnapshot = vi.fn().mockResolvedValue({
      ...emptySnapshot,
      eventCursor: 12,
    });

    render(<App services={services({ loadSnapshot, subscribe })} />);

    await waitFor(() => expect(subscribe).toHaveBeenCalledOnce());
    expect(subscribe).toHaveBeenCalledWith(12, expect.any(Function));
    expect(loadSnapshot.mock.invocationCallOrder[0]).toBeLessThan(
      subscribe.mock.invocationCallOrder[0],
    );
  });
});
