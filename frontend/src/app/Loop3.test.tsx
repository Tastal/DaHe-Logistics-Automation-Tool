import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  App,
  type AppServices,
  type ConsoleSnapshot,
  type JobSummary,
} from "./App";

function action(label: string, version: number, enabled = true) {
  return {
    visible: true,
    enabled,
    reason: enabled ? null : "当前不可用",
    label,
    expectedRecordVersion: version,
  };
}

function job(
  jobId: string,
  displayName: string,
  overrides: Partial<JobSummary> = {},
): JobSummary {
  return {
    jobId,
    taskType: "audit",
    jobKind: "business",
    displayName,
    scopeLabel: displayName,
    runMode: "shadow",
    jobStatus: "running",
    statusLabel: "正在处理",
    currentStage: "audit.recognize",
    currentStageLabel: "正在识别磅单",
    activeStageLabels: ["正在识别磅单"],
    activeResources: [{ resourceId: "gpu", displayName: "图像识别设备" }],
    waitingReason: null,
    latestCheckpointLabel: "运单清单已经保存",
    progressLabel: "已处理 2/10",
    diagnosticCode: null,
    recordVersion: 10,
    counts: {
      total: 10,
      processed: 2,
      remaining: 8,
      waitingUser: 0,
      failed: 0,
    },
    actions: {
      pause: action("暂停此任务", 10),
      cancel: action("取消此任务", 10),
    },
    ...overrides,
  };
}

const longJob = job("job-long", "并行审核演练（长批次）");
const shortJob = job("job-short", "并行审核演练（短批次）", {
  jobStatus: "waiting_resource",
  statusLabel: "等待本地资源",
  currentStageLabel: "等待识别磅单",
  activeResources: [],
  waitingReason: "图像识别设备正由长批次使用，当前任务已进入公平队列",
  recordVersion: 19,
  actions: {
    pause: action("暂停短批次", 19),
    cancel: action("取消短批次", 19),
  },
});
const loadingProbe = job("job-loading", "装卸车并行调度探针", {
  taskType: "loading_details",
  jobKind: "test_fixture",
  activeResources: [{ resourceId: "browser", displayName: "平台浏览器" }],
});

const snapshot: ConsoleSnapshot = {
  eventCursor: 8,
  jobs: [longJob, shortJob, loadingProbe],
  resources: [
    {
      resourceId: "gpu",
      displayName: "图像识别设备",
      statusLabel: "使用中",
      capacity: 1,
      inUse: 1,
      waitingJobs: 1,
      holderLabel: "并行审核演练（长批次）",
    },
  ],
  startActions: {
    start_audit: {
      visible: true,
      enabled: false,
      reason: "相同审核范围已经运行",
      label: "开始审核",
      expectedRecordVersion: 3,
    },
    start_audit_long: action("启动长批次审核演练", 3, false),
    start_audit_short: action("启动短批次审核演练", 4),
    start_loading_probe: action("启动装卸车调度演练", 5),
  },
};

function services(overrides: Partial<AppServices> = {}): AppServices {
  return {
    bootstrap: vi.fn().mockResolvedValue({
      applicationVersion: "1.0.0",
      csrfToken: "csrf-test",
      lockedSetReviewEnabled: false,
    }),
    loadSnapshot: vi.fn().mockResolvedValue(snapshot),
    loadResources: vi.fn().mockResolvedValue(snapshot.resources),
    loadJobItems: vi.fn().mockResolvedValue([]),
    createAuditJob: vi.fn(),
    createFixtureJob: vi.fn().mockResolvedValue({
      created: true,
      job: loadingProbe,
    }),
    subscribe: vi.fn().mockReturnValue(() => undefined),
    runJobAction: vi.fn().mockResolvedValue(undefined),
    loadSettlementWorkspace: vi.fn().mockResolvedValue({
      latestFetch: null,
      items: [],
      counts: { all: 0, waiting_review: 0, confirmed_problem: 0, normal_ready: 0 },
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
    loadWaybillHistory: vi.fn().mockResolvedValue([]),
    ...overrides,
  };
}

describe("B version multi-job controls", () => {
  it("controls the latest settlement capture without exposing audit batches", async () => {
    const runJobAction = vi.fn().mockResolvedValue(undefined);
    const captureJob = job("capture-latest", "运费结算数据获取", {
      taskType: "settlement_capture",
      runMode: "operational",
      actions: {
        pause: action("暂停获取", 10),
        cancel: action("取消获取", 10),
      },
    });
    render(
      <App
        services={services({
          runJobAction,
          startPlatformBusinessRead: vi.fn(),
          loadSnapshot: vi.fn().mockResolvedValue({ ...snapshot, jobs: [longJob, captureJob] }),
        })}
      />,
    );

    expect(screen.queryByRole("combobox", { name: "审核批次" })).toBeNull();
    expect(await screen.findByRole("button", { name: "暂停" })).toBeDisabled();
    expect(runJobAction).not.toHaveBeenCalled();
  });

  it("keeps protected fixture actions in the System developer area", async () => {
    const user = userEvent.setup();
    const createFixtureJob = vi.fn().mockResolvedValue({
      created: true,
      job: loadingProbe,
    });
    render(<App services={services({ createFixtureJob })} />);

    await user.click(await screen.findByRole("button", { name: "系统设置" }));
    await user.hover(
      screen.getByRole("button", { name: "启动装卸车调度演练" }),
    );
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "调度演练，不是正式装卸车业务",
    );
    expect(
      screen.getByRole("button", { name: "启动长批次审核演练" }),
    ).toBeDisabled();
    await user.click(
      screen.getByRole("button", { name: "启动装卸车调度演练" }),
    );
    expect(createFixtureJob).toHaveBeenCalledWith("loading-probe-001", 5);
  });

  it("does not expose scheduler jobs or local resources in the operator system view", async () => {
    const user = userEvent.setup();
    render(<App services={services()} />);

    await user.click(await screen.findByRole("button", { name: "系统设置" }));

    expect(screen.queryByRole("region", { name: "任务" })).toBeNull();
    expect(screen.queryByRole("region", { name: "本地资源" })).toBeNull();
    expect(screen.queryByText("并行审核演练（长批次）")).toBeNull();
    expect(screen.queryByText("图像识别设备")).toBeNull();
  });

  it("keeps waiting-user scheduler details out of the operator system view", async () => {
    const user = userEvent.setup();
    const waitingUser = job("job-review", "等待人员判断的审核", {
      jobStatus: "waiting_user",
      statusLabel: "等待人员判断",
      currentStage: "audit.review",
      currentStageLabel: "等待核对疑似问题",
      activeStageLabels: ["等待核对疑似问题"],
      activeResources: [],
      waitingReason: "有 2 条运单需要人员判断",
      latestCheckpointLabel: "自动识别结果已经保存",
    });
    render(
      <App
        services={services({
          loadSnapshot: vi.fn().mockResolvedValue({
            ...snapshot,
            jobs: [waitingUser],
          }),
        })}
      />,
    );

    await user.click(await screen.findByRole("button", { name: "系统设置" }));
    expect(screen.queryByText(/有 2 条运单需要人员判断/)).toBeNull();
    expect(screen.queryByText("当前未占用自动处理资源")).toBeNull();
    expect(screen.queryByText(/自动识别结果已经保存/)).toBeNull();
  });
});
