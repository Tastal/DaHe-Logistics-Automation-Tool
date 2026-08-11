import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AppServices, PlatformSession } from "../../app/contracts";
import { BusinessConnectionBar } from "./BusinessConnectionBar";

function session(overrides: Partial<PlatformSession> = {}): PlatformSession {
  return {
    enabled: true,
    runMode: "operational",
    connectionMode: "operational_compat",
    connectionModeLabel: "业务连接",
    connectionModeRecordVersion: 1,
    browserLifecycle: "stopped",
    browserControlMode: "idle",
    recordVersion: 1,
    runtimeAvailable: true,
    runtimeRunning: false,
    selectedBrowser: null,
    discoveryCapturing: false,
    visibleBrowserRunning: false,
    controlMode: "idle",
    humanHandoffReady: false,
    loginState: "unavailable",
    activeJobId: null,
    warmSessionReusable: false,
    contractCandidateSelected: true,
    contractSelectionSha256: "a".repeat(64),
    accessWindow: null,
    businessSession: null,
    waitingReason: null,
    availableActions: {
      create_access_window: { enabled: false, reason: null },
      switch_connection_mode: { enabled: true, reason: null },
      start_business_session: { enabled: false, reason: null },
      begin_business_read: { enabled: false, reason: null },
      close_business_session: { enabled: false, reason: null },
      start_operational_capture: { enabled: true, reason: null },
      start_human_login: { enabled: false, reason: null },
      return_human_login: { enabled: false, reason: null },
      start_discovery_capture: { enabled: false, reason: null },
      stop_discovery_capture: { enabled: false, reason: null },
      validate_read_contract: { enabled: false, reason: null },
      close_session: { enabled: false, reason: null },
    },
    ...overrides,
  };
}

describe("Business connection bar", () => {
  it("starts one read directly without daily confirmation fields", async () => {
    const start = vi.fn(async () => ({
      created: true,
      attached: false,
      job: {} as never,
    }));
    const services = {
      loadPlatformSession: vi.fn(async () => session()),
      startPlatformBusinessRead: start,
    } as unknown as AppServices;

    render(<BusinessConnectionBar services={services} />);
    await userEvent.click(await screen.findByRole("button", { name: "启动" }));

    expect(start).toHaveBeenCalledWith({
      businessScope: "settlement",
      expectedRecordVersion: 0,
    });
    expect(screen.queryByText("旧程序已完全停止")).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("leaves login coordination to the backend without frontend polling side effects", async () => {
    const loginSession = session({
      waitingReason: "login_required",
      accessWindow: {
        accessWindowId: "window-1",
        purpose: "production_shadow",
        expiresAt: "2026-08-01T12:00:00Z",
        consumedAt: null,
        expired: false,
        recordVersion: 1,
      },
      availableActions: {
        ...session().availableActions,
        start_human_login: { enabled: true, reason: null },
      },
    });
    const open = vi.fn(async () => loginSession);
    const returnControl = vi.fn(async () => loginSession);
    const services = {
      loadPlatformSession: vi.fn(async () => loginSession),
      startPlatformBusinessRead: vi.fn(),
      startPlatformHumanLogin: open,
      returnPlatformHumanLogin: returnControl,
    } as unknown as AppServices;

    render(
      <BusinessConnectionBar
        services={services}
        jobs={[
          {
            jobId: "capture-1",
            taskType: "settlement_capture",
            jobKind: "business",
            displayName: "运费结算数据获取",
            scopeLabel: "运费结算数据获取",
            runMode: "operational",
            jobStatus: "paused",
            statusLabel: "需要重新登录",
            currentStage: "settlement_capture.read",
            currentStageLabel: "正在登录平台",
            activeStageLabels: [],
            activeResources: [],
            waitingReason: "credential_required",
            latestCheckpointLabel: null,
            progressLabel: "正在登录平台",
            diagnosticCode: null,
            recordVersion: 4,
            counts: { total: 0, processed: 0, remaining: 0, waitingUser: 0, failed: 0 },
            actions: {},
          },
        ]}
      />,
    );

    expect(screen.getByRole("button", { name: "启动" })).toBeVisible();
    expect(screen.getByRole("status", { name: "正在登录平台" })).toBeVisible();
    expect(services.loadPlatformSession).not.toHaveBeenCalled();
    expect(open).not.toHaveBeenCalled();
    expect(returnControl).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "打开登录窗口" })).not.toBeInTheDocument();
  });
});
