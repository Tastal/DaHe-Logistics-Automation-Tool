import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AppServices, PlatformSession } from "../../app/contracts";
import { PlatformSessionPanel } from "./PlatformSessionPanel";

function session(overrides: Partial<PlatformSession> = {}): PlatformSession {
  return {
    enabled: true,
    runMode: "shadow",
    connectionMode: "strict_shadow",
    connectionModeLabel: "验证连接",
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
    contractCandidateSelected: false,
    contractSelectionSha256: null,
    accessWindow: null,
    businessSession: null,
    waitingReason: "access_window_required",
    availableActions: {
      create_access_window: { enabled: true, reason: null },
      switch_connection_mode: { enabled: true, reason: null },
      start_business_session: { enabled: false, reason: "strict_connection" },
      begin_business_read: { enabled: false, reason: "strict_connection" },
      close_business_session: { enabled: false, reason: "strict_connection" },
      start_operational_capture: {
        enabled: false,
        reason: "business_connection_not_ready",
      },
      start_human_login: {
        enabled: false,
        reason: "access_window_or_browser_runtime_required",
      },
      return_human_login: {
        enabled: false,
        reason: "human_login_not_active",
      },
      start_discovery_capture: {
        enabled: false,
        reason: "login_return_required",
      },
      stop_discovery_capture: {
        enabled: false,
        reason: "contract_discovery_not_active",
      },
      validate_read_contract: {
        enabled: false,
        reason: "read_contract_candidate_required",
      },
      close_session: {
        enabled: false,
        reason: "browser_session_not_running",
      },
    },
    ...overrides,
  };
}

describe("Loop 9 platform session panel", () => {
  it("shows operational status without duplicating settlement actions", async () => {
    const operational = session({
      runMode: "operational",
      connectionMode: "operational_compat",
      connectionModeLabel: "业务连接",
      browserLifecycle: "ready",
      browserControlMode: "human_handoff",
      runtimeRunning: true,
      businessSession: {
        businessSessionId: "business-one",
        status: "active",
        expiresAt: "2026-08-01T12:00:00+00:00",
        expired: false,
        recordVersion: 2,
      },
    });
    render(
      <PlatformSessionPanel services={{
        loadPlatformSession: vi.fn(async () => operational),
      } as unknown as AppServices} />,
    );

    expect(await screen.findByText("人员正在使用平台")).toBeVisible();
    expect(screen.queryByRole("button", { name: "从成丰获取运单" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "交给程序继续读取" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "关闭成丰" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "切换到验证连接" })).toBeVisible();
  });

  it("requires all three current safety confirmations before creating a window", async () => {
    const create = vi.fn(async () => ({
      accessWindowId: "window-one",
      purpose: "contract_discovery" as const,
      expiresAt: "2026-07-28T13:00:00+00:00",
      consumedAt: null,
      expired: false,
      recordVersion: 1,
    }));
    const load = vi
      .fn<() => Promise<PlatformSession>>()
      .mockResolvedValueOnce(session())
      .mockResolvedValue(
        session({
          accessWindow: {
            accessWindowId: "window-one",
            purpose: "contract_discovery",
            expiresAt: "2026-07-28T13:00:00+00:00",
            consumedAt: null,
            expired: false,
            recordVersion: 1,
          },
          availableActions: {
            ...session().availableActions,
            start_human_login: { enabled: true, reason: null },
          },
        }),
      );
    const services = {
      loadPlatformSession: load,
      createPlatformAccessWindow: create,
    } as unknown as AppServices;
    const user = userEvent.setup();

    render(<PlatformSessionPanel services={services} />);

    const createButton = await screen.findByRole("button", {
      name: "建立 60 分钟只读窗口",
    });
    expect(createButton).toBeDisabled();
    await user.click(screen.getByLabelText("旧程序已完全停止"));
    await user.click(
      screen.getByLabelText("当前没有采集、下载、结算交接或付款"),
    );
    await user.click(
      screen.getByLabelText("接受新登录可能使旧程序登录态失效"),
    );
    expect(createButton).toBeEnabled();
    await user.click(createButton);

    expect(create).toHaveBeenCalledWith({
      purpose: "contract_discovery",
      legacyIdleConfirmed: true,
      noSettlementOrPaymentConfirmed: true,
      sameAccountSessionRiskAccepted: true,
    });
    expect(
      await screen.findByRole("button", { name: "打开成丰登录页" }),
    ).toBeEnabled();
  });

  it("shows the precise backend failure instead of a generic retry message", async () => {
    const active = session({
      accessWindow: {
        accessWindowId: "window-one",
        purpose: "contract_discovery",
        expiresAt: "2026-07-29T13:00:00+00:00",
        consumedAt: null,
        expired: false,
        recordVersion: 1,
      },
      availableActions: {
        ...session().availableActions,
        start_human_login: { enabled: true, reason: null },
        close_session: { enabled: true, reason: null },
      },
    });
    const services = {
      loadPlatformSession: vi.fn(async () => active),
      startPlatformHumanLogin: vi.fn(async () => {
        throw new Error("成丰登录页未能打开，受控浏览器已安全关闭。");
      }),
    } as unknown as AppServices;
    const user = userEvent.setup();

    render(<PlatformSessionPanel services={services} />);

    await user.click(
      await screen.findByRole("button", { name: "打开成丰登录页" }),
    );
    expect(
      await screen.findByText("成丰登录页未能打开，受控浏览器已安全关闭。"),
    ).toBeVisible();
  });

  it("does not expose an active control when real access is disabled", async () => {
    const services = {
      loadPlatformSession: vi.fn(async () =>
        session({
          enabled: false,
          runtimeAvailable: false,
          waitingReason: "real_platform_access_disabled",
          availableActions: {
            ...session().availableActions,
            create_access_window: {
              enabled: false,
              reason: "real_platform_access_disabled",
            },
          },
        }),
      ),
    } as unknown as AppServices;

    render(<PlatformSessionPanel services={services} />);

    expect(await screen.findByText("未启用")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "建立 60 分钟只读窗口" }),
    ).toBeDisabled();
    expect(screen.queryByLabelText("旧程序已完全停止")).not.toBeInTheDocument();
  });

  it("shows direct read-only instructions while discovery capture is active", async () => {
    const stop = vi.fn(async () => ({
      evidenceId: "a".repeat(64),
      canonicalSha256: "a".repeat(64),
      observationCount: 4,
    }));
    const active = session({
      browserLifecycle: "ready",
      browserControlMode: "human_handoff",
      recordVersion: 5,
      runtimeRunning: true,
      discoveryCapturing: true,
      accessWindow: {
        accessWindowId: "window-one",
        purpose: "contract_discovery",
        expiresAt: "2026-07-29T13:00:00+00:00",
        consumedAt: null,
        expired: false,
        recordVersion: 1,
      },
      availableActions: {
        ...session().availableActions,
        stop_discovery_capture: { enabled: true, reason: null },
        close_session: { enabled: true, reason: null },
      },
    });
    const services = {
      loadPlatformSession: vi
        .fn<() => Promise<PlatformSession>>()
        .mockResolvedValueOnce(active)
        .mockResolvedValue(
          session({
            enabled: true,
            browserLifecycle: "stopped",
          }),
        ),
      stopPlatformDiscoveryCapture: stop,
    } as unknown as AppServices;
    const user = userEvent.setup();

    render(<PlatformSessionPanel services={services} />);

    expect(
      await screen.findByText(/只查看待结算列表、打开一条运单详情和两张磅单/),
    ).toBeVisible();
    await user.click(screen.getByRole("button", { name: "停止并封存" }));
    expect(stop).toHaveBeenCalledWith("window-one", 5);
    expect(await screen.findByText(/共记录 4 条脱敏结构/)).toBeVisible();
  });

  it("runs the selected contract validation without discovery controls", async () => {
    const validate = vi.fn(async () => ({
      evidenceId: "a".repeat(64),
      canonicalSha256: "a".repeat(64),
      selectionSha256: "b".repeat(64),
      listItemCount: 20,
      detailAttemptCount: 1,
      imageCount: 2,
    }));
    const active = session({
      contractCandidateSelected: true,
      contractSelectionSha256: "b".repeat(64),
      browserLifecycle: "ready",
      runtimeRunning: true,
      recordVersion: 4,
      accessWindow: {
        accessWindowId: "window-validation",
        purpose: "formal_locked_set",
        expiresAt: "2026-07-29T13:00:00+00:00",
        consumedAt: null,
        expired: false,
        recordVersion: 1,
      },
      availableActions: {
        ...session().availableActions,
        validate_read_contract: { enabled: true, reason: null },
        close_session: { enabled: true, reason: null },
      },
    });
    const services = {
      loadPlatformSession: vi
        .fn<() => Promise<PlatformSession>>()
        .mockResolvedValueOnce(active)
        .mockResolvedValue(session({ contractCandidateSelected: true })),
      validatePlatformReadContract: validate,
    } as unknown as AppServices;
    const user = userEvent.setup();

    render(<PlatformSessionPanel services={services} />);

    expect(
      screen.queryByRole("button", { name: "开始记录只读结构" }),
    ).not.toBeInTheDocument();
    await user.click(
      await screen.findByRole("button", { name: "验证只读合同" }),
    );
    expect(validate).toHaveBeenCalledWith("window-validation", 4);
    expect(await screen.findByText(/2 张磅单图片均通过安全边界/)).toBeVisible();
  });
});
