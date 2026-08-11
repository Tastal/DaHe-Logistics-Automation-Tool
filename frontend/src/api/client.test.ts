import { afterEach, describe, expect, it, vi } from "vitest";

import { BrowserAppServices } from "./client";

class FakeEventSource {
  static instances: FakeEventSource[] = [];

  readonly close = vi.fn();
  onmessage: ((message: MessageEvent<string>) => void) | null = null;

  constructor(
    readonly url: string | URL,
    readonly options?: EventSourceInit,
  ) {
    FakeEventSource.instances.push(this);
  }

  emit(payload: object) {
    this.onmessage?.(
      new MessageEvent("message", { data: JSON.stringify(payload) }),
    );
  }
}

afterEach(() => {
  FakeEventSource.instances = [];
  vi.unstubAllGlobals();
});

describe("BrowserAppServices", () => {
  it("maps an active production policy without a first-batch guard", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            application_version: "1.0.0",
            csrf_token: "csrf-production",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            status: "operational_read_only_active",
            target_count: 30,
            registered_count: 2,
            reviewed_count: 0,
            false_normal_count: 0,
            guard_active: false,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const service = new BrowserAppServices();
    await service.bootstrap();

    await expect(service.loadProductionReadOnlyStatus()).resolves.toEqual({
      status: "operational_read_only_active",
      targetCount: 30,
      registeredCount: 2,
      reviewedCount: 0,
      falseNormalCount: 0,
      guardActive: false,
    });
  });

  it("maps Loop 9 platform state and creates only the fixed discovery window", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            application_version: "1.0.0",
            csrf_token: "csrf-loop9",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            enabled: true,
            run_mode: "shadow",
            connection_mode: "strict_shadow",
            connection_mode_label: "验证连接",
            connection_mode_record_version: 1,
            browser_lifecycle: "stopped",
            browser_control_mode: "idle",
            record_version: 1,
            runtime_available: true,
            runtime_running: false,
            selected_browser: null,
            discovery_capturing: false,
            contract_candidate_selected: false,
            contract_selection_sha256: null,
            access_window: null,
            waiting_reason: "access_window_required",
            available_actions: {
              create_access_window: { enabled: true, reason: null },
              switch_connection_mode: { enabled: true, reason: null },
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
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_window: {
              access_window_id: "window-one",
              purpose: "contract_discovery",
              expires_at: "2026-07-28T13:00:00+00:00",
              consumed_at: null,
              expired: false,
              record_version: 1,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "loop9-key" });
    const service = new BrowserAppServices();
    await service.bootstrap();

    await expect(service.loadPlatformSession()).resolves.toMatchObject({
      enabled: true,
      runtimeAvailable: true,
      browserControlMode: "idle",
    });
    await service.createPlatformAccessWindow({
      purpose: "contract_discovery",
      legacyIdleConfirmed: true,
      noSettlementOrPaymentConfirmed: true,
      sameAccountSessionRiskAccepted: true,
    });

    const create = fetchMock.mock.calls[2];
    expect(create?.[0]).toBe("/api/v1/platform/access-windows");
    expect(JSON.parse(String((create?.[1] as RequestInit).body))).toEqual({
      purpose: "contract_discovery",
      job_id: "loop9-contract-discovery-loop9-key",
      duration_minutes: 60,
      legacy_idle_confirmed: true,
      no_settlement_or_payment_confirmed: true,
      same_account_session_risk_accepted: true,
      expected_record_version: 0,
    });
  });

  it("maps Loop 3 job projections and backend action versions", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            event_cursor: 21,
            start_actions: {
              start_audit_long: {
                visible: true,
                enabled: true,
                reason: null,
                label: "启动长批次审核演练",
                expected_record_version: 3,
              },
            },
            jobs: [
              {
                job_id: "job-long",
                task_type: "audit",
                job_kind: "test_fixture",
                display_name: "并行审核演练（长批次）",
                scope_label: "30 条冻结假运单",
                run_mode: "shadow",
                job_status: "waiting_resource",
                status_label: "等待图像识别设备",
                current_stage: "audit.recognize",
                current_stage_label: "等待识别磅单",
                active_stage_labels: ["等待识别磅单", "正在核对数字"],
                active_resources: [
                  {
                    resource_id: "platform_browser",
                    display_name: "成丰窗口",
                  },
                ],
                waiting_reason: "图像识别设备当前无空闲位置",
                latest_checkpoint_label: "已保存 12 条结果",
                progress_label: "已处理 12/30",
                diagnostic_code: null,
                record_version: 8,
                counts: {
                  total: 30,
                  processed: 12,
                  remaining: 18,
                  waiting_user: 0,
                  failed: 0,
                },
                actions: {
                  pause: {
                    visible: true,
                    enabled: true,
                    reason: null,
                    label: "暂停此任务",
                    expected_record_version: 8,
                  },
                },
              },
            ],
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    const snapshot = await new BrowserAppServices().loadSnapshot();

    expect(snapshot.startActions.start_audit_long).toMatchObject({
      expectedRecordVersion: 3,
    });
    expect(snapshot.jobs[0]).toMatchObject({
      jobKind: "test_fixture",
      currentStageLabel: "等待识别磅单",
      activeStageLabels: ["等待识别磅单", "正在核对数字"],
      activeResources: [
        {
          resourceId: "platform_browser",
          displayName: "成丰窗口",
        },
      ],
      waitingReason: "图像识别设备当前无空闲位置",
      latestCheckpointLabel: "已保存 12 条结果",
      actions: {
        pause: {
          expectedRecordVersion: 8,
        },
      },
    });
  });

  it("loads the resource overview from its dedicated endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          resources: [
            {
              resource_id: "gpu_ocr_slot",
              display_name: "图像识别设备",
              status_label: "使用中，1 个任务等待",
              capacity: 1,
              in_use: 1,
              waiting_jobs: 1,
              holder_label: "并行审核演练（长批次）",
            },
          ],
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const resources = await new BrowserAppServices().loadResources();

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/resources",
      expect.objectContaining({ cache: "no-store" }),
    );
    expect(resources).toEqual([
      {
        resourceId: "gpu_ocr_slot",
        displayName: "图像识别设备",
        statusLabel: "使用中，1 个任务等待",
        capacity: 1,
        inUse: 1,
        waitingJobs: 1,
        holderLabel: "并行审核演练（长批次）",
      },
    ]);
  });

  it.each(["pause", "resume", "cancel"] as const)(
    "posts %s with its own expected version and idempotency key",
    async (actionId) => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            application_version: "1.0.0",
            csrf_token: "csrf-loop3",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "job-action-key" });
    const service = new BrowserAppServices();
    await service.bootstrap();

      await service.runJobAction("job short", actionId, 9);

      expect(fetchMock).toHaveBeenLastCalledWith(
        `/api/v1/jobs/job%20short/${actionId}`,
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "X-CSRF-Token": "csrf-loop3",
            "X-Idempotency-Key": "job-action-key",
          }),
          body: JSON.stringify({ expected_record_version: 9 }),
        }),
      );
    },
  );

  it("reuses the same job-action idempotency key after an uncertain failure", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            application_version: "1.0.0",
            csrf_token: "csrf-loop3",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({}), {
          status: 503,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    const randomUUID = vi.fn().mockReturnValue("stable-action-key");
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID });
    const service = new BrowserAppServices();
    await service.bootstrap();

    await expect(
      service.runJobAction("job-1", "cancel", 12),
    ).rejects.toThrow("status 503");
    await service.runJobAction("job-1", "cancel", 12);

    const firstHeaders = (
      fetchMock.mock.calls[1]?.[1] as RequestInit
    ).headers as Record<string, string>;
    const retryHeaders = (
      fetchMock.mock.calls[2]?.[1] as RequestInit
    ).headers as Record<string, string>;
    expect(firstHeaders["X-Idempotency-Key"]).toBe("stable-action-key");
    expect(retryHeaders["X-Idempotency-Key"]).toBe("stable-action-key");
    expect(randomUUID).toHaveBeenCalledTimes(1);
  });

  it("creates only a declared protected Loop 3 fixture", async () => {
    const createdJob = {
      job_id: "job-probe",
      task_type: "loading_probe",
      job_kind: "test_fixture",
      display_name: "装卸车并行调度探针",
      scope_label: "受保护调度演练",
      run_mode: "shadow",
      job_status: "queued",
      status_label: "等待开始调度演练",
      current_stage: "loading_probe.acquire_browser",
      current_stage_label: "等待申请成丰窗口",
      active_stage_labels: [],
      active_resources: [],
      waiting_reason: null,
      latest_checkpoint_label: null,
      progress_label: "任务已经建立",
      diagnostic_code: null,
      record_version: 1,
      counts: {
        total: 1,
        processed: 0,
        remaining: 1,
        waiting_user: 0,
        failed: 0,
      },
      actions: {},
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            application_version: "1.0.0",
            csrf_token: "csrf-loop3",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            created: true,
            job: createdJob,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "fixture-create-key" });
    const service = new BrowserAppServices();
    await service.bootstrap();

    await service.createFixtureJob("loading-probe-001", 5);

    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/jobs",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "X-Idempotency-Key": "fixture-create-key",
        }),
        body: JSON.stringify({
          task_type: "loading_probe",
          job_kind: "test_fixture",
          scope: {
            label: "装卸车并行调度探针",
            fixture_id: "loading-probe-001",
          },
          expected_record_version: 5,
        }),
      }),
    );
  });

  it("maps a failed job diagnostic code from the backend snapshot", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            event_cursor: 4,
            resources: [],
            start_actions: {},
            jobs: [
              {
                job_id: "job-failed",
                task_type: "audit",
                display_name: "单条假数据审核",
                scope_label: "单条假数据审核",
                run_mode: "shadow",
                job_status: "failed",
                status_label: "本任务处理失败",
                current_stage: "audit.recognize",
                progress_label: "正在识别磅单，已处理 0/1",
                diagnostic_code: "LOOP2-TEST-FAILURE",
                record_version: 4,
                counts: {
                  total: 1,
                  processed: 1,
                  remaining: 0,
                  waiting_user: 0,
                  failed: 1,
                },
                actions: {},
              },
            ],
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    const snapshot = await new BrowserAppServices().loadSnapshot();

    expect(snapshot.jobs[0]?.diagnosticCode).toBe("LOOP2-TEST-FAILURE");
  });

  it("maps the real job-items endpoint into finance-facing result data", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              work_item_id: "item-1",
              record_version: 4,
              waybill_number: "TEST-20260725-001",
              vehicle_number: "测试车辆01",
              status: "succeeded",
              current_stage: "audit.finalize",
              business_outcome: "normal_ready",
              is_terminal_outcome: true,
              platform_loading_net: "30.00",
              platform_unloading_net: "29.80",
              ticket_loading_net: "30.00",
              ticket_unloading_net: "29.80",
              decision: "pass",
              review_reason: null,
            },
          ],
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await new BrowserAppServices().loadJobItems("job 1");

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/jobs/job%201/items",
      expect.objectContaining({ cache: "no-store" }),
    );
    expect(result).toEqual([
      {
        workItemId: "item-1",
        recordVersion: 4,
        waybillNumber: "TEST-20260725-001",
        vehicleNumber: "测试车辆01",
        status: "succeeded",
        currentStage: "audit.finalize",
        businessOutcome: "normal_ready",
        isTerminalOutcome: true,
        platformLoadingNet: "30.00",
        platformUnloadingNet: "29.80",
        ticketLoadingNet: "30.00",
        ticketUnloadingNet: "29.80",
        decision: "pass",
        reviewReason: null,
      },
    ]);
  });

  it("maps aggregate_id from a fake EventSource message and closes the stream", () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    const onEvent = vi.fn();
    const unsubscribe = new BrowserAppServices().subscribe(7, onEvent);
    const source = FakeEventSource.instances[0];

    expect(source.url).toContain("/api/v1/events?after=7");
    source.emit({
      event_id: 8,
      aggregate_id: "job-1",
      record_version: 3,
    });

    expect(onEvent).toHaveBeenCalledWith({
      eventId: 8,
      aggregateId: "job-1",
      recordVersion: 3,
    });
    unsubscribe();
    expect(source.close).toHaveBeenCalledTimes(1);
  });
});
