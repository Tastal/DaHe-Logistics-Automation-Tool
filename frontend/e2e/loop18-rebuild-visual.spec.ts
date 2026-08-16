import { expect, type Page, test } from "@playwright/test";

const businessDate = "2026-08-15";
const subjectCode = "shanxi_guienbo";

const action = (label: string, enabled = true) => ({
  visible: true,
  enabled,
  reason: enabled ? null : "当前阶段不可用",
  label,
  expected_record_version: 1,
});

const job = (taskType: "settlement_capture" | "daily") => ({
  job_id: `${taskType}-visual-job`,
  task_type: taskType,
  job_kind: "business",
  display_name: taskType === "daily" ? "装卸车明细数据获取" : "运费结算数据获取",
  scope_label: taskType === "daily" ? `装卸车明细 ${businessDate}` : "运费结算",
  run_mode: "operational",
  job_status: "running",
  status_label: "运行中",
  current_stage: "offline_review",
  current_stage_label: "正在离线审核",
  active_stage_labels: ["正在离线审核"],
  active_resources: [],
  waiting_reason: null,
  latest_checkpoint_label: "已完成 3/10",
  progress_label: "正在离线审核 3/10",
  diagnostic_code: null,
  record_version: 1,
  counts: { total: 10, processed: 3, remaining: 7, waiting_user: 0, failed: 0 },
  actions: {
    pause: action("暂停"),
    resume: action("继续", false),
    cancel: action("取消"),
  },
  created_at: "2026-08-15T14:00:00+08:00",
  updated_at: "2026-08-15T14:00:18+08:00",
});

const progress = (taskType: "settlement_capture" | "daily") => ({
  job_id: `${taskType}-visual-job`,
  phase: "offline_review",
  phase_label: "正在离线审核",
  progress_current: 3,
  progress_total: 10,
  fetched: 10,
  recognized: 3,
  missing_fields: 0,
  technical_failed: 0,
  committed_batches: 0,
  started_at: "2026-08-15T14:00:00+08:00",
  phase_started_at: "2026-08-15T14:00:12+08:00",
  updated_at: "2026-08-15T14:00:18+08:00",
  finished_at: null,
  elapsed_seconds: 18,
  estimated_remaining_seconds: 42,
  estimate_state: "estimated",
  is_terminal: false,
  source_job_id: `${taskType}-visual-job`,
  source_record_version: 1,
  capture_mode: "whole_run_v1",
  visible_prefix_count: 3,
  online_capture_complete: true,
  review_job: job(taskType),
});

const dailyFields = {
  loading_net_tonnes: "33.08",
  loading_time: "2026-08-15T14:08:12+08:00",
  unloading_net_tonnes: "33.04",
  unloading_time: "2026-08-15T18:42:00+08:00",
};

const settlementItem = {
  work_item_id: "visual-settlement-item",
  job_id: "settlement_capture-visual-job",
  waybill_id: "SXYD-VISUAL-001",
  vehicle_number: "陕A00001",
  record_version: 1,
  status: "waiting_user",
  business_outcome: "awaiting_review",
  decision: "review",
  review_reason: "numeric_mismatch",
  review_highlight_roles: ["loading"],
  diagnostic_code: null,
  platform_loading_net: "33.10",
  platform_unloading_net: "33.04",
  ticket_loading_net: "33.08",
  ticket_unloading_net: "33.04",
  loading_image_sha256: null,
  unloading_image_sha256: null,
  run_mode: "operational",
  available_actions: {
    confirm_normal: action("确认无误"),
    confirm_problem: action("异常"),
  },
  timeline: [],
  review_actions: [],
};

async function installVisualRoutes(page: Page) {
  await page.addInitScript((date) => {
    localStorage.setItem("dahe:last-daily-business-date", date);
    localStorage.setItem("dahe:last-page", "settlement");
  }, businessDate);

  await page.route(/\/api\/v1\/session$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      application_version: "1.1.4",
      csrf_token: "visual-csrf",
      production_read_only: true,
      locked_set_review_enabled: false,
      loop9_review_enabled: false,
    }),
  }));
  await page.route(/\/api\/v1\/system\/readiness$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ application_version: "1.1.4" }),
  }));
  await page.route(/\/api\/v1\/jobs$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      event_cursor: 1,
      jobs: [job("settlement_capture"), job("daily")],
      resources: [],
      start_actions: {
        start_operational_settlement: action("启动"),
        start_operational_daily: action("启动"),
      },
    }),
  }));
  await page.route(/\/api\/v1\/resources$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ resources: [] }),
  }));
  await page.route(/\/api\/v1\/platform\/session$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      enabled: true,
      run_mode: "operational",
      connection_mode: "operational_compat",
      connection_mode_label: "业务连接",
      connection_mode_record_version: 1,
      browser_lifecycle: "ready",
      browser_control_mode: "automated",
      record_version: 1,
      runtime_available: true,
      runtime_running: true,
      selected_browser: "Microsoft Edge",
      discovery_capturing: false,
      visible_browser_running: true,
      control_mode: "automated",
      human_handoff_ready: false,
      login_state: "authenticated",
      active_job_id: "daily-visual-job",
      warm_session_reusable: true,
      connection_status: { code: "reading", label: "正在读取" },
      contract_subject: {
        available_subjects: [
          { code: "shanxi_guienbo", label: "山西贵恩博" },
          { code: "shanghai_jinyisheng", label: "上海晋亿晟" },
        ],
        current_subject_code: subjectCode,
        record_version: 1,
        updated_at: "2026-08-15T14:00:00+08:00",
      },
      contract_candidate_selected: true,
      contract_selection_sha256: "a".repeat(64),
      access_window: null,
      business_session: null,
      waiting_reason: null,
      available_actions: {},
    }),
  }));
  await page.route(/\/api\/v1\/system\/update-status$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      state: "up_to_date",
      current_version: "1.1.4",
      available_version: null,
      update_available: false,
      checked_at: "2026-08-15T14:00:00+08:00",
      error_code: null,
    }),
  }));
  await page.route(/\/api\/v1\/settlement\/workspace(?:\?.*)?$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      latest_fetch: {
        created_at: "2026-08-15T14:00:00+08:00",
        started_at: "2026-08-15T14:00:00+08:00",
        phase_started_at: "2026-08-15T14:00:12+08:00",
        updated_at: "2026-08-15T14:00:18+08:00",
        finished_at: null,
        elapsed_seconds: 18,
        estimated_remaining_seconds: 42,
        estimate_state: "estimated",
        is_terminal: false,
        status: "offline_review",
        is_complete: false,
        phase_label: "正在离线审核",
        progress_current: 3,
        progress_total: 10,
        fetched_count: 10,
        recognized_count: 3,
        technical_failure_count: 0,
        source_job_id: "settlement_capture-visual-job",
        source_record_version: 1,
        capture_mode: "whole_run_v1",
        visible_prefix_count: 3,
        online_capture_complete: true,
      },
      items: [settlementItem],
      counts: { all: 1, waiting_review: 1, confirmed_problem: 0, normal_ready: 0 },
    }),
  }));
  await page.route(/\/api\/v1\/platform\/business-reads\/(?:settlement_capture|daily)-visual-job\/progress$/, (route) => {
    const kind = route.request().url().includes("settlement_capture") ? "settlement_capture" : "daily";
    return route.fulfill({ contentType: "application/json", body: JSON.stringify(progress(kind)) });
  });
  await page.route(/\/api\/v1\/platform\/business-reads\/(?:settlement_capture|daily)-visual-job\/progress\/stream(?:\?.*)?$/, (route) => {
    const kind = route.request().url().includes("settlement_capture") ? "settlement_capture" : "daily";
    return route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: `event: progress\ndata: ${JSON.stringify(progress(kind))}\n\n`,
    });
  });
  const image = "<svg xmlns='http://www.w3.org/2000/svg' width='720' height='480'><rect width='100%' height='100%' fill='#111'/><rect x='100' y='70' width='520' height='340' rx='12' fill='white'/><text x='50%' y='49%' text-anchor='middle' font-family='sans-serif' font-size='42'>脱敏磅单</text><text x='50%' y='62%' text-anchor='middle' font-family='sans-serif' font-size='30'>33.08 吨</text></svg>";
  await page.route(/\/api\/v1\/evidence\/[ab]{64}(?:\?.*)?$/, (route) => route.fulfill({
    contentType: "image/svg+xml",
    body: image,
  }));
  await page.route(/\/api\/v1\/daily\/items(?:\?.*)?$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      business_date: businessDate,
      contract_subject_code: subjectCode,
      counts: { all: 3, needs_review: 0, reviewed: 3 },
      source_job_id: "daily-visual-job",
      source_record_version: 1,
      capture_mode: "whole_run_v1",
      visible_prefix_count: 3,
      online_capture_complete: true,
      items: [1, 2, 3].map((index) => ({
        platform_waybill_id: `daily-visual-${index}`,
        waybill_number: `SXYD-VISUAL-${index.toString().padStart(3, "0")}`,
        vehicle_number: `陕A0000${index}`,
        loading_ticket: { sha256: "a".repeat(64), url: `/api/v1/evidence/${"a".repeat(64)}` },
        unloading_ticket: { sha256: "b".repeat(64), url: `/api/v1/evidence/${"b".repeat(64)}` },
        machine_fields: dailyFields,
        effective_fields: dailyFields,
        field_sources: Object.fromEntries(Object.keys(dailyFields).map((field) => [field, "machine"])),
        field_issues: Object.fromEntries(Object.keys(dailyFields).map((field) => [field, { has_issue: false, message: null }])),
        review_state: "reviewed",
        materialized_at: "2026-08-15T14:00:18+08:00",
        time_prefill: { loading_date: businessDate, unloading_date: businessDate },
        record_version: 1,
        updated_at: "2026-08-15T14:00:18+08:00",
      })),
    }),
  }));
  await page.route(/\/api\/v1\/daily\/report-settings$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({
      shipping_mine: "脱敏发运煤矿",
      coal_type: "煤炭",
      unloading_place: "脱敏卸货地点",
      query_place_keyword: "脱敏地点",
      output_directory: "D:\\脱敏报表",
      confirmed: true,
      record_version: 1,
      capture_start_time: "15:00:00",
      capture_end_mode: "fixed_time",
      capture_fixed_end_day_offset: 0,
      capture_fixed_end_time: "22:00:00",
      capture_range_covers_report_window: false,
    }),
  }));
  await page.route(/\/api\/v1\/daily\/reports(?:\?.*)?$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ report: null }),
  }));
}

async function openVisualConsole(page: Page) {
  await installVisualRoutes(page);
  await page.goto("/");
  await expect(page.locator(".product-title-stack:visible").first()).toBeVisible();
  await expect(page.locator(".application-version:visible").first()).toHaveText("v1.1.4");
}

const screens = [
  { name: "1366x768", width: 1366, height: 768 },
  { name: "1920x1080", width: 1920, height: 1080 },
  { name: "2560x1440", width: 2560, height: 1440 },
];
const scales = [100, 125, 150, 200];

for (const screen of screens) {
  for (const scale of scales) {
    test(`title layout ${screen.name} at ${scale}%`, async ({ page }) => {
      await page.setViewportSize({
        width: Math.floor(screen.width / (scale / 100)),
        height: Math.floor(screen.height / (scale / 100)),
      });
      await openVisualConsole(page);
      const title = page.locator(".product-title-stack:visible").first();
      const titleBox = await title.boundingBox();
      expect(titleBox).not.toBeNull();
      expect((titleBox?.x ?? 0) + (titleBox?.width ?? 0)).toBeLessThanOrEqual(
        page.viewportSize()?.width ?? 0,
      );
      await expect(title.locator("strong")).toHaveText(/大禾物流\s*自动化平台/);
      if ((page.viewportSize()?.width ?? 0) <= 800) {
        const viewportWidth = page.viewportSize()?.width ?? 0;
        const navigationButtons = await page
          .locator(".side-navigation button:visible")
          .evaluateAll((buttons) => buttons.map((button) => {
            const box = button.getBoundingClientRect();
            return { x: box.x, width: box.width };
          }));
        expect(navigationButtons.length).toBeGreaterThan(0);
        for (const button of navigationButtons) {
          expect(button.x).toBeGreaterThanOrEqual(0);
          expect(button.x + button.width).toBeLessThanOrEqual(viewportWidth);
        }
      }
      await page.screenshot({
        path: `../output/playwright/loop18-rebuild/title-${screen.name}-${scale}.png`,
        fullPage: true,
      });
    });
  }
}

test("settlement progress visual", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await openVisualConsole(page);
  await expect(page.locator(".workspace-progress-label")).toContainText("正在离线审核 3/10");
  await page.screenshot({ path: "../output/playwright/loop18-rebuild/settlement-progress.png", fullPage: true });
});

test("daily vehicle progress visual", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await openVisualConsole(page);
  await page.getByRole("button", { name: "装卸车明细" }).click();
  await expect(page.locator(".workspace-progress-label")).toContainText("正在离线审核 3/10");
  await expect(page.locator(".daily-item-row")).toHaveCount(3);
  await page.screenshot({ path: "../output/playwright/loop18-rebuild/daily-progress.png", fullPage: true });
});

test("daily report risk warning visual", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await openVisualConsole(page);
  await page.getByRole("button", { name: "系统设置", exact: true }).click();
  await page.getByRole("button", { name: "参数设置", exact: true }).click();
  const warning = page.getByText("当前下载范围可能未覆盖完整报表窗口（14:00 至次日 14:00）。");
  await expect(warning).toBeVisible();
  await warning.scrollIntoViewIfNeeded();
  await page.screenshot({ path: "../output/playwright/loop18-rebuild/daily-settings-warning.png", fullPage: true });
});

test("daily explicit blank save visual", async ({ page }) => {
  let reviewed = false;
  let submittedChanges: Record<string, unknown> | null = null;
  const blankItem = () => ({
    platform_waybill_id: "daily-blank-1",
    waybill_number: "SXYD-BLANK-001",
    vehicle_number: "陕A00001",
    loading_ticket: { sha256: "a".repeat(64), url: `/api/v1/evidence/${"a".repeat(64)}` },
    unloading_ticket: null,
    machine_fields: {
      ...dailyFields,
      unloading_net_tonnes: null,
      unloading_time: null,
    },
    effective_fields: {
      ...dailyFields,
      unloading_net_tonnes: null,
      unloading_time: null,
    },
    field_sources: {
      loading_net_tonnes: "machine",
      loading_time: "machine",
      unloading_net_tonnes: reviewed ? "manual" : "machine",
      unloading_time: reviewed ? "manual" : "machine",
    },
    field_issues: {
      loading_net_tonnes: { has_issue: false, message: null },
      loading_time: { has_issue: false, message: null },
      unloading_net_tonnes: {
        has_issue: !reviewed,
        message: reviewed ? null : "该字段尚未确认",
      },
      unloading_time: {
        has_issue: !reviewed,
        message: reviewed ? null : "该字段尚未确认",
      },
    },
    review_state: reviewed ? "reviewed" : "needs_review",
    materialized_at: "2026-08-15T14:00:18+08:00",
    time_prefill: { loading_date: businessDate, unloading_date: businessDate },
    record_version: reviewed ? 1000002 : 1000000,
    updated_at: "2026-08-15T14:00:18+08:00",
  });
  const workspace = () => ({
    business_date: businessDate,
    contract_subject_code: subjectCode,
    counts: {
      all: 1,
      needs_review: reviewed ? 0 : 1,
      reviewed: reviewed ? 1 : 0,
      complete: reviewed ? 1 : 0,
    },
    source_job_id: "daily-visual-job",
    source_record_version: 1,
    capture_mode: "whole_run_v1",
    visible_prefix_count: 1,
    online_capture_complete: true,
    items: [blankItem()],
  });

  await installVisualRoutes(page);
  await page.unroute(/\/api\/v1\/daily\/items(?:\?.*)?$/);
  await page.route(/\/api\/v1\/daily\/items(?:\?.*)?$/, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify(workspace()),
  }));
  await page.route(/\/api\/v1\/daily\/items\/daily-blank-1\/revisions$/, async (route) => {
    const payload = route.request().postDataJSON() as { changes: Record<string, unknown> };
    submittedChanges = payload.changes;
    reviewed = true;
    return route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        idempotent_replay: false,
        business_date: businessDate,
        contract_subject_code: subjectCode,
        item: blankItem(),
        counts: workspace().counts,
      }),
    });
  });

  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("/");
  await page.getByRole("button", { name: "装卸车明细" }).click();
  await expect(page.getByRole("button", { name: /待核对 1/ })).toBeVisible();
  await page.getByRole("button", { name: "保存", exact: true }).click();

  await expect(page.getByText("已保存，已移入已核对。")).toBeVisible();
  await expect(page.getByRole("button", { name: /待核对 0/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /已核对 1/ })).toBeVisible();
  expect(submittedChanges).toEqual({
    unloading_net_tonnes: null,
    unloading_time: null,
  });
  await expect(page.getByText("daily item processing is not complete")).toHaveCount(0);
  await page.screenshot({
    path: "../output/playwright/loop18-rebuild/daily-explicit-blank-saved.png",
    fullPage: true,
  });
});
