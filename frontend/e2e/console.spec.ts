import { expect, type Page, test } from "@playwright/test";

const settlementItem = {
  work_item_id: "e2e-review-item",
  job_id: "e2e-review-job",
  waybill_id: "E2E-REVIEW-001",
  vehicle_number: "测试车辆01",
  record_version: 1,
  status: "waiting_user",
  business_outcome: "awaiting_review",
  decision: "review",
  review_reason: "numeric_mismatch",
  diagnostic_code: null,
  platform_loading_net: "30.00",
  platform_unloading_net: "29.80",
  ticket_loading_net: "30.00",
  ticket_unloading_net: "29.70",
  loading_image_sha256: null,
  unloading_image_sha256: null,
  run_mode: "operational",
  available_actions: {
    confirm_normal: { visible: true, enabled: true, reason: null },
    confirm_problem: { visible: true, enabled: true, reason: null },
  },
  timeline: [],
  review_actions: [],
};

function settlementWorkspace(outcome = "awaiting_review") {
  const item = {
    ...settlementItem,
    record_version: outcome === "awaiting_review" ? 1 : 2,
    status: outcome === "awaiting_review" ? "waiting_user" : "succeeded",
    business_outcome: outcome,
    decision: outcome === "confirmed_problem" ? "problem" : outcome === "normal_ready" ? "pass" : "review",
  };
  return {
    latest_fetch: {
      created_at: "2026-08-07T09:00:00Z",
      updated_at: "2026-08-07T09:02:00Z",
      status: "complete",
      is_complete: true,
      phase_label: "已完成",
      progress_current: 1,
      progress_total: 1,
      fetched_count: 1,
      recognized_count: 1,
      technical_failure_count: 0,
    },
    items: [item],
    counts: {
      all: 1,
      waiting_review: outcome === "awaiting_review" ? 1 : 0,
      confirmed_problem: outcome === "confirmed_problem" ? 1 : 0,
      normal_ready: outcome === "normal_ready" ? 1 : 0,
    },
  };
}

async function installSettlementRoutes(page: Page) {
  let outcome = "awaiting_review";
  const decisions: Array<{ path: string; body: unknown; idempotencyKey: string | undefined }> = [];
  await page.route(/\/api\/v1\/settlement\/workspace(?:\?.*)?$/, async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify(settlementWorkspace(outcome)),
    });
  });
  await page.route(/\/api\/v1\/audit\/items\/e2e-review-item\/(problem-confirmations|problem-dismissals)$/, async (route) => {
    decisions.push({
      path: new URL(route.request().url()).pathname,
      body: route.request().postDataJSON(),
      idempotencyKey: route.request().headers()["idempotency-key"],
    });
    outcome = route.request().url().endsWith("problem-confirmations")
      ? "confirmed_problem"
      : "normal_ready";
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ item: settlementWorkspace(outcome).items[0] }),
    });
  });
  return decisions;
}

async function installDailyRoutes(page: Page) {
  const fields = {
    loading_net_tonnes: "33.08",
    loading_time: "2026-08-05T18:57:54+08:00",
    unloading_net_tonnes: "33.04",
    unloading_time: "2026-08-05T19:42:00+08:00",
  };
  const issues = Object.fromEntries(
    Object.keys(fields).map((field) => [field, { has_issue: false, message: null }]),
  );
  const sources = Object.fromEntries(Object.keys(fields).map((field) => [field, "machine"]));
  const image = "<svg xmlns='http://www.w3.org/2000/svg' width='640' height='400'><rect width='100%' height='100%' fill='#eee'/><rect x='80' y='60' width='480' height='280' rx='8' fill='white' stroke='#999'/><text x='50%' y='48%' text-anchor='middle' font-family='sans-serif' font-size='34'>磅单图片</text><text x='50%' y='60%' text-anchor='middle' font-family='sans-serif' font-size='26'>33.08 吨</text></svg>";
  await page.route(/\/api\/v1\/evidence\/[ab]{64}\?.*$/, async (route) => {
    await route.fulfill({
      contentType: "image/svg+xml",
      body: image,
    });
  });
  await page.route(/\/api\/v1\/daily\/items\?.*$/, async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        business_date: "2026-08-05",
        counts: { all: 2, needs_review: 0, reviewed: 2 },
        items: [1, 2].map((index) => ({
          platform_waybill_id: `daily-${index}`,
          waybill_number: `YD-00${index}`,
          vehicle_number: `陕A0000${index}`,
          loading_ticket: { sha256: "a".repeat(64), url: `/api/v1/evidence/${"a".repeat(64)}` },
          unloading_ticket: { sha256: "b".repeat(64), url: `/api/v1/evidence/${"b".repeat(64)}` },
          machine_fields: fields,
          effective_fields: fields,
          field_sources: sources,
          field_issues: issues,
          review_state: "reviewed",
          materialized_at: "2026-08-05T20:06:00+08:00",
          time_prefill: {
            loading_date: "2026-08-05",
            unloading_date: "2026-08-05",
          },
          record_version: 1,
          updated_at: "2026-08-05T20:07:00+08:00",
        })),
      }),
    });
  });
}

test("latest freight-settlement workspace has one operation row and direct decisions", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  const decisions = await installSettlementRoutes(page);
  const platformRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("chengfengkuaiyun.com")) platformRequests.push(request.url());
  });

  await page.goto("/");
  await expect(page.locator(".settlement-workspace")).toBeVisible();
  await expect(page.getByRole("combobox", { name: "审核批次" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "开始审核" })).toHaveCount(0);
  await expect(page.locator(".business-operation-bar")).toHaveCount(1);
  await expect(page.locator(".workspace-progress")).toHaveCount(1);
  await expect(page.locator(".settlement-waybill")).toHaveCount(1);
  await expect(page.locator("section.settlement-ticket[aria-label='装货磅单']")).toHaveCount(1);
  await expect(page.locator("section.settlement-ticket[aria-label='卸货磅单']")).toHaveCount(1);
  await expect(page.getByRole("button", { name: "确认无误" })).toBeVisible();
  await expect(page.getByRole("button", { name: "异常" })).toBeVisible();
  await expect(
    page.getByRole("navigation", { name: "主导航" }).getByText("运费结算", { exact: true }),
  ).toHaveCount(1);
  const updateButton = page.getByRole("button", { name: /检查更新/ });
  const exitButton = page.getByRole("button", { name: "退出程序" });
  const updateBox = await updateButton.boundingBox();
  const exitBox = await exitButton.boundingBox();
  expect(updateBox).not.toBeNull();
  expect(exitBox).not.toBeNull();
  expect(updateBox?.x ?? 0).toBeLessThan(exitBox?.x ?? 0);
  expect(updateBox?.width).toBe(exitBox?.width);
  expect(updateBox?.height).toBe(exitBox?.height);
  await expect(page.locator("main h1:not(.visually-hidden)")).toHaveCount(0);
  await expect(page.getByText(/capture:|operational_compat|settlement_capture/)).toHaveCount(0);

  await page.getByRole("button", { name: "异常" }).click();
  await expect(page.getByRole("button", { name: "异常" })).toHaveAttribute("aria-pressed", "true");
  expect(decisions[0]?.body).toEqual({ expected_record_version: 1 });
  expect(decisions[0]?.idempotencyKey).toBeTruthy();
  expect(platformRequests).toEqual([]);
  await page.screenshot({ path: "../output/playwright/ux-v2/settlement-1366x768.png", fullPage: true });
});

test("daily workspace uses one progress projection and keeps field editing visible", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await installSettlementRoutes(page);
  await installDailyRoutes(page);
  await page.goto("/");
  await page.getByRole("button", { name: "装卸车明细" }).click();

  await expect(page.locator(".daily-workspace")).toBeVisible();
  await expect(page.locator(".daily-item-row")).toHaveCount(2);
  await expect(page.getByRole("heading", { name: "装卸车明细" })).toHaveCount(1);
  await expect(page.locator(".business-operation-bar")).toHaveCount(1);
  await expect(page.locator(".workspace-progress")).toHaveCount(1);
  const input = page.getByLabel("出矿净重（吨）").first();
  expect(await input.evaluate((element) => getComputedStyle(element).borderStyle)).toBe("solid");
  await page.getByRole("button", { name: "装货磅单" }).first().click();
  await expect(page.getByRole("dialog", { name: "装货磅单" })).toBeVisible();
  await page.keyboard.press("Escape");
  await page.screenshot({ path: "../output/playwright/ux-v2/daily-1366x768.png", fullPage: true });
});

test("runtime log stays before the collapsed issue history", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await installSettlementRoutes(page);
  await page.goto("/");
  await page.getByRole("button", { name: "系统" }).click();
  await page.getByRole("button", { name: "运行诊断" }).click();

  const terminal = page.locator(".runtime-log-terminal");
  const issues = page.locator(".collapsible-history");
  await expect(terminal).toBeVisible();
  await expect(issues).not.toHaveAttribute("open", "");
  const terminalBox = await terminal.boundingBox();
  const issuesBox = await issues.boundingBox();
  expect(issuesBox?.y ?? 0).toBeGreaterThan((terminalBox?.y ?? 0) + (terminalBox?.height ?? 0));
  await expect(page.getByRole("heading", { name: "运行诊断" })).toHaveCount(1);
  await page.screenshot({ path: "../output/playwright/ux-v2/diagnostics-1366x768.png", fullPage: true });
});

test("local shutdown requires one confirmation", async ({ page }) => {
  await installSettlementRoutes(page);
  let shutdownCount = 0;
  await page.route(/\/api\/v1\/system\/shutdown$/, async (route) => {
    shutdownCount += 1;
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ accepted: true, idempotent_replay: false }) });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "退出程序" }).click();
  await expect(
    page.getByRole("dialog", { name: "退出大禾物流自动化平台？" }),
  ).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "退出程序" }).click();
  await expect(page.getByRole("heading", { name: "程序已退出" })).toBeVisible();
  expect(shutdownCount).toBe(1);
});

const viewports = [
  { label: "2560x1440", width: 2560, height: 1440 },
  { label: "1920x1080", width: 1920, height: 1080 },
  { label: "100", width: 1366, height: 768 },
  { label: "125", width: Math.floor(1366 / 1.25), height: Math.floor(768 / 1.25) },
  { label: "150", width: Math.floor(1366 / 1.5), height: Math.floor(768 / 1.5) },
  { label: "200", width: Math.floor(1366 / 2), height: Math.floor(768 / 2) },
];

for (const viewport of viewports) {
  test(`approved pages have no horizontal overflow at ${viewport.label}`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await installSettlementRoutes(page);
    await installDailyRoutes(page);
    await page.goto("/");
    await expect(page.locator(".settlement-workspace")).toBeVisible();
    if (viewport.width <= 999) {
      await expect(page.getByRole("button", { name: "更多" })).toBeVisible();
      await expect(page.getByRole("button", { name: "暂停" })).not.toBeVisible();
    } else {
      await expect(page.getByRole("button", { name: "更多" })).toHaveCount(0);
      await expect(page.getByRole("button", { name: "暂停" })).toBeVisible();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `../output/playwright/ux-v2/settlement-${viewport.label}.png`, fullPage: true });

    await page.getByRole("button", { name: "装卸车明细" }).click();
    if (viewport.width <= 999) {
      await expect(page.getByRole("button", { name: "更多" })).toBeVisible();
      await expect(page.getByRole("button", { name: "生成报表" })).not.toBeVisible();
    } else {
      await expect(page.getByRole("button", { name: "更多" })).toHaveCount(0);
      await expect(page.getByRole("button", { name: "生成报表" })).toBeVisible();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `../output/playwright/ux-v2/daily-${viewport.label}.png`, fullPage: true });

    await page.getByRole("button", { name: "历史数据" }).click();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `../output/playwright/ux-v2/history-${viewport.label}.png`, fullPage: true });

    await page.getByRole("button", { name: "系统" }).click();
    await page.getByRole("button", { name: "运行诊断" }).click();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `../output/playwright/ux-v2/system-${viewport.label}.png`, fullPage: true });
  });
}

for (const viewport of [
  { label: "1366x768", width: 1366, height: 768 },
  { label: "1920x1080", width: 1920, height: 1080 },
]) {
  test(`all system sections keep navigation as the only visible page title at ${viewport.label}`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await installSettlementRoutes(page);
    await page.goto("/");
    await page.getByRole("button", { name: "系统" }).click();
    for (const section of ["运行状态", "运行诊断", "识别模板", "参数设置", "数据管理"]) {
      const button = page.getByRole("button", { name: section, exact: true });
      if (await button.count()) {
        await button.click();
        const visiblePageTitles = await page.getByText(section, { exact: true }).evaluateAll((elements) =>
          elements.filter((element) => {
            const box = element.getBoundingClientRect();
            return box.width > 2 && box.height > 2;
          }).length,
        );
        expect(visiblePageTitles).toBe(1);
        expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1);
        await page.screenshot({
          path: `../output/playwright/ux-v2/system-${section}-${viewport.label}.png`,
          fullPage: true,
        });
      }
    }
  });
}
