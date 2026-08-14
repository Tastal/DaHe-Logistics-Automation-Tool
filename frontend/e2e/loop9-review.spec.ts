import { expect, test, type Page, type Route } from "@playwright/test";

const e2eBaseUrl =
  process.env.DAHE_E2E_BASE_URL ?? "http://127.0.0.1:8899";
const clientVersion = "1.1.2";
const firstItemId = "e".repeat(64);
const secondItemId = "f".repeat(64);
const loadingImageSha256 = "a".repeat(64);
const unloadingImageSha256 = "b".repeat(64);

const truthImages = [
  {
    slot: "loading",
    image_sha256: loadingImageSha256,
    role: "loading",
    ordinary_net: "30.00",
    quality_conditions: ["rotation_0"],
  },
  {
    slot: "unloading",
    image_sha256: unloadingImageSha256,
    role: "unloading",
    ordinary_net: "29.80",
    quality_conditions: ["rotation_0"],
  },
];

function reviewItem(itemIdentitySha256: string, position: number) {
  return {
    item_identity_sha256: itemIdentitySha256,
    position,
    review_kind: "current_locked_50",
    review_status: "pending",
    record_version: 0,
    platform_weights: { loading: "30.00", unloading: "29.80" },
    images: [
      {
        slot: "loading",
        image_sha256: loadingImageSha256,
        image_url: `/api/v1/loop9-review/images/${loadingImageSha256}`,
      },
      {
        slot: "unloading",
        image_sha256: unloadingImageSha256,
        image_url: `/api/v1/loop9-review/images/${unloadingImageSha256}`,
      },
    ],
    advisory: {
      item_identity_sha256: itemIdentitySha256,
      truth_status: "unconfirmed_non_truth",
      images: truthImages,
      pair_condition: "normal_pair",
    },
    truth: {
      images: truthImages,
      pair_condition: "normal_pair",
    },
    confirmation: null,
    confirmed_at: null,
  };
}

async function installLoop9ReviewFixture(page: Page) {
  let confirmRequest: {
    headers: Record<string, string>;
    body: Record<string, unknown>;
  } | null = null;

  const sessionResponse = await page.request.get("/api/v1/session", {
    headers: {
      Origin: new URL(e2eBaseUrl).origin,
      "X-DaHe-Client-Version": clientVersion,
    },
  });
  expect(sessionResponse.ok()).toBeTruthy();
  const sessionPayload =
    (await sessionResponse.json()) as Record<string, unknown>;

  await page.route("**/api/v1/session", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ...sessionPayload,
        loop9_review_enabled: true,
      }),
    });
  });

  await page.route("**/api/v1/loop9-review**", async (route: Route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/v1/loop9-review/images/")) {
      await route.fulfill({
        contentType: "image/svg+xml",
        body: [
          '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="500">',
          '<rect width="800" height="500" fill="#f4f4f4"/>',
          '<rect x="80" y="70" width="640" height="360" fill="#fff" stroke="#555"/>',
          '<text x="400" y="250" text-anchor="middle" font-size="36">TEST TICKET</text>',
          "</svg>",
        ].join(""),
      });
      return;
    }
    if (url.pathname === "/api/v1/loop9-review") {
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          package_sha256: "c".repeat(64),
          review_kind: "current_locked_50",
          advisory_message: "辅助建议，尚未成为真值",
          review_revision_sha256: "d".repeat(64),
          progress: {
            total: 50,
            confirmed: 0,
            draft: 0,
            remaining: 50,
          },
          items: [
            {
              item_identity_sha256: firstItemId,
              position: 1,
              review_status: "pending",
              record_version: 0,
            },
            {
              item_identity_sha256: secondItemId,
              position: 2,
              review_status: "pending",
              record_version: 0,
            },
          ],
        }),
      });
      return;
    }

    if (
      request.method() === "POST" &&
      url.pathname === `/api/v1/loop9-review/items/${firstItemId}/confirm`
    ) {
      confirmRequest = {
        headers: request.headers(),
        body: request.postDataJSON() as Record<string, unknown>,
      };
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          item: {
            ...reviewItem(firstItemId, 1),
            review_status: "confirmed",
            record_version: 1,
            confirmation: "suggestion_confirmed",
            confirmed_at: "2026-07-31T00:00:00+08:00",
          },
          progress: {
            total: 50,
            confirmed: 1,
            draft: 0,
            remaining: 49,
          },
          review_revision_sha256: "1".repeat(64),
        }),
      });
      return;
    }

    const itemMatch = url.pathname.match(
      /^\/api\/v1\/loop9-review\/items\/([0-9a-f]{64})$/,
    );
    if (itemMatch) {
      const identity = itemMatch[1];
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify(
          reviewItem(identity, identity === firstItemId ? 1 : 2),
        ),
      });
      return;
    }

    await route.abort("blockedbyclient");
  });

  return {
    readConfirmRequest: () => confirmRequest,
  };
}

test("Loop 9 locked-set review requires both original images and advances", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  const fixture = await installLoop9ReviewFixture(page);

  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "当前构建锁定集人工复核" }),
  ).toBeVisible();
  await expect(page.getByText("辅助建议，尚未成为真值")).toBeVisible();
  await expect(page.getByRole("heading", { name: "样本 01" })).toBeVisible();
  await expect(page.locator(".locked-review-image-pane")).toHaveCount(2);
  await expect(page.getByText(/审核人|处理人|工号|备注/)).toHaveCount(0);

  const confirm = page.getByRole("button", {
    name: "建议正确，确认并下一条",
  });
  await expect(confirm).toBeDisabled();
  await page.getByLabel("已核对装货位置原图").check();
  await expect(confirm).toBeDisabled();
  await page.getByLabel("已核对卸货位置原图").check();
  await expect(confirm).toBeEnabled();
  await confirm.click();

  await expect(page.getByRole("heading", { name: "样本 02" })).toBeVisible();
  const request = fixture.readConfirmRequest();
  expect(request).not.toBeNull();
  expect(request?.headers["idempotency-key"]).toBeTruthy();
  expect(request?.body).toMatchObject({
    expected_record_version: 0,
    verified_image_sha256s: [
      loadingImageSha256,
      unloadingImageSha256,
    ],
  });
  expect(JSON.stringify(request?.body)).not.toMatch(
    /reviewer|operator|actor|employee|notes/i,
  );

  const horizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(horizontalOverflow).toBeLessThanOrEqual(1);
  await page.screenshot({
    path: "../output/playwright/loop9-locked-review-1366x768.png",
    fullPage: true,
  });
});

test("Loop 9 review remains horizontally contained at 200% scaling", async ({
  page,
}) => {
  await page.setViewportSize({
    width: Math.floor(1366 / 2),
    height: Math.floor(768 / 2),
  });
  await installLoop9ReviewFixture(page);

  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "当前构建锁定集人工复核" }),
  ).toBeVisible();
  const horizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(horizontalOverflow).toBeLessThanOrEqual(1);
});
