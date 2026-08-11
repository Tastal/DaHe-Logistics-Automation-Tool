import { render, screen } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";

import type { Loop9ReviewItem } from "../api/loop9ReviewContracts";
import { App, type AppServices } from "./App";

function reviewItem(): Loop9ReviewItem {
  return {
    itemIdentitySha256: "e".repeat(64),
    position: 1,
    reviewKind: "current_locked_50",
    reviewStatus: "draft",
    recordVersion: 1,
    platformWeights: { loading: "30.00", unloading: "29.80" },
    images: [
      {
        slot: "loading",
        imageSha256: "a".repeat(64),
        imageUrl: "/loading.png",
      },
      {
        slot: "unloading",
        imageSha256: "b".repeat(64),
        imageUrl: "/unloading.png",
      },
    ],
    advisory: {
      kind: "draft_suggestion",
      images: [
        {
          slot: "loading",
          imageSha256: "a".repeat(64),
          role: "loading",
          ordinaryNet: "30.00",
          qualityConditions: ["rotation_0"],
        },
        {
          slot: "unloading",
          imageSha256: "b".repeat(64),
          role: "unloading",
          ordinaryNet: "29.80",
          qualityConditions: ["rotation_0"],
        },
      ],
      pairCondition: "normal_pair",
    },
    truth: {
      images: [
        {
          slot: "loading",
          imageSha256: "a".repeat(64),
          role: "loading",
          ordinaryNet: "31.25",
          qualityConditions: ["rotation_0"],
        },
        {
          slot: "unloading",
          imageSha256: "b".repeat(64),
          role: "unloading",
          ordinaryNet: "29.80",
          qualityConditions: ["rotation_0"],
        },
      ],
      pairCondition: "normal_pair",
    },
    confirmation: null,
    confirmedAt: null,
  };
}

function services(): AppServices {
  return {
    bootstrap: vi.fn().mockResolvedValue({
      applicationVersion: "1.0.0",
      csrfToken: "csrf-loop9-review",
      lockedSetReviewEnabled: false,
      loop9ReviewEnabled: true,
    }),
    loadSnapshot: vi.fn().mockResolvedValue({
      eventCursor: 0,
      jobs: [],
      resources: [],
      startActions: {},
    }),
    loadResources: vi.fn().mockResolvedValue([]),
    loadJobItems: vi.fn().mockResolvedValue([]),
    createAuditJob: vi.fn(),
    createFixtureJob: vi.fn(),
    subscribe: vi.fn().mockReturnValue(() => undefined),
    runJobAction: vi.fn(),
    loadLoop9Review: vi.fn().mockResolvedValue({
      packageSha256: "c".repeat(64),
      reviewKind: "current_locked_50",
      advisoryMessage: "辅助建议，尚未成为真值",
      reviewRevisionSha256: "d".repeat(64),
      progress: {
        total: 50,
        confirmed: 0,
        draft: 1,
        remaining: 50,
      },
      items: [
        {
          itemIdentitySha256: "e".repeat(64),
          position: 1,
          reviewStatus: "draft",
          recordVersion: 1,
        },
      ],
    }),
    loadLoop9ReviewItem: vi.fn().mockResolvedValue(reviewItem()),
    saveLoop9ReviewDraft: vi.fn(),
    confirmLoop9ReviewItem: vi.fn(),
    exportLoop9Review: vi.fn(),
  };
}

beforeEach(() => {
  window.localStorage.clear();
});

test("opens the isolated Loop 9 review directly and restores the server draft", async () => {
  render(<App services={services()} />);

  expect(
    await screen.findByRole("heading", {
      name: "当前构建锁定集人工复核",
    }),
  ).toBeVisible();
  expect(
    await screen.findByText("辅助建议，尚未成为真值"),
  ).toBeVisible();
  expect(await screen.findByDisplayValue("31.25")).toBeVisible();
  expect(screen.getByText("已恢复服务端草稿。")).toBeVisible();
  expect(screen.queryByText(/审核人|处理人|工号|备注/)).toBeNull();
});
