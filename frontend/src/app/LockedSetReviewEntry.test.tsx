import {
  act,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type {
  LockedSetReviewItem,
  LockedSetReviewProgress,
} from "../api/lockedSetReviewContracts";
import { App, type AppServices } from "./App";

const reviewSummaries = [
  {
    sampleId: "L7-001",
    position: 1,
    reviewStatus: "pending" as const,
    recordVersion: 0,
    decision: null,
  },
  {
    sampleId: "L7-002",
    position: 2,
    reviewStatus: "pending" as const,
    recordVersion: 0,
    decision: null,
  },
];

function reviewItem(
  sampleId = "L7-001",
  position = 1,
): LockedSetReviewItem {
  return {
    sampleId,
    position,
    recordVersion: 0,
    reviewStatus: "pending",
    selectionClues: [],
    images: [
      {
        submittedSlot: "loading",
        imageUrl: `/review/${sampleId}/loading.jpg`,
        selectionClues: [],
        review: null,
      },
      {
        submittedSlot: "unloading",
        imageUrl: `/review/${sampleId}/unloading.jpg`,
        selectionClues: [],
        review: null,
      },
    ],
    pairReview: null,
    decision: null,
    replaceReason: null,
  };
}

function services(
  enabled: boolean,
  overrides: Partial<AppServices> = {},
): AppServices {
  return {
    bootstrap: vi.fn().mockResolvedValue({
      applicationVersion: "1.0.0",
      csrfToken: "csrf-review",
      lockedSetReviewEnabled: enabled,
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
    loadLockedSetReview: vi.fn().mockResolvedValue({
      packageId: "locked-review-001",
      status: "awaiting_human_review",
      progress: {
        total: 50,
        completed: 0,
        remaining: 50,
        replaceCandidate: 0,
      },
      items: reviewSummaries,
    }),
    loadLockedSetReviewItem: vi
      .fn()
      .mockImplementation((sampleId: string) =>
        Promise.resolve(
          reviewItem(sampleId, sampleId === "L7-001" ? 1 : 2),
        ),
      ),
    saveLockedSetReviewItem: vi.fn(),
    ...overrides,
  };
}

async function openMaintenance(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "系统设置" }));
}

async function openLockedSetReview(user: ReturnType<typeof userEvent.setup>) {
  await openMaintenance(user);
  await user.click(screen.getByRole("button", { name: "打开锁定集复核" }));
  await screen.findByRole("heading", { name: "样本 01" });
}

describe("locked-set review entry", () => {
  it("shows the review tool only when the session feature is enabled", async () => {
    const user = userEvent.setup();
    render(<App services={services(true)} />);
    await openMaintenance(user);

    expect(
      screen.getByRole("button", { name: "打开锁定集复核" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "识别模板" }),
    ).toBeVisible();
  });

  it("does not expose the review tool when the session feature is disabled", async () => {
    const user = userEvent.setup();
    render(<App services={services(false)} />);
    await openMaintenance(user);

    expect(
      screen.queryByRole("button", { name: "打开锁定集复核" }),
    ).toBeNull();
    expect(
      screen.getByRole("button", { name: "识别模板" }),
    ).toBeVisible();
  });

  it("keeps unsaved review input when global navigation is rejected", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<App services={services(true)} />);
    await openLockedSetReview(user);

    const loading = screen.getByRole("region", {
      name: "装货位置图片",
    });
    await user.click(
      within(loading).getByRole("radio", {
        name: "票据类型无法判断（净重留空）",
      }),
    );
    await user.click(screen.getByRole("button", { name: "运费结算" }));

    expect(window.confirm).toHaveBeenCalledWith(
      "当前填写尚未保存。离开后将丢失这些修改，是否继续？",
    );
    expect(screen.getByRole("heading", { name: "样本 01" })).toBeVisible();
  });

  it("blocks every review navigation target while a save is pending", async () => {
    const user = userEvent.setup();
    let finishSave:
      | ((value: {
          item: LockedSetReviewItem;
          progress: LockedSetReviewProgress;
        }) => void)
      | undefined;
    const pendingSave = new Promise<{
      item: LockedSetReviewItem;
      progress: LockedSetReviewProgress;
    }>((resolve) => {
      finishSave = resolve;
    });
    const saveLockedSetReviewItem = vi.fn().mockReturnValue(pendingSave);
    render(
      <App
        services={services(true, {
          saveLockedSetReviewItem,
        })}
      />,
    );
    await openLockedSetReview(user);

    await user.click(
      screen.getByRole("radio", {
        name: "这条不适合作为锁定集样本，申请更换",
      }),
    );
    await user.type(screen.getByLabelText("更换原因"), "原图无法确认");
    await user.click(screen.getByRole("button", { name: "保存" }));

    await waitFor(() => expect(saveLockedSetReviewItem).toHaveBeenCalledOnce());
    expect(screen.getByRole("button", { name: "运费结算" })).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "系统设置" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: /样本 02/ }),
    ).toBeDisabled();

    await act(async () => {
      finishSave?.({
        item: {
          ...reviewItem(),
          recordVersion: 1,
          reviewStatus: "replace_candidate",
          decision: "replace_candidate",
          replaceReason: "原图无法确认",
        },
        progress: {
          total: 50,
          completed: 1,
          remaining: 49,
          replaceCandidate: 1,
        },
      });
      await pendingSave;
    });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "运费结算" })).toBeEnabled(),
    );
    expect(screen.getByRole("heading", { name: "样本 01" })).toBeVisible();
  });
});
