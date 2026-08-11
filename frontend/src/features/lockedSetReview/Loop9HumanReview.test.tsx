import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import type { AppServices } from "../../app/contracts";
import type {
  Loop9ReviewIndex,
  Loop9ReviewItem,
} from "../../api/loop9ReviewContracts";
import { Loop9HumanReview } from "./Loop9HumanReview";

const imageTruth = [
  {
    slot: "loading" as const,
    imageSha256: "a".repeat(64),
    role: "loading" as const,
    ordinaryNet: "30.00",
    qualityConditions: ["rotation_0" as const],
  },
  {
    slot: "unloading" as const,
    imageSha256: "b".repeat(64),
    role: "unloading" as const,
    ordinaryNet: "29.80",
    qualityConditions: ["rotation_0" as const],
  },
];

function index(): Loop9ReviewIndex {
  return {
    packageSha256: "c".repeat(64),
    reviewKind: "current_locked_50",
    advisoryMessage: "辅助建议，尚未成为真值",
    reviewRevisionSha256: "d".repeat(64),
    progress: {
      total: 50,
      confirmed: 0,
      draft: 0,
      remaining: 50,
    },
    items: [
      {
        itemIdentitySha256: "e".repeat(64),
        position: 1,
        reviewStatus: "pending",
        recordVersion: 0,
      },
      {
        itemIdentitySha256: "f".repeat(64),
        position: 2,
        reviewStatus: "pending",
        recordVersion: 0,
      },
    ],
  };
}

function item(): Loop9ReviewItem {
  return {
    itemIdentitySha256: "e".repeat(64),
    position: 1,
    reviewKind: "current_locked_50",
    reviewStatus: "pending",
    recordVersion: 0,
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
      images: imageTruth,
      pairCondition: "normal_pair",
    },
    truth: {
      images: imageTruth,
      pairCondition: "normal_pair",
    },
    confirmation: null,
    confirmedAt: null,
  };
}

function services(
  values: Partial<AppServices> = {},
): AppServices {
  return {
    loadLoop9Review: vi.fn().mockResolvedValue(index()),
    loadLoop9ReviewItem: vi.fn().mockResolvedValue(item()),
    saveLoop9ReviewDraft: vi.fn().mockResolvedValue({
      item: { ...item(), reviewStatus: "draft", recordVersion: 1 },
      progress: {
        total: 50,
        confirmed: 0,
        draft: 1,
        remaining: 50,
      },
      reviewRevisionSha256: "1".repeat(64),
    }),
    confirmLoop9ReviewItem: vi.fn().mockResolvedValue({
      item: {
        ...item(),
        reviewStatus: "confirmed",
        recordVersion: 1,
        confirmation: "suggestion_confirmed",
        confirmedAt: "2026-07-30T00:00:00Z",
      },
      progress: {
        total: 50,
        confirmed: 1,
        draft: 0,
        remaining: 49,
      },
      reviewRevisionSha256: "2".repeat(64),
    }),
    exportLoop9Review: vi.fn(),
    ...values,
  } as AppServices;
}

test("shows advisory separately and has no replacement, identity, or notes UI", async () => {
  render(<Loop9HumanReview services={services()} />);

  expect(
    await screen.findByText("辅助建议，尚未成为真值"),
  ).toBeInTheDocument();
  expect(
    await screen.findByRole("heading", { name: "样本 01" }),
  ).toBeInTheDocument();
  expect(screen.queryByText(/替换候选/)).not.toBeInTheDocument();
  expect(screen.queryByText(/审核人|处理人|工号/)).not.toBeInTheDocument();
  expect(screen.queryByText(/备注/)).not.toBeInTheDocument();
  expect(
    await screen.findByRole("button", { name: "保存草稿" }),
  ).toBeEnabled();
});

test("requires both original images to be checked before confirm and advances", async () => {
  const confirmLoop9ReviewItem = vi.fn().mockResolvedValue({
    item: {
      ...item(),
      reviewStatus: "confirmed",
      recordVersion: 1,
      confirmation: "suggestion_confirmed",
      confirmedAt: "2026-07-30T00:00:00Z",
    },
    progress: {
      total: 50,
      confirmed: 1,
      draft: 0,
      remaining: 49,
    },
    reviewRevisionSha256: "2".repeat(64),
  });
  const loadLoop9ReviewItem = vi
    .fn()
    .mockResolvedValueOnce(item())
    .mockResolvedValueOnce({
      ...item(),
      itemIdentitySha256: "f".repeat(64),
      position: 2,
    });
  render(
    <Loop9HumanReview
      services={services({
        confirmLoop9ReviewItem,
        loadLoop9ReviewItem,
      })}
    />,
  );

  const confirm = await screen.findByRole("button", {
    name: "建议正确，确认并下一条",
  });
  expect(confirm).toBeDisabled();
  fireEvent.click(screen.getByLabelText("已核对装货位置原图"));
  expect(confirm).toBeDisabled();
  fireEvent.click(screen.getByLabelText("已核对卸货位置原图"));
  expect(confirm).toBeEnabled();
  fireEvent.click(confirm);

  await waitFor(() =>
    expect(confirmLoop9ReviewItem).toHaveBeenCalledWith(
      "e".repeat(64),
      expect.objectContaining({ expectedRecordVersion: 0 }),
    ),
  );
  await waitFor(() =>
    expect(loadLoop9ReviewItem).toHaveBeenLastCalledWith("f".repeat(64)),
  );
});

test("shows the real shadow machine result but still requires both image checks", async () => {
  const shadowItem: Loop9ReviewItem = {
    ...item(),
    reviewKind: "real_shadow_30",
    truth: null,
    advisory: {
      kind: "machine_result",
      automaticOutcome: "awaiting_review",
      issueCode: "role_unknown",
      diagnosticCode: null,
      images: [
        {
          slot: "loading",
          imageSha256: "a".repeat(64),
          predictedRole: "loading",
          ordinaryNet: "30.00",
          roleHighConfidence: true,
        },
        {
          slot: "unloading",
          imageSha256: "b".repeat(64),
          predictedRole: "unknown",
          ordinaryNet: null,
          roleHighConfidence: false,
        },
      ],
    },
  };
  const shadowIndex: Loop9ReviewIndex = {
    ...index(),
    reviewKind: "real_shadow_30",
    advisoryMessage: "机器结果仅供逐条人工核对",
    progress: {
      total: 30,
      confirmed: 0,
      draft: 0,
      remaining: 30,
    },
  };
  render(
    <Loop9HumanReview
      services={services({
        loadLoop9Review: vi.fn().mockResolvedValue(shadowIndex),
        loadLoop9ReviewItem: vi.fn().mockResolvedValue(shadowItem),
      })}
    />,
  );

  expect(
    await screen.findByText("机器判断：需要人工核对"),
  ).toBeVisible();
  const confirm = screen.getByRole("button", {
    name: "确认本条并下一条",
  });
  expect(confirm).toBeDisabled();
  fireEvent.click(screen.getByLabelText("已核对装货位置原图"));
  expect(confirm).toBeDisabled();
  fireEvent.click(screen.getByLabelText("已核对卸货位置原图"));
  expect(confirm).toBeEnabled();
});
