import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AppServices } from "../../app/contracts";
import type {
  LockedSetReviewIndex,
  LockedSetReviewItem,
} from "../../api/lockedSetReviewContracts";
import { LockedSetReview } from "./LockedSetReview";

const index: LockedSetReviewIndex = {
  packageId: "locked-review-001",
  status: "awaiting_human_review",
  progress: {
    total: 50,
    completed: 0,
    remaining: 50,
    replaceCandidate: 0,
  },
  items: [
    {
      sampleId: "L7-001",
      position: 1,
      reviewStatus: "pending",
      recordVersion: 0,
      decision: null,
    },
    {
      sampleId: "L7-002",
      position: 2,
      reviewStatus: "pending",
      recordVersion: 0,
      decision: null,
    },
  ],
};

function item(sampleId = "L7-001", position = 1): LockedSetReviewItem {
  return {
    sampleId,
    position,
    recordVersion: 0,
    reviewStatus: "pending",
    selectionClues: ["legacy_review_hint"],
    images: [
      {
        submittedSlot: "loading",
        imageUrl: `/review/${sampleId}/loading.jpg`,
        selectionClues: ["rotation_90_hint"],
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

function reviewServices(
  overrides: Partial<AppServices> = {},
): AppServices {
  return {
    bootstrap: vi.fn().mockResolvedValue({
      applicationVersion: "1.0.0",
      csrfToken: "csrf-review",
      lockedSetReviewEnabled: true,
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
    loadLockedSetReview: vi.fn().mockResolvedValue(index),
    loadLockedSetReviewItem: vi
      .fn()
      .mockImplementation((sampleId: string) =>
        Promise.resolve(
          item(sampleId, sampleId === "L7-001" ? 1 : 2),
        ),
      ),
    saveLockedSetReviewItem: vi.fn(),
    ...overrides,
  };
}

describe("LockedSetReview", () => {
  it("restores business fields without showing or persisting identity", async () => {
    sessionStorage.setItem(
      "dahe.locked-set-review.draft.v1:locked-review-001:L7-001",
      JSON.stringify({
        schemaVersion: 1,
        packageId: "locked-review-001",
        sampleId: "L7-001",
        recordVersion: 0,
        draft: {
          legacy_identity: "legacy-value",
          decision: "",
          images: [
            {
              submittedSlot: "loading",
              role: "unknown",
              ordinaryNet: "",
              qualityConditions: ["rotation_0"],
              notes: "保留这条本地填写",
            },
            {
              submittedSlot: "unloading",
              role: "",
              ordinaryNet: "",
              qualityConditions: [],
              notes: "",
            },
          ],
          pairConditions: [],
          pairNotes: "",
          replaceReason: "",
        },
      }),
    );
    const loadLockedSetReviewItem = vi.fn().mockResolvedValue(item());

    render(
      <LockedSetReview
        services={reviewServices({ loadLockedSetReviewItem })}
        onBack={() => undefined}
      />,
    );

    await screen.findByRole("heading", { name: "样本 01" });
    const loading = screen.getByRole("region", {
      name: "装货位置图片",
    });
    expect(
      within(loading).getByLabelText("这张图片的备注（选填）"),
    ).toHaveValue("保留这条本地填写");

    await waitFor(() => {
      const raw = sessionStorage.getItem(
        "dahe.locked-set-review.draft.v1:locked-review-001:L7-001",
      );
      expect(raw).not.toBeNull();
      expect(JSON.parse(raw as string).draft).not.toHaveProperty("legacy_identity");
    });
  });

  it("shows two submitted images and keeps sampling clues folded away from truth fields", async () => {
    render(
      <LockedSetReview services={reviewServices()} onBack={() => undefined} />,
    );

    expect(
      await screen.findByRole("heading", { name: "锁定集人工复核" }),
    ).toBeVisible();
    expect(screen.getByText("0 / 50 已完成")).toBeVisible();
    expect(
      await screen.findByRole("region", { name: "装货位置图片" }),
    ).toBeVisible();
    expect(
      screen.getByRole("region", { name: "卸货位置图片" }),
    ).toBeVisible();
    const clues = screen.getByText("抽样线索（不是答案）").closest("details");
    expect(clues).not.toHaveAttribute("open");
    expect(screen.queryByText("OCR 结果")).toBeNull();
    expect(screen.queryByText("平台重量")).toBeNull();
    expect(screen.queryByText("推荐答案")).toBeNull();
  });

  it("saves direct human truth and advances to the next sample", async () => {
    const user = userEvent.setup();
    const loadLockedSetReviewItem = vi
      .fn()
      .mockImplementation((sampleId: string) =>
        Promise.resolve(item(sampleId, sampleId === "L7-001" ? 1 : 2)),
      );
    const saveLockedSetReviewItem = vi.fn().mockResolvedValue({
      item: {
        ...item(),
        recordVersion: 1,
        reviewStatus: "confirmed",
      },
      progress: {
        total: 50,
        completed: 1,
        remaining: 49,
        replaceCandidate: 0,
      },
    });
    render(
      <LockedSetReview
        services={reviewServices({
          loadLockedSetReviewItem,
          saveLockedSetReviewItem,
        })}
        onBack={() => undefined}
      />,
    );

    const loading = await screen.findByRole("region", {
      name: "装货位置图片",
    });
    const unloading = screen.getByRole("region", {
      name: "卸货位置图片",
    });
    await user.click(
      within(loading).getByRole("radio", { name: "装货票" }),
    );
    await user.type(
      within(loading).getByLabelText("普通净重（吨）"),
      "30.50",
    );
    await user.click(within(loading).getByLabelText("打印票"));
    await user.click(within(loading).getByLabelText("正向 0°"));
    await user.click(
      within(unloading).getByRole("radio", { name: "卸货票" }),
    );
    await user.type(
      within(unloading).getByLabelText("普通净重（吨）"),
      "30.25",
    );
    await user.click(within(unloading).getByLabelText("屏幕拍摄"));
    await user.click(within(unloading).getByLabelText("右转 90°"));
    await user.click(screen.getByRole("radio", { name: "正常一装一卸" }));
    await user.click(
      screen.getByLabelText("疑似重复上传（可与上面的结论同时选择）"),
    );
    await user.click(
      screen.getByRole("radio", { name: "确认并保存人工标注" }),
    );
    await waitFor(() => {
      expect(sessionStorage.length).toBe(1);
    });
    await user.click(
      screen.getByRole("button", { name: "保存并下一条" }),
    );

    await waitFor(() =>
      expect(saveLockedSetReviewItem).toHaveBeenCalledWith(
        "L7-001",
        expect.objectContaining({
          expectedRecordVersion: 0,
          decision: "confirmed",
          images: [
            expect.objectContaining({
              submittedSlot: "loading",
              role: "loading",
              ordinaryNet: "30.50",
              qualityConditions: expect.arrayContaining([
                "printed",
                "rotation_0",
              ]),
            }),
            expect.objectContaining({
              submittedSlot: "unloading",
              role: "unloading",
              ordinaryNet: "30.25",
              qualityConditions: expect.arrayContaining([
                "screen",
                "rotation_90",
              ]),
            }),
          ],
          pairConditions: ["normal_pair", "duplicate_upload"],
        }),
      ),
    );
    expect(
      await screen.findByRole("heading", { name: "样本 02" }),
    ).toBeVisible();
    expect(sessionStorage.length).toBe(0);
    expect(saveLockedSetReviewItem).toHaveBeenCalledTimes(1);
  });

  it("keeps the current sample when the reviewer rejects an unsaved switch", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(
      <LockedSetReview services={reviewServices()} onBack={() => undefined} />,
    );

    const loading = await screen.findByRole("region", {
      name: "装货位置图片",
    });
    await user.click(
      within(loading).getByRole("radio", {
        name: "票据类型无法判断（净重留空）",
      }),
    );
    await user.click(screen.getByRole("button", { name: /样本 02/ }));

    expect(window.confirm).toHaveBeenCalledWith(
      "当前填写尚未提交，切换后仍会保留在本机草稿中。是否继续？",
    );
    expect(screen.getByRole("heading", { name: "样本 01" })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "当前填写尚未提交，已留在本条样本。",
    );
  });

  it("supports image-only rotation and zoom without changing review truth", async () => {
    const user = userEvent.setup();
    render(
      <LockedSetReview services={reviewServices()} onBack={() => undefined} />,
    );

    const loading = await screen.findByRole("region", {
      name: "装货位置图片",
    });
    const image = within(loading).getByRole("img");
    await user.click(
      within(loading).getByRole("button", { name: "顺时针旋转图片" }),
    );
    await user.click(within(loading).getByRole("button", { name: "放大图片" }));
    expect(image).toHaveStyle({ transform: "rotate(90deg) scale(1.25)" });
    await user.click(
      within(loading).getByRole("button", { name: "复位图片" }),
    );
    expect(image).toHaveStyle({ transform: "rotate(0deg) scale(1)" });
  });

  it("marks an unknown-layout image as unknown and clears its weight", async () => {
    const user = userEvent.setup();
    render(
      <LockedSetReview services={reviewServices()} onBack={() => undefined} />,
    );

    const loading = await screen.findByRole("region", {
      name: "装货位置图片",
    });
    await user.click(within(loading).getByRole("radio", { name: "装货票" }));
    await user.type(within(loading).getByLabelText("普通净重（吨）"), "30.50");
    await user.click(within(loading).getByLabelText("未知版式"));

    expect(
      within(loading).getByRole("radio", {
        name: "票据类型无法判断（净重留空）",
      }),
    ).toBeChecked();
    expect(within(loading).getByLabelText("普通净重（吨）")).toHaveValue("");
    expect(within(loading).getByLabelText("普通净重（吨）")).toBeDisabled();
  });

  it("marks a non-ticket image as unknown and clears its weight", async () => {
    const user = userEvent.setup();
    render(
      <LockedSetReview services={reviewServices()} onBack={() => undefined} />,
    );

    const loading = await screen.findByRole("region", {
      name: "装货位置图片",
    });
    await user.click(within(loading).getByRole("radio", { name: "装货票" }));
    await user.type(within(loading).getByLabelText("普通净重（吨）"), "30.50");
    await user.click(within(loading).getByLabelText("非磅单或上传错误"));

    expect(
      within(loading).getByRole("radio", {
        name: "票据类型无法判断（净重留空）",
      }),
    ).toBeChecked();
    expect(within(loading).getByLabelText("普通净重（吨）")).toHaveValue("");
    expect(within(loading).getByLabelText("普通净重（吨）")).toBeDisabled();
  });

  it("clears fields that are mutually exclusive with the selected decision", async () => {
    const user = userEvent.setup();
    const saveLockedSetReviewItem = vi.fn().mockResolvedValue({
      item: {
        ...item(),
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
    render(
      <LockedSetReview
        services={reviewServices({ saveLockedSetReviewItem })}
        onBack={() => undefined}
      />,
    );

    await screen.findByRole("heading", { name: "样本 01" });
    await user.type(
      screen.getByLabelText("整条样本备注（选填）"),
      "不应随更换决定提交",
    );
    await user.click(
      screen.getByRole("radio", {
        name: "这条不适合作为锁定集样本，申请更换",
      }),
    );
    await user.type(screen.getByLabelText("更换原因"), "原图无法确认");
    await user.click(screen.getByRole("button", { name: "保存" }));

    await waitFor(() =>
      expect(saveLockedSetReviewItem).toHaveBeenCalledWith(
        "L7-001",
        expect.objectContaining({
          decision: "replace_candidate",
          images: [],
          pairConditions: [],
          pairNotes: null,
          replaceReason: "原图无法确认",
        }),
      ),
    );

    await user.click(
      screen.getByRole("radio", { name: "确认并保存人工标注" }),
    );
    await user.click(
      screen.getByRole("radio", {
        name: "这条不适合作为锁定集样本，申请更换",
      }),
    );
    expect(screen.getByLabelText("更换原因")).toHaveValue("");
  });

  it("rejects an unknown pair when both image roles are known", async () => {
    const user = userEvent.setup();
    const saveLockedSetReviewItem = vi.fn();
    render(
      <LockedSetReview
        services={reviewServices({ saveLockedSetReviewItem })}
        onBack={() => undefined}
      />,
    );

    const loading = await screen.findByRole("region", {
      name: "装货位置图片",
    });
    const unloading = screen.getByRole("region", {
      name: "卸货位置图片",
    });
    await user.click(
      within(loading).getByRole("radio", { name: "装货票" }),
    );
    await user.type(
      within(loading).getByLabelText("普通净重（吨）"),
      "30.50",
    );
    await user.click(within(loading).getByLabelText("正向 0°"));
    await user.click(
      within(unloading).getByRole("radio", { name: "卸货票" }),
    );
    await user.type(
      within(unloading).getByLabelText("普通净重（吨）"),
      "30.25",
    );
    await user.click(within(unloading).getByLabelText("正向 0°"));
    const pairSection = screen
      .getByRole("heading", { name: "两张图片放在一起看" })
      .closest("section");
    expect(pairSection).not.toBeNull();
    await user.click(
      within(pairSection as HTMLElement).getByRole("radio", {
        name: "无法判断两张图片的组合",
      }),
    );
    await user.click(
      screen.getByRole("radio", { name: "确认并保存人工标注" }),
    );
    await user.click(screen.getByRole("button", { name: "保存" }));

    expect(saveLockedSetReviewItem).not.toHaveBeenCalled();
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(
      "选择“无法判断两张图片的组合”时，至少一张图片的真实角色也应为“票据类型无法判断”。",
    );
    expect(alert).toHaveFocus();
    expect(alert.closest(".locked-review-action-dock")).not.toBeNull();
  });

  it("restores an unsubmitted sample draft after a page remount", async () => {
    const user = userEvent.setup();
    const firstView = render(
      <LockedSetReview services={reviewServices()} onBack={() => undefined} />,
    );

    const loading = await screen.findByRole("region", {
      name: "装货位置图片",
    });
    await user.click(
      within(loading).getByRole("radio", {
        name: "票据类型无法判断（净重留空）",
      }),
    );
    await user.click(within(loading).getByLabelText("正向 0°"));
    await user.type(
      within(loading).getByLabelText("这张图片的备注（选填）"),
      "刷新后仍需保留",
    );

    await waitFor(() => {
      const stored = sessionStorage.getItem(
        "dahe.locked-set-review.draft.v1:locked-review-001:L7-001",
      );
      expect(stored).not.toBeNull();
      expect(JSON.parse(stored as string)).toEqual(
        expect.objectContaining({
          draft: expect.objectContaining({
            images: expect.arrayContaining([
              expect.objectContaining({
                submittedSlot: "loading",
                notes: "刷新后仍需保留",
              }),
            ]),
          }),
        }),
      );
      expect(JSON.parse(stored as string).draft).not.toHaveProperty("legacy_identity");
    });
    firstView.unmount();

    render(
      <LockedSetReview services={reviewServices()} onBack={() => undefined} />,
    );

    await screen.findByRole("heading", { name: "样本 01" });
    const restoredLoading = screen.getByRole("region", {
      name: "装货位置图片",
    });
    expect(
      within(restoredLoading).getByRole("radio", {
        name: "票据类型无法判断（净重留空）",
      }),
    ).toBeChecked();
    expect(
      within(restoredLoading).getByLabelText("这张图片的备注（选填）"),
    ).toHaveValue("刷新后仍需保留");
    expect(
      screen.getByText("已恢复本条尚未提交的填写内容。"),
    ).toBeVisible();
  });

  it("discards a stale browser draft when the server record version changed", async () => {
    sessionStorage.setItem(
      "dahe.locked-set-review.draft.v1:locked-review-001:L7-001",
      JSON.stringify({
        schemaVersion: 1,
        packageId: "locked-review-001",
        sampleId: "L7-001",
        recordVersion: 8,
        draft: {
          legacy_identity: "legacy-value",
          decision: "",
          images: [],
          pairConditions: [],
          pairNotes: "",
          replaceReason: "",
        },
      }),
    );

    render(
      <LockedSetReview services={reviewServices()} onBack={() => undefined} />,
    );

    await screen.findByRole("heading", { name: "样本 01" });
    expect(sessionStorage.length).toBe(0);
    expect(
      screen.queryByText("已恢复本条尚未提交的填写内容。"),
    ).toBeNull();
  });

  it("matches the backend text length limits in every review field", async () => {
    const user = userEvent.setup();
    render(
      <LockedSetReview services={reviewServices()} onBack={() => undefined} />,
    );

    await screen.findByRole("heading", { name: "样本 01" });
    for (const notes of screen.getAllByLabelText("这张图片的备注（选填）")) {
      expect(notes).toHaveAttribute("maxLength", "1000");
    }
    expect(
      screen.getByLabelText("整条样本备注（选填）"),
    ).toHaveAttribute("maxLength", "1000");

    await user.click(
      screen.getByRole("radio", {
        name: "这条不适合作为锁定集样本，申请更换",
      }),
    );
    expect(screen.getByLabelText("更换原因")).toHaveAttribute(
      "maxLength",
      "1000",
    );
  });
});
