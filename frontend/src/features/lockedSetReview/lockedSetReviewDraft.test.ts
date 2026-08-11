import { describe, expect, it } from "vitest";

import type { LockedSetReviewItem } from "../../api/lockedSetReviewContracts";
import {
  readReviewDraft,
  writeReviewDraft,
  type ReviewDraft,
} from "./lockedSetReviewDraft";

const item: LockedSetReviewItem = {
  sampleId: "L7-001",
  position: 1,
  recordVersion: 0,
  reviewStatus: "pending",
  selectionClues: [],
  images: [
    {
      submittedSlot: "loading",
      imageUrl: "/review/L7-001/loading.jpg",
      selectionClues: [],
      review: null,
    },
    {
      submittedSlot: "unloading",
      imageUrl: "/review/L7-001/unloading.jpg",
      selectionClues: [],
      review: null,
    },
  ],
  pairReview: null,
  decision: null,
  replaceReason: null,
};

const businessDraft = {
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
} as const;

describe("locked-set review draft identity isolation", () => {
  it("drops a legacy identity field while restoring business fields", () => {
    sessionStorage.setItem(
      "dahe.locked-set-review.draft.v1:locked-review-001:L7-001",
      JSON.stringify({
        schemaVersion: 1,
        packageId: "locked-review-001",
        sampleId: "L7-001",
        recordVersion: 0,
        draft: {
          legacy_identity: "legacy-value",
          ...businessDraft,
        },
      }),
    );

    const restored = readReviewDraft("locked-review-001", item);

    expect(restored).toEqual(businessDraft);
    expect(restored).not.toHaveProperty("legacy_identity");
  });

  it("never persists a caller-supplied identity with the browser draft", () => {
    const callerShapedDraft = {
      legacy_identity: "forged-value",
      ...businessDraft,
    } as unknown as ReviewDraft;

    writeReviewDraft(
      "locked-review-001",
      item,
      callerShapedDraft,
    );

    const raw = sessionStorage.getItem(
      "dahe.locked-set-review.draft.v1:locked-review-001:L7-001",
    );
    expect(raw).not.toBeNull();
    const stored = JSON.parse(raw as string);
    expect(stored.draft).toEqual(businessDraft);
    expect(stored.draft).not.toHaveProperty("legacy_identity");
  });
});
