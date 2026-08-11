import type {
  LockedSetPairCondition,
  LockedSetQualityCondition,
  LockedSetReviewDecision,
  LockedSetReviewItem,
  LockedSetTicketRole,
} from "../../api/lockedSetReviewContracts";

export interface ImageDraft {
  submittedSlot: "loading" | "unloading";
  role: LockedSetTicketRole | "";
  ordinaryNet: string;
  qualityConditions: LockedSetQualityCondition[];
  notes: string;
}

export interface ReviewDraft {
  decision: LockedSetReviewDecision | "";
  images: ImageDraft[];
  pairConditions: LockedSetPairCondition[];
  pairNotes: string;
  replaceReason: string;
}

interface StoredReviewDraft {
  schemaVersion: 1;
  packageId: string;
  sampleId: string;
  recordVersion: number;
  draft: ReviewDraft;
}

const REVIEW_DRAFT_STORAGE_PREFIX = "dahe.locked-set-review.draft.v1";
const ticketRoles = new Set<LockedSetTicketRole | "">([
  "",
  "loading",
  "unloading",
  "unknown",
]);
const qualityConditions = new Set<LockedSetQualityCondition>([
  "blur",
  "glare",
  "crop",
  "rotation_0",
  "rotation_90",
  "rotation_180",
  "rotation_270",
  "screen",
  "printed",
  "unknown_layout",
  "non_ticket",
]);
const pairConditions = new Set<LockedSetPairCondition>([
  "normal_pair",
  "swapped_pair",
  "same_role_pair",
  "duplicate_upload",
  "pair_unknown",
]);

export function emptyDraft(item: LockedSetReviewItem): ReviewDraft {
  return {
    decision: item.decision ?? "",
    images: item.images.map((image) => ({
      submittedSlot: image.submittedSlot,
      role: image.review?.role ?? "",
      ordinaryNet: image.review?.ordinaryNet ?? "",
      qualityConditions: image.review?.qualityConditions ?? [],
      notes: image.review?.notes ?? "",
    })),
    pairConditions: item.pairReview?.conditions ?? [],
    pairNotes: item.pairReview?.notes ?? "",
    replaceReason: item.replaceReason ?? "",
  };
}

export function draftFingerprint(draft: ReviewDraft | null): string {
  if (!draft) {
    return "";
  }
  return JSON.stringify({
    ...draft,
    images: draft.images.map((image) => ({
      ...image,
      qualityConditions: [...image.qualityConditions].sort(),
    })),
    pairConditions: [...draft.pairConditions].sort(),
  });
}

function reviewDraftStorageKey(packageId: string, sampleId: string): string {
  return `${REVIEW_DRAFT_STORAGE_PREFIX}:${packageId}:${sampleId}`;
}

function clearStoredValue(key: string): void {
  try {
    sessionStorage.removeItem(key);
  } catch {
    // Browser storage is optional; the beforeunload guard still protects edits.
  }
}

function isImageDraft(value: unknown): value is ImageDraft {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as Partial<ImageDraft>;
  return (
    (candidate.submittedSlot === "loading" ||
      candidate.submittedSlot === "unloading") &&
    typeof candidate.role === "string" &&
    ticketRoles.has(candidate.role as LockedSetTicketRole | "") &&
    typeof candidate.ordinaryNet === "string" &&
    Array.isArray(candidate.qualityConditions) &&
    candidate.qualityConditions.every(
      (condition) =>
        typeof condition === "string" &&
        qualityConditions.has(condition as LockedSetQualityCondition),
    ) &&
    typeof candidate.notes === "string"
  );
}

function isReviewDraft(value: unknown): value is ReviewDraft {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as Partial<ReviewDraft>;
  return (
    (candidate.decision === "" ||
      candidate.decision === "confirmed" ||
      candidate.decision === "replace_candidate") &&
    Array.isArray(candidate.images) &&
    candidate.images.every(isImageDraft) &&
    Array.isArray(candidate.pairConditions) &&
    candidate.pairConditions.every(
      (condition) =>
        typeof condition === "string" &&
        pairConditions.has(condition as LockedSetPairCondition),
    ) &&
    typeof candidate.pairNotes === "string" &&
    typeof candidate.replaceReason === "string"
  );
}

export function readReviewDraft(
  packageId: string,
  item: LockedSetReviewItem,
): ReviewDraft | null {
  const key = reviewDraftStorageKey(packageId, item.sampleId);
  try {
    const raw = sessionStorage.getItem(key);
    if (raw === null) {
      return null;
    }
    const stored = JSON.parse(raw) as Partial<StoredReviewDraft>;
    if (
      stored.schemaVersion !== 1 ||
      stored.packageId !== packageId ||
      stored.sampleId !== item.sampleId ||
      stored.recordVersion !== item.recordVersion ||
      !isReviewDraft(stored.draft)
    ) {
      clearStoredValue(key);
      return null;
    }
    return {
      decision: stored.draft.decision,
      images: stored.draft.images.map((image) => ({
        ...image,
        qualityConditions: [...image.qualityConditions],
      })),
      pairConditions: [...stored.draft.pairConditions],
      pairNotes: stored.draft.pairNotes,
      replaceReason: stored.draft.replaceReason,
    };
  } catch {
    clearStoredValue(key);
    return null;
  }
}

export function writeReviewDraft(
  packageId: string,
  item: LockedSetReviewItem,
  draft: ReviewDraft,
): void {
  try {
    const stored: StoredReviewDraft = {
      schemaVersion: 1,
      packageId,
      sampleId: item.sampleId,
      recordVersion: item.recordVersion,
      draft: {
        decision: draft.decision,
        images: draft.images.map((image) => ({
          ...image,
          qualityConditions: [...image.qualityConditions],
        })),
        pairConditions: [...draft.pairConditions],
        pairNotes: draft.pairNotes,
        replaceReason: draft.replaceReason,
      },
    };
    sessionStorage.setItem(
      reviewDraftStorageKey(packageId, item.sampleId),
      JSON.stringify(stored),
    );
  } catch {
    // Browser storage is optional; the beforeunload guard still protects edits.
  }
}

export function clearReviewDraft(
  packageId: string,
  sampleId: string,
): void {
  clearStoredValue(reviewDraftStorageKey(packageId, sampleId));
}
