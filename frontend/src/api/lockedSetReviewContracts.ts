export type LockedSetReviewStatus =
  | "pending"
  | "confirmed"
  | "replace_candidate";

export type LockedSetReviewDecision = "confirmed" | "replace_candidate";

export type LockedSetTicketRole = "loading" | "unloading" | "unknown";

export type LockedSetQualityCondition =
  | "blur"
  | "glare"
  | "crop"
  | "rotation_0"
  | "rotation_90"
  | "rotation_180"
  | "rotation_270"
  | "screen"
  | "printed"
  | "unknown_layout"
  | "non_ticket";

export type LockedSetPairCondition =
  | "normal_pair"
  | "swapped_pair"
  | "same_role_pair"
  | "duplicate_upload"
  | "pair_unknown";

export interface LockedSetReviewProgress {
  total: number;
  completed: number;
  remaining: number;
  replaceCandidate: number;
}

export interface LockedSetReviewSummary {
  sampleId: string;
  position: number;
  reviewStatus: LockedSetReviewStatus;
  recordVersion: number;
  decision: LockedSetReviewDecision | null;
}

export interface LockedSetReviewIndex {
  packageId: string;
  status: string;
  progress: LockedSetReviewProgress;
  items: LockedSetReviewSummary[];
}

export interface LockedSetImageTruth {
  role: LockedSetTicketRole;
  ordinaryNet: string | null;
  qualityConditions: LockedSetQualityCondition[];
  notes: string | null;
}

export interface LockedSetReviewImage {
  submittedSlot: "loading" | "unloading";
  imageUrl: string;
  selectionClues: string[];
  review: LockedSetImageTruth | null;
}

export interface LockedSetPairTruth {
  conditions: LockedSetPairCondition[];
  notes: string | null;
}

export interface LockedSetReviewItem {
  sampleId: string;
  position: number;
  recordVersion: number;
  reviewStatus: LockedSetReviewStatus;
  selectionClues: string[];
  images: LockedSetReviewImage[];
  pairReview: LockedSetPairTruth | null;
  decision: LockedSetReviewDecision | null;
  replaceReason: string | null;
}

export interface LockedSetReviewImageInput {
  submittedSlot: "loading" | "unloading";
  role: LockedSetTicketRole;
  ordinaryNet: string | null;
  qualityConditions: LockedSetQualityCondition[];
  notes: string | null;
}

export interface SaveLockedSetReviewInput {
  expectedRecordVersion: number;
  decision: LockedSetReviewDecision;
  images: LockedSetReviewImageInput[];
  pairConditions: LockedSetPairCondition[];
  pairNotes: string | null;
  replaceReason: string | null;
}

export interface SaveLockedSetReviewResult {
  item: LockedSetReviewItem;
  progress: LockedSetReviewProgress;
}
