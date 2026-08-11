export type Loop9ReviewKind = "current_locked_50" | "real_shadow_30";
export type Loop9ReviewStatus = "pending" | "draft" | "confirmed";
export type Loop9TicketRole = "loading" | "unloading" | "unknown";
export type Loop9PairCondition =
  | "normal_pair"
  | "suspected_swapped"
  | "both_loading"
  | "both_unloading"
  | "unknown_or_non_ticket";
export type Loop9QualityCondition =
  | "blur"
  | "crop"
  | "glare"
  | "printed"
  | "rotation_0"
  | "rotation_90"
  | "rotation_180"
  | "rotation_270"
  | "screen"
  | "unknown_layout";

export interface Loop9TruthImage {
  slot: "loading" | "unloading";
  imageSha256: string;
  role: Loop9TicketRole;
  ordinaryNet: string | null;
  qualityConditions: Loop9QualityCondition[];
}

export interface Loop9ReviewTruth {
  images: Loop9TruthImage[];
  pairCondition: Loop9PairCondition;
}

export interface Loop9ReviewProgress {
  total: number;
  confirmed: number;
  draft: number;
  remaining: number;
}

export interface Loop9ReviewSummary {
  itemIdentitySha256: string;
  position: number;
  reviewStatus: Loop9ReviewStatus;
  recordVersion: number;
}

export interface Loop9ReviewIndex {
  packageSha256: string;
  reviewKind: Loop9ReviewKind;
  advisoryMessage: string;
  reviewRevisionSha256: string;
  progress: Loop9ReviewProgress;
  items: Loop9ReviewSummary[];
}

export interface Loop9ReviewImage {
  slot: "loading" | "unloading";
  imageSha256: string;
  imageUrl: string;
}

export interface Loop9DraftSuggestion {
  kind: "draft_suggestion";
  images: Loop9TruthImage[];
  pairCondition: Loop9PairCondition;
}

export interface Loop9MachineImage {
  slot: "loading" | "unloading";
  imageSha256: string;
  predictedRole: Loop9TicketRole;
  ordinaryNet: string | null;
  roleHighConfidence: boolean;
}

export interface Loop9MachineResult {
  kind: "machine_result";
  automaticOutcome: string;
  issueCode: string | null;
  diagnosticCode: string | null;
  images: Loop9MachineImage[];
}

export interface Loop9ReviewItem {
  itemIdentitySha256: string;
  position: number;
  reviewKind: Loop9ReviewKind;
  reviewStatus: Loop9ReviewStatus;
  recordVersion: number;
  platformWeights: {
    loading: string;
    unloading: string;
  };
  images: Loop9ReviewImage[];
  advisory: Loop9DraftSuggestion | Loop9MachineResult;
  truth: Loop9ReviewTruth | null;
  confirmation:
    | "suggestion_confirmed"
    | "corrected"
    | "machine_result_confirmed"
    | "difference_confirmed"
    | null;
  confirmedAt: string | null;
}

export interface SaveLoop9ReviewInput {
  expectedRecordVersion: number;
  truth: Loop9ReviewTruth;
}

export interface ConfirmLoop9ReviewInput extends SaveLoop9ReviewInput {
  verifiedImageSha256s: [string, string];
}

export interface SaveLoop9ReviewResult {
  item: Loop9ReviewItem;
  progress: Loop9ReviewProgress;
  reviewRevisionSha256: string;
}

export interface ExportLoop9ReviewResult {
  fileName: string;
  canonicalSha256: string;
  reviewRevisionSha256: string;
}
