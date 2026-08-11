export type AuditActionType =
  | "correction"
  | "problem_confirmation"
  | "problem_dismissal"
  | "revocation";

export interface AuditTimelineEvent {
  eventId: string;
  eventType: string;
  referenceId: string | null;
  createdAt: string;
}

export interface AuditReviewAction {
  actionId: string;
  actionType: AuditActionType;
  reasonCode: string;
  correctValue: string | null;
  note: string | null;
  revokesActionId: string | null;
  createdAt: string;
}

export interface AuditReviewItem {
  workItemId: string;
  jobId: string;
  waybillId: string;
  vehicleNumber: string;
  recordVersion: number;
  status: string;
  businessOutcome: string | null;
  decision: string | null;
  reviewReason: string | null;
  diagnosticCode: string | null;
  fieldIssueDiagnosticCode?: string | null;
  platformLoadingNet: string | null;
  platformUnloadingNet: string | null;
  ticketLoadingNet: string | null;
  ticketUnloadingNet: string | null;
  loadingImageSha256: string | null;
  unloadingImageSha256: string | null;
  runMode: "offline" | "shadow" | "operational";
  availableActions: Record<string, AuditAvailableAction>;
  timeline: AuditTimelineEvent[];
  reviewActions: AuditReviewAction[];
  fieldIssues: AuditFieldIssues;
  reviewHighlightRoles: AuditReviewHighlightRole[];
}

export type AuditReviewHighlightRole = "loading" | "unloading";

export type AuditIssueField =
  | "loading_ticket"
  | "loading_ocr_weight"
  | "loading_platform_weight"
  | "unloading_ticket"
  | "unloading_ocr_weight"
  | "unloading_platform_weight";

export type AuditFieldIssues = Record<
  AuditIssueField,
  { hasIssue: boolean }
>;

export interface AuditAvailableAction {
  visible: boolean;
  enabled: boolean;
  reason: string | null;
}

export type AuditWorkspaceView =
  | "all"
  | "waiting_review"
  | "confirmed_problem"
  | "normal_ready";

export type AuditWorkspaceCounts = Record<AuditWorkspaceView, number>;

export interface AuditWorkspaceResult {
  items: AuditReviewItem[];
  counts: AuditWorkspaceCounts;
}

export interface SettlementLatestFetch {
  createdAt: string;
  startedAt?: string;
  phaseStartedAt?: string;
  updatedAt: string;
  finishedAt?: string | null;
  elapsedSeconds?: number;
  estimatedRemainingSeconds?: number | null;
  estimateState?: "estimating" | "estimated" | "complete" | "unavailable";
  isTerminal?: boolean;
  status: "running" | "complete" | "incomplete";
  isComplete: boolean;
  phaseLabel: string;
  progressCurrent: number;
  progressTotal: number;
  fetchedCount: number;
  recognizedCount: number;
  technicalFailureCount: number;
  phase: "login" | "read" | "download" | "recognize" | "finalize" | "complete" | "incomplete";
  metadataChecked: number;
  reused: number;
  imagesDownloaded: number;
  ocrCompleted: number;
  ocrImagesCompleted: number;
  ocrImagesTotal: number;
  finalized: number;
}

export interface SettlementWorkspaceResult extends AuditWorkspaceResult {
  latestFetch: SettlementLatestFetch | null;
}

export interface AuditDecisionInput {
  expectedRecordVersion: number;
}

export interface AuditRevocationInput {
  expectedRecordVersion: number;
  reason:
    | "decision_entered_in_error"
    | "evidence_rechecked"
    | "other_revocation_reason";
}

export interface DiagnosticHealth {
  id: string;
  label: string;
  status: "normal" | "attention";
  summary: string;
}

export interface DiagnosticIssue {
  diagnosticCode: string | null;
  location: string;
  message: string;
  workItemId: string | null;
}

export interface DiagnosticsSnapshot {
  generatedAt: string;
  health: DiagnosticHealth[];
  recentIssues: DiagnosticIssue[];
}

export type RuntimeLogLevel = "debug" | "info" | "warning" | "error";

export interface RuntimeLogEvent {
  eventId: string;
  createdAt: string;
  level: RuntimeLogLevel;
  source: string;
  eventCode: string;
  stream: "application" | "stdout" | "stderr";
  message: string;
  diagnosticCode: string | null;
  jobId: string | null;
  workItemId: string | null;
}

export interface RuntimeLogPage {
  events: RuntimeLogEvent[];
  earliestCursor: string | null;
  latestCursor: string | null;
  hasMoreOlder: boolean;
}

export interface RuntimeLogQuery {
  before?: string;
  after?: string;
  limit?: number;
  level?: RuntimeLogLevel;
  source?: string;
  text?: string;
}
