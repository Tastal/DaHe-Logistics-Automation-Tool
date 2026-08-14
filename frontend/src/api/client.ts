import type {
  AppServices,
  BeginBusinessConnectionReadResult,
  BootstrapResult,
  BusinessConnectionSession,
  ConsoleEvent,
  ConsoleSnapshot,
  ContractSubjectCode,
  CreateJobResult,
  DailyReportRecord,
  DailyReportSettings,
  DailyItem,
  DailyItemRevisionResult,
  DailyItemsResult,
  DailyEditableField,
  PerformanceSettings,
  PlatformCredentialStatus,
  PlatformBusinessReadProgress,
  SavePlatformCredentialInput,
  StartPlatformBusinessReadInput,
  StartPlatformBusinessReadResult,
  StartOperationalCaptureInput,
  StartOperationalCaptureResult,
  StartBusinessConnectionSessionResult,
  JobCounts,
  JobItem,
  JobResourceUsage,
  JobSummary,
  Loop3FixtureId,
  PlatformAccessWindow,
  PlatformSession,
  ProductionReadOnlyStatus,
  SaveDailyReportSettingsInput,
  CreatePlatformAccessWindowInput,
  ResourceSummary,
  ServerAction,
  UpdateStatus,
  EnvironmentSnapshot,
} from "../app/contracts";
import {
  ApiVersionMismatchError,
  TemplateMaintenanceRequiredError,
} from "../app/contracts";
import {
  mapStagedTemplateReference,
  mapTemplateRollbackOptions,
  mapTemplateFamilyIndex,
  mapTemplateVersion,
  serializeTemplateDraft,
  type StagedTemplateReference,
  type TemplateDraft,
  type TemplateFamilyIndex,
  type TemplateRole,
  type TemplateRollbackOptions,
  type TemplateRollbackResult,
  type TemplateVersionSnapshot,
  type WireTemplateFamilyIndex,
  type WireStagedTemplateReference,
  type WireTemplateRollbackOptions,
  type WireTemplateVersionSnapshot,
} from "./templateContracts";
import type {
  LockedSetPairCondition,
  LockedSetQualityCondition,
  LockedSetReviewDecision,
  LockedSetReviewIndex,
  LockedSetReviewItem,
  LockedSetReviewProgress,
  LockedSetReviewStatus,
  LockedSetTicketRole,
  SaveLockedSetReviewInput,
  SaveLockedSetReviewResult,
} from "./lockedSetReviewContracts";
import type {
  ConfirmLoop9ReviewInput,
  ExportLoop9ReviewResult,
  Loop9DraftSuggestion,
  Loop9MachineResult,
  Loop9PairCondition,
  Loop9QualityCondition,
  Loop9ReviewIndex,
  Loop9ReviewItem,
  Loop9ReviewProgress,
  Loop9ReviewStatus,
  Loop9ReviewTruth,
  Loop9TicketRole,
  SaveLoop9ReviewInput,
  SaveLoop9ReviewResult,
} from "./loop9ReviewContracts";
import type {
  AuditDecisionInput,
  AuditReviewAction,
  AuditReviewItem,
  AuditRevocationInput,
  AuditWorkspaceView,
  DiagnosticsSnapshot,
  RuntimeLogEvent,
  RuntimeLogPage,
  RuntimeLogQuery,
  AuditWorkspaceResult,
  SettlementLatestFetch,
  SettlementWorkspaceResult,
  AuditTimelineEvent,
} from "./auditContracts";

interface WirePlatformBusinessReadProgress {
  job_id: string;
  phase: PlatformBusinessReadProgress["phase"];
  phase_label: string;
  progress_current: number;
  progress_total: number;
  fetched: number;
  recognized: number;
  missing_fields: number;
  technical_failed: number;
  committed_batches: number;
  started_at: string | null;
  phase_started_at: string | null;
  updated_at: string | null;
  finished_at: string | null;
  elapsed_seconds: number;
  estimated_remaining_seconds: number | null;
  estimate_state: "estimating" | "estimated" | "complete" | "unavailable";
  is_terminal: boolean;
  source_job_id: string;
  source_record_version: number;
  capture_mode: "batch_v1" | "whole_run_v1";
  visible_prefix_count: number;
  online_capture_complete: boolean;
  review_job: WireJob | null;
}

function platformBusinessReadProgress(
  result: WirePlatformBusinessReadProgress,
): PlatformBusinessReadProgress {
  return {
    jobId: result.job_id,
    phase: result.phase,
    label: result.phase_label,
    current: result.progress_current,
    total: result.progress_total,
    fetched: result.fetched,
    recognized: result.recognized,
    missingFields: result.missing_fields,
    technicalFailed: result.technical_failed,
    committedBatches: result.committed_batches,
    startedAt: result.started_at,
    phaseStartedAt: result.phase_started_at,
    updatedAt: result.updated_at,
    finishedAt: result.finished_at,
    elapsedSeconds: result.elapsed_seconds,
    estimatedRemainingSeconds: result.estimated_remaining_seconds,
    estimateState: result.estimate_state,
    isTerminal: result.is_terminal,
    sourceJobId: result.source_job_id,
    sourceRecordVersion: result.source_record_version,
    captureMode: result.capture_mode,
    visiblePrefixCount: result.visible_prefix_count,
    onlineCaptureComplete: result.online_capture_complete,
    reviewJob: result.review_job ? jobSummary(result.review_job) : null,
  };
}

declare const __APP_VERSION__: string;

interface WireAction {
  visible: boolean;
  enabled: boolean;
  reason: string | null;
  label: string;
  expected_record_version?: number | null;
}

interface WireJob {
  job_id: string;
  task_type: string;
  job_kind?: "business" | "test_fixture";
  display_name: string;
  scope_label: string;
  run_mode: "shadow" | "operational";
  job_status: string;
  status_label: string;
  current_stage: string | null;
  current_stage_label?: string | null;
  active_stage_labels?: string[];
  active_resources?: Array<{
    resource_id: string;
    display_name: string;
  }>;
  waiting_reason?: string | null;
  latest_checkpoint_label?: string | null;
  progress_label: string;
  diagnostic_code?: string | null;
  record_version: number;
  counts: {
    total: number;
    processed: number;
    remaining: number;
    waiting_user: number;
    failed: number;
  };
  actions: Record<string, WireAction>;
  created_at: string;
  updated_at: string;
}

interface WireResource {
  resource_id: string;
  display_name: string;
  status_label: string;
  capacity?: number;
  in_use?: number;
  waiting_jobs?: number;
  holder_label?: string | null;
}

interface WireSnapshot {
  event_cursor: number;
  jobs: WireJob[];
  resources?: WireResource[];
  start_actions: Record<string, WireAction>;
}

interface WireJobItem {
  work_item_id: string;
  record_version: number;
  waybill_number: string;
  vehicle_number: string;
  status: string;
  current_stage: string;
  business_outcome: string | null;
  is_terminal_outcome: boolean;
  platform_loading_net: string | null;
  platform_unloading_net: string | null;
  ticket_loading_net: string | null;
  ticket_unloading_net: string | null;
  decision: string | null;
  review_reason: string | null;
}

interface WireError {
  error?: {
    code?: string;
    message?: string;
  };
}

interface WirePlatformAccessWindow {
  access_window_id: string;
  purpose: PlatformAccessWindow["purpose"];
  expires_at: string;
  consumed_at: string | null;
  expired: boolean;
  record_version: number;
}

interface WireBusinessConnectionSession {
  business_session_id: string;
  status: "active" | "closed";
  expires_at: string;
  expired: boolean;
  record_version: number;
}

interface WirePlatformSession {
  enabled: boolean;
  run_mode: "shadow" | "operational";
  connection_mode: "operational_compat" | "strict_shadow";
  connection_mode_label: string;
  connection_mode_record_version: number;
  browser_lifecycle: PlatformSession["browserLifecycle"];
  browser_control_mode: PlatformSession["browserControlMode"];
  record_version: number;
  runtime_available: boolean;
  runtime_running: boolean;
  selected_browser: string | null;
  discovery_capturing: boolean;
  visible_browser_running: boolean;
  control_mode: PlatformSession["controlMode"];
  human_handoff_ready: boolean;
  login_state: PlatformSession["loginState"];
  active_job_id: string | null;
  warm_session_reusable: boolean;
  connection_status: PlatformSession["connectionStatus"];
  contract_subject: {
    available_subjects: Array<{
      code: PlatformSession["contractSubject"]["currentSubjectCode"];
      label: string;
    }>;
    current_subject_code: PlatformSession["contractSubject"]["currentSubjectCode"];
    record_version: number;
    updated_at: string;
  };
  contract_candidate_selected: boolean;
  contract_selection_sha256: string | null;
  access_window: WirePlatformAccessWindow | null;
  business_session: WireBusinessConnectionSession | null;
  waiting_reason: string | null;
  available_actions: PlatformSession["availableActions"];
}

interface WireDailyReport {
  contract_subject_code: ContractSubjectCode;
  report_id: string;
  business_date: string;
  status: "pending_confirmation" | "confirmed";
  file_name: string;
  file_sha256: string;
  data_snapshot_sha256: string;
  output_directory: string;
  row_count: number;
  loading_net_total: string;
  record_version: number;
  created_at: string;
  confirmed_at: string | null;
  stale: boolean;
}

interface WireDailyItem {
  platform_waybill_id: string;
  waybill_number: string | null;
  vehicle_number: string | null;
  loading_ticket: { sha256: string; url: string } | null;
  unloading_ticket: { sha256: string; url: string } | null;
  machine_fields: Record<DailyEditableField, string | null>;
  effective_fields: Record<DailyEditableField, string | null>;
  field_sources: Record<DailyEditableField, "machine" | "manual">;
  field_issues: Record<DailyEditableField, { has_issue: boolean; message: string | null }>;
  review_state: "reviewed" | "needs_review";
  materialized_at: string;
  time_prefill: { loading_date: string; unloading_date: string };
  record_version: number;
  updated_at: string;
}

interface WireAuditReviewAction {
  action_id: string;
  action_type: AuditReviewAction["actionType"];
  reason_code: string;
  correct_value: string | null;
  note: string | null;
  revokes_action_id: string | null;
  created_at: string;
}

interface WireAuditTimelineEvent {
  timeline_event_id: string;
  event_type: string;
  reference_id: string | null;
  created_at: string;
}

interface WireAuditItem {
  work_item_id: string;
  job_id: string;
  waybill_id: string;
  vehicle_number: string;
  record_version: number;
  status: string;
  business_outcome: string | null;
  decision: string | null;
  review_reason: string | null;
  diagnostic_code: string | null;
  field_issue_diagnostic_code?: string | null;
  platform_loading_net: string | null;
  platform_unloading_net: string | null;
  ticket_loading_net: string | null;
  ticket_unloading_net: string | null;
  evidence: {
    loading_image_sha256: string | null;
    unloading_image_sha256: string | null;
  } | null;
  run_mode: "offline" | "shadow" | "operational";
  available_actions: Record<
    string,
    { visible: boolean; enabled: boolean; reason: string | null }
  >;
  timeline?: WireAuditTimelineEvent[];
  review_actions?: WireAuditReviewAction[];
  field_issues?: Record<string, { has_issue: boolean }>;
  review_highlight_roles: Array<"loading" | "unloading">;
}

interface WireLockedSetReviewProgress {
  total: number;
  completed: number;
  remaining: number;
  replace_candidate: number;
}

interface WireLockedSetReviewSummary {
  sample_id: string;
  position: number;
  review_status: LockedSetReviewStatus;
  record_version: number;
  decision: LockedSetReviewDecision | null;
}

interface WireLockedSetReviewIndex {
  package: {
    package_id: string;
    status: string;
  };
  progress: WireLockedSetReviewProgress;
  items: WireLockedSetReviewSummary[];
}

interface WireLockedSetReviewImage {
  submitted_slot: "loading" | "unloading";
  image_url: string;
  selection_clues: string[];
  human_review: {
    role: LockedSetTicketRole | null;
    ordinary_net: string | null;
    quality_conditions: LockedSetQualityCondition[];
    notes: string | null;
  } | null;
}

interface WireLockedSetReviewItem {
  sample_id: string;
  position: number;
  record_version: number;
  review_status: LockedSetReviewStatus;
  selection_clues: string[];
  images: WireLockedSetReviewImage[];
  pair_review: {
    conditions: LockedSetPairCondition[];
    notes: string | null;
  } | null;
  decision: LockedSetReviewDecision | null;
  replace_reason: string | null;
}

interface WireLoop9TruthImage {
  slot: "loading" | "unloading";
  image_sha256: string;
  role: Loop9TicketRole;
  ordinary_net: string | null;
  quality_conditions: Loop9QualityCondition[];
}

interface WireLoop9ReviewTruth {
  images: WireLoop9TruthImage[];
  pair_condition: Loop9PairCondition;
}

interface WireLoop9ReviewProgress {
  total: number;
  confirmed: number;
  draft: number;
  remaining: number;
}

interface WireLoop9ReviewSummary {
  item_identity_sha256: string;
  position: number;
  review_status: Loop9ReviewStatus;
  record_version: number;
}

interface WireLoop9ReviewIndex {
  package_sha256: string;
  review_kind: "current_locked_50" | "real_shadow_30";
  advisory_message: string;
  review_revision_sha256: string;
  progress: WireLoop9ReviewProgress;
  items: WireLoop9ReviewSummary[];
}

interface WireLoop9DraftSuggestion {
  item_identity_sha256: string;
  truth_status: "unconfirmed_non_truth";
  images: WireLoop9TruthImage[];
  pair_condition: Loop9PairCondition;
}

interface WireLoop9MachineImage {
  slot: "loading" | "unloading";
  image_sha256: string;
  predicted_role: Loop9TicketRole;
  ordinary_net: string | null;
  role_high_confidence: boolean;
}

interface WireLoop9MachineResult {
  automatic_outcome: string;
  issue_code: string | null;
  diagnostic_code: string | null;
  images: WireLoop9MachineImage[];
}

interface WireLoop9ReviewItem {
  item_identity_sha256: string;
  position: number;
  review_kind: "current_locked_50" | "real_shadow_30";
  review_status: Loop9ReviewStatus;
  record_version: number;
  platform_weights: {
    loading: string;
    unloading: string;
  };
  images: Array<{
    slot: "loading" | "unloading";
    image_sha256: string;
    image_url: string;
  }>;
  advisory: WireLoop9DraftSuggestion | WireLoop9MachineResult;
  truth: WireLoop9ReviewTruth | null;
  confirmation:
    | "suggestion_confirmed"
    | "corrected"
    | "machine_result_confirmed"
    | "difference_confirmed"
    | null;
  confirmed_at: string | null;
}

function jobCounts(counts: WireJob["counts"]): JobCounts {
  return {
    total: counts.total,
    processed: counts.processed,
    remaining: counts.remaining,
    waitingUser: counts.waiting_user,
    failed: counts.failed,
  };
}

function serverAction(action: WireAction): ServerAction {
  return {
    visible: action.visible,
    enabled: action.enabled,
    reason: action.reason,
    label: action.label,
    expectedRecordVersion: action.expected_record_version ?? null,
  };
}

function actionMatrix(
  actions: Record<string, WireAction>,
): Record<string, ServerAction> {
  return Object.fromEntries(
    Object.entries(actions).map(([actionId, action]) => [
      actionId,
      serverAction(action),
    ]),
  );
}

function jobResourceUsage(
  resource: NonNullable<WireJob["active_resources"]>[number],
): JobResourceUsage {
  return {
    resourceId: resource.resource_id,
    displayName: resource.display_name,
  };
}

function jobSummary(job: WireJob): JobSummary {
  return {
    jobId: job.job_id,
    taskType: job.task_type,
    jobKind: job.job_kind ?? "business",
    displayName: job.display_name,
    scopeLabel: job.scope_label,
    runMode: job.run_mode,
    jobStatus: job.job_status,
    statusLabel: job.status_label,
    currentStage: job.current_stage,
    currentStageLabel: job.current_stage_label ?? null,
    activeStageLabels: job.active_stage_labels ?? [],
    activeResources: (job.active_resources ?? []).map(jobResourceUsage),
    waitingReason: job.waiting_reason ?? null,
    latestCheckpointLabel: job.latest_checkpoint_label ?? null,
    progressLabel: job.progress_label,
    diagnosticCode: job.diagnostic_code ?? null,
    recordVersion: job.record_version,
    counts: jobCounts(job.counts),
    actions: actionMatrix(job.actions),
    createdAt: job.created_at,
    updatedAt: job.updated_at,
  };
}

function jobItem(item: WireJobItem): JobItem {
  return {
    workItemId: item.work_item_id,
    recordVersion: item.record_version,
    waybillNumber: item.waybill_number,
    vehicleNumber: item.vehicle_number,
    status: item.status,
    currentStage: item.current_stage,
    businessOutcome: item.business_outcome,
    isTerminalOutcome: item.is_terminal_outcome,
    platformLoadingNet: item.platform_loading_net,
    platformUnloadingNet: item.platform_unloading_net,
    ticketLoadingNet: item.ticket_loading_net,
    ticketUnloadingNet: item.ticket_unloading_net,
    decision: item.decision,
    reviewReason: item.review_reason,
  };
}

function auditTimelineEvent(
  event: WireAuditTimelineEvent,
): AuditTimelineEvent {
  return {
    eventId: event.timeline_event_id,
    eventType: event.event_type,
    referenceId: event.reference_id,
    createdAt: event.created_at,
  };
}

function auditReviewAction(
  action: WireAuditReviewAction,
): AuditReviewAction {
  return {
    actionId: action.action_id,
    actionType: action.action_type,
    reasonCode: action.reason_code,
    correctValue: action.correct_value,
    note: action.note,
    revokesActionId: action.revokes_action_id,
    createdAt: action.created_at,
  };
}

function auditReviewItem(item: WireAuditItem): AuditReviewItem {
  const issue = (name: string) => ({
    hasIssue: item.field_issues?.[name]?.has_issue === true,
  });
  return {
    workItemId: item.work_item_id,
    jobId: item.job_id,
    waybillId: item.waybill_id,
    vehicleNumber: item.vehicle_number,
    recordVersion: item.record_version,
    status: item.status,
    businessOutcome: item.business_outcome,
    decision: item.decision,
    reviewReason: item.review_reason,
    diagnosticCode: item.diagnostic_code,
    fieldIssueDiagnosticCode: item.field_issue_diagnostic_code ?? null,
    platformLoadingNet: item.platform_loading_net,
    platformUnloadingNet: item.platform_unloading_net,
    ticketLoadingNet: item.ticket_loading_net,
    ticketUnloadingNet: item.ticket_unloading_net,
    loadingImageSha256: item.evidence?.loading_image_sha256 ?? null,
    unloadingImageSha256: item.evidence?.unloading_image_sha256 ?? null,
    runMode: item.run_mode,
    availableActions: item.available_actions,
    timeline: (item.timeline ?? []).map(auditTimelineEvent),
    reviewActions: (item.review_actions ?? []).map(auditReviewAction),
    fieldIssues: {
      loading_ticket: issue("loading_ticket"),
      loading_ocr_weight: issue("loading_ocr_weight"),
      loading_platform_weight: issue("loading_platform_weight"),
      unloading_ticket: issue("unloading_ticket"),
      unloading_ocr_weight: issue("unloading_ocr_weight"),
      unloading_platform_weight: issue("unloading_platform_weight"),
    },
    reviewHighlightRoles: item.review_highlight_roles,
  };
}

function resourceSummary(resource: WireResource): ResourceSummary {
  return {
    resourceId: resource.resource_id,
    displayName: resource.display_name,
    statusLabel: resource.status_label,
    capacity: resource.capacity ?? 0,
    inUse: resource.in_use ?? 0,
    waitingJobs: resource.waiting_jobs ?? 0,
    holderLabel: resource.holder_label ?? null,
  };
}

function platformAccessWindow(
  window: WirePlatformAccessWindow,
): PlatformAccessWindow {
  return {
    accessWindowId: window.access_window_id,
    purpose: window.purpose,
    expiresAt: window.expires_at,
    consumedAt: window.consumed_at,
    expired: window.expired,
    recordVersion: window.record_version,
  };
}

function businessConnectionSession(
  session: WireBusinessConnectionSession,
) {
  return {
    businessSessionId: session.business_session_id,
    status: session.status,
    expiresAt: session.expires_at,
    expired: session.expired,
    recordVersion: session.record_version,
  } as const;
}

function platformSession(session: WirePlatformSession): PlatformSession {
  return {
    enabled: session.enabled,
    runMode: session.run_mode,
    connectionMode: session.connection_mode,
    connectionModeLabel: session.connection_mode_label,
    connectionModeRecordVersion: (
      session.connection_mode_record_version
    ),
    browserLifecycle: session.browser_lifecycle,
    browserControlMode: session.browser_control_mode,
    recordVersion: session.record_version,
    runtimeAvailable: session.runtime_available,
    runtimeRunning: session.runtime_running,
    selectedBrowser: session.selected_browser,
    discoveryCapturing: session.discovery_capturing,
    visibleBrowserRunning: session.visible_browser_running,
    controlMode: session.control_mode,
    humanHandoffReady: session.human_handoff_ready,
    loginState: session.login_state,
    activeJobId: session.active_job_id,
    warmSessionReusable: session.warm_session_reusable,
    connectionStatus: session.connection_status,
    contractSubject: {
      availableSubjects: session.contract_subject.available_subjects,
      currentSubjectCode: session.contract_subject.current_subject_code,
      recordVersion: session.contract_subject.record_version,
      updatedAt: session.contract_subject.updated_at,
    },
    contractCandidateSelected: session.contract_candidate_selected,
    contractSelectionSha256: session.contract_selection_sha256,
    accessWindow: session.access_window
      ? platformAccessWindow(session.access_window)
      : null,
    businessSession: session.business_session
      ? businessConnectionSession(session.business_session)
      : null,
    waitingReason: session.waiting_reason,
    availableActions: session.available_actions,
  };
}

function dailyReport(report: WireDailyReport): DailyReportRecord {
  return {
    contractSubjectCode: report.contract_subject_code,
    reportId: report.report_id,
    businessDate: report.business_date,
    status: report.status,
    fileName: report.file_name,
    fileSha256: report.file_sha256,
    dataSnapshotSha256: report.data_snapshot_sha256,
    outputDirectory: report.output_directory,
    rowCount: report.row_count,
    loadingNetTotal: report.loading_net_total,
    recordVersion: report.record_version,
    createdAt: report.created_at,
    confirmedAt: report.confirmed_at,
    stale: report.stale,
  };
}

function dailyItem(item: WireDailyItem): DailyItem {
  return {
    platformWaybillId: item.platform_waybill_id,
    waybillNumber: item.waybill_number,
    vehicleNumber: item.vehicle_number,
    loadingTicket: item.loading_ticket,
    unloadingTicket: item.unloading_ticket,
    machineFields: item.machine_fields,
    effectiveFields: item.effective_fields,
    fieldSources: item.field_sources,
    fieldIssues: Object.fromEntries(
      Object.entries(item.field_issues).map(([key, value]) => [
        key,
        { hasIssue: value.has_issue, message: value.message },
      ]),
    ) as DailyItem["fieldIssues"],
    reviewState: item.review_state,
    materializedAt: item.materialized_at,
    timePrefill: {
      loadingDate: item.time_prefill.loading_date,
      unloadingDate: item.time_prefill.unloading_date,
    },
    recordVersion: item.record_version,
    updatedAt: item.updated_at,
  };
}

function lockedSetReviewProgress(
  progress: WireLockedSetReviewProgress,
): LockedSetReviewProgress {
  return {
    total: progress.total,
    completed: progress.completed,
    remaining: progress.remaining,
    replaceCandidate: progress.replace_candidate,
  };
}

function lockedSetReviewItem(
  item: WireLockedSetReviewItem,
): LockedSetReviewItem {
  return {
    sampleId: item.sample_id,
    position: item.position,
    recordVersion: item.record_version,
    reviewStatus: item.review_status,
    selectionClues: item.selection_clues,
    images: item.images.map((image) => ({
      submittedSlot: image.submitted_slot,
      imageUrl: image.image_url,
      selectionClues: image.selection_clues,
      review:
        image.human_review &&
        image.human_review.role !== null
        ? {
            role: image.human_review.role,
            ordinaryNet: image.human_review.ordinary_net,
            qualityConditions: image.human_review.quality_conditions,
            notes: image.human_review.notes,
          }
        : null,
    })),
    pairReview: item.pair_review
      ? {
          conditions: item.pair_review.conditions,
          notes: item.pair_review.notes,
        }
      : null,
    decision: item.decision,
    replaceReason: item.replace_reason,
  };
}

function loop9Truth(value: WireLoop9ReviewTruth): Loop9ReviewTruth {
  return {
    images: value.images.map((image) => ({
      slot: image.slot,
      imageSha256: image.image_sha256,
      role: image.role,
      ordinaryNet: image.ordinary_net,
      qualityConditions: image.quality_conditions,
    })),
    pairCondition: value.pair_condition,
  };
}

function loop9Progress(
  value: WireLoop9ReviewProgress,
): Loop9ReviewProgress {
  return {
    total: value.total,
    confirmed: value.confirmed,
    draft: value.draft,
    remaining: value.remaining,
  };
}

function loop9Advisory(
  value: WireLoop9DraftSuggestion | WireLoop9MachineResult,
): Loop9DraftSuggestion | Loop9MachineResult {
  if ("truth_status" in value) {
    return {
      kind: "draft_suggestion",
      images: loop9Truth({
        images: value.images,
        pair_condition: value.pair_condition,
      }).images,
      pairCondition: value.pair_condition,
    };
  }
  return {
    kind: "machine_result",
    automaticOutcome: value.automatic_outcome,
    issueCode: value.issue_code,
    diagnosticCode: value.diagnostic_code,
    images: value.images.map((image) => ({
      slot: image.slot,
      imageSha256: image.image_sha256,
      predictedRole: image.predicted_role,
      ordinaryNet: image.ordinary_net,
      roleHighConfidence: image.role_high_confidence,
    })),
  };
}

function loop9ReviewItem(
  value: WireLoop9ReviewItem,
): Loop9ReviewItem {
  return {
    itemIdentitySha256: value.item_identity_sha256,
    position: value.position,
    reviewKind: value.review_kind,
    reviewStatus: value.review_status,
    recordVersion: value.record_version,
    platformWeights: {
      loading: value.platform_weights.loading,
      unloading: value.platform_weights.unloading,
    },
    images: value.images.map((image) => ({
      slot: image.slot,
      imageSha256: image.image_sha256,
      imageUrl: image.image_url,
    })),
    advisory: loop9Advisory(value.advisory),
    truth: value.truth ? loop9Truth(value.truth) : null,
    confirmation: value.confirmation,
    confirmedAt: value.confirmed_at,
  };
}

const fixtureDefinitions: Record<
  Loop3FixtureId,
  {
    taskType: "audit" | "loading_probe";
    displayName: string;
  }
> = {
  "audit-batch-long-001": {
    taskType: "audit",
    displayName: "并行审核演练（长批次）",
  },
  "audit-batch-short-002": {
    taskType: "audit",
    displayName: "并行审核演练（短批次）",
  },
  "loading-probe-001": {
    taskType: "loading_probe",
    displayName: "装卸车并行调度探针",
  },
};

const jobControlActions = new Set(["pause", "resume", "cancel"]);

async function checkedJson<T>(
  input: RequestInfo | URL,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(input, {
    credentials: "same-origin",
    cache: "no-store",
    ...init,
    headers: {
      "X-DaHe-Client-Version": __APP_VERSION__,
      ...init.headers,
    },
  });
  if (!response.ok) {
    let body: WireError = {};
    try {
      body = (await response.json()) as WireError;
    } catch {
      // Keep the status-only fallback for malformed local responses.
    }
    if (
      response.status === 409 &&
      body.error?.code === "client_version_mismatch"
    ) {
      throw new ApiVersionMismatchError();
    }
    if (
      response.status === 403 &&
      (body.error?.code === "developer_revalidation_required" ||
        body.error?.code === "developer_action_revalidation_required")
    ) {
      throw new TemplateMaintenanceRequiredError();
    }
    throw new Error(
      body.error?.message ??
        `Local API request failed with status ${response.status}.`,
    );
  }
  return (await response.json()) as T;
}

export class BrowserAppServices implements AppServices {
  private csrfToken: string | null = null;
  private createIdempotencyKey: string | null = null;
  private readonly fixtureIdempotencyKeys = new Map<Loop3FixtureId, string>();
  private readonly actionIdempotencyKeys = new Map<string, string>();
  private readonly templateIdempotencyKeys = new Map<string, string>();
  private readonly platformIdempotencyKeys = new Map<string, string>();
  private readonly lockedSetReviewIdempotencyKeys = new Map<
    string,
    { key: string; payload: string }
  >();
  private readonly loop9ReviewIdempotencyKeys = new Map<
    string,
    { key: string; payload: string }
  >();

  async bootstrap(): Promise<BootstrapResult> {
    const result = await checkedJson<{
      application_version: string;
      csrf_token: string;
      locked_set_review_enabled?: boolean;
      loop9_review_enabled?: boolean;
      production_read_only?: boolean;
    }>("/api/v1/session");
    if (result.application_version !== __APP_VERSION__) {
      throw new ApiVersionMismatchError();
    }
    this.csrfToken = result.csrf_token;
    return {
      applicationVersion: result.application_version,
      csrfToken: result.csrf_token,
      lockedSetReviewEnabled: result.locked_set_review_enabled ?? false,
      loop9ReviewEnabled: result.loop9_review_enabled ?? false,
      productionReadOnly: result.production_read_only ?? false,
    };
  }

  async shutdownApplication(): Promise<void> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    await checkedJson<{ accepted: boolean }>("/api/v1/system/shutdown", {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
    });
  }

  private mapUpdateStatus(result: {
    state: UpdateStatus["state"];
    current_version: string;
    available_version: string | null;
    update_available: boolean;
    checked_at: string | null;
    error_code: string | null;
  }): UpdateStatus {
    return {
      state: result.state,
      currentVersion: result.current_version,
      availableVersion: result.available_version,
      updateAvailable: result.update_available,
      checkedAt: result.checked_at,
      errorCode: result.error_code,
    };
  }

  async loadUpdateStatus(): Promise<UpdateStatus> {
    return this.mapUpdateStatus(
      await checkedJson<{
        state: UpdateStatus["state"];
        current_version: string;
        available_version: string | null;
        update_available: boolean;
        checked_at: string | null;
        error_code: string | null;
      }>("/api/v1/system/update-status"),
    );
  }

  async checkForUpdates(): Promise<UpdateStatus> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      state: UpdateStatus["state"];
      current_version: string;
      available_version: string | null;
      update_available: boolean;
      checked_at: string | null;
      error_code: string | null;
    }>("/api/v1/system/updates/check", {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
    });
    return this.mapUpdateStatus(result);
  }

  async installUpdate(): Promise<UpdateStatus> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      state: UpdateStatus["state"];
      current_version: string;
      available_version: string | null;
      update_available: boolean;
      checked_at: string | null;
      error_code: string | null;
    }>("/api/v1/system/updates/install", {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
    });
    return this.mapUpdateStatus(result);
  }

  async importUpdatePackage(
    manifest: File,
    application: File,
  ): Promise<UpdateStatus> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const created = await checkedJson<{
      import_id: string;
      application_file_name: string;
    }>("/api/v1/system/updates/imports", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: manifest,
    });
    if (application.name !== created.application_file_name) {
      throw new Error("应用 ZIP 文件名与更新清单不一致。");
    }
    const result = await checkedJson<{
      state: UpdateStatus["state"];
      current_version: string;
      available_version: string | null;
      update_available: boolean;
      checked_at: string | null;
      error_code: string | null;
    }>(`/api/v1/system/updates/imports/${encodeURIComponent(created.import_id)}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
        "X-DaHe-Update-File-Name": application.name,
      },
      body: application,
    });
    return this.mapUpdateStatus(result);
  }

  async recordBreadcrumb(
    page: "settlement" | "daily" | "history" | "system",
  ): Promise<void> {
    if (!this.csrfToken) return;
    await checkedJson<{ accepted: boolean }>("/api/v1/diagnostics/breadcrumbs", {
      method: "POST",
      headers: {
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({ page, action_type: "page_opened" }),
    });
  }

  async loadEnvironmentSnapshot(): Promise<EnvironmentSnapshot> {
    const result = await checkedJson<{
      application: { version: string; commit: string; resource_sha256: string };
      windows: { release: string; version: string; architecture: string };
      database: { schema_revision: string; integrity: string };
      runtime: { edge_worker: string | null; ocr_cpu: string | null };
      resources: {
        disk_free_bytes: number;
        cpu_count: number | null;
        gpu: { available: boolean; device_count: number; devices?: string[] };
      };
    }>("/api/v1/diagnostics/environment");
    return {
      application: {
        version: result.application.version,
        commit: result.application.commit,
        resourceSha256: result.application.resource_sha256,
      },
      windows: result.windows,
      database: {
        schemaRevision: result.database.schema_revision,
        integrity: result.database.integrity,
      },
      runtime: {
        edgeWorker: result.runtime.edge_worker,
        ocrCpu: result.runtime.ocr_cpu,
      },
      resources: {
        diskFreeBytes: result.resources.disk_free_bytes,
        cpuCount: result.resources.cpu_count,
        gpu: {
          available: result.resources.gpu.available,
          deviceCount: result.resources.gpu.device_count,
          devices: result.resources.gpu.devices,
        },
      },
    };
  }

  async exportDiagnosticBundle(): Promise<void> {
    const response = await fetch("/api/v1/diagnostics/support-bundle", {
      credentials: "same-origin",
      headers: { "X-DaHe-Client-Version": __APP_VERSION__ },
    });
    if (!response.ok) {
      throw new Error("诊断包生成失败，请稍后重试。");
    }
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = "dahe-diagnostic-package.zip";
    link.click();
    URL.revokeObjectURL(url);
  }

  async openDiagnosticsDirectory(): Promise<void> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    await checkedJson<{ opened: boolean }>(
      "/api/v1/diagnostics/open-directory",
      {
        method: "POST",
        headers: {
          "X-CSRF-Token": this.csrfToken,
          "Idempotency-Key": crypto.randomUUID(),
        },
      },
    );
  }

  async loadLockedSetReview(): Promise<LockedSetReviewIndex> {
    const result = await checkedJson<WireLockedSetReviewIndex>(
      "/api/v1/locked-set-review",
    );
    return {
      packageId: result.package.package_id,
      status: result.package.status,
      progress: lockedSetReviewProgress(result.progress),
      items: result.items.map((item) => ({
        sampleId: item.sample_id,
        position: item.position,
        reviewStatus: item.review_status,
        recordVersion: item.record_version,
        decision: item.decision,
      })),
    };
  }

  async loadLockedSetReviewItem(
    sampleId: string,
  ): Promise<LockedSetReviewItem> {
    return lockedSetReviewItem(
      await checkedJson<WireLockedSetReviewItem>(
        `/api/v1/locked-set-review/items/${encodeURIComponent(sampleId)}`,
      ),
    );
  }

  async saveLockedSetReviewItem(
    sampleId: string,
    input: SaveLockedSetReviewInput,
  ): Promise<SaveLockedSetReviewResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (
      !Number.isInteger(input.expectedRecordVersion) ||
      input.expectedRecordVersion < 0
    ) {
      throw new Error("The locked-set review record version is invalid.");
    }
    const serializedPayload = JSON.stringify(input);
    const pending = this.lockedSetReviewIdempotencyKeys.get(sampleId);
    const idempotencyKey =
      pending?.payload === serializedPayload
        ? pending.key
        : crypto.randomUUID();
    this.lockedSetReviewIdempotencyKeys.set(sampleId, {
      key: idempotencyKey,
      payload: serializedPayload,
    });
    const result = await checkedJson<{
      item: WireLockedSetReviewItem;
      progress: WireLockedSetReviewProgress;
    }>(
      `/api/v1/locked-set-review/items/${encodeURIComponent(sampleId)}/review`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({
          expected_record_version: input.expectedRecordVersion,
          decision: input.decision,
          images: input.images.map((image) => ({
            submitted_slot: image.submittedSlot,
            role: image.role,
            ordinary_net: image.ordinaryNet,
            quality_conditions: image.qualityConditions,
            notes: image.notes,
          })),
          pair_conditions: input.pairConditions,
          pair_notes: input.pairNotes,
          replace_reason: input.replaceReason,
        }),
      },
    );
    this.lockedSetReviewIdempotencyKeys.delete(sampleId);
    return {
      item: lockedSetReviewItem(result.item),
      progress: lockedSetReviewProgress(result.progress),
    };
  }

  async loadLoop9Review(): Promise<Loop9ReviewIndex> {
    const result = await checkedJson<WireLoop9ReviewIndex>(
      "/api/v1/loop9-review",
    );
    return {
      packageSha256: result.package_sha256,
      reviewKind: result.review_kind,
      advisoryMessage: result.advisory_message,
      reviewRevisionSha256: result.review_revision_sha256,
      progress: loop9Progress(result.progress),
      items: result.items.map((item) => ({
        itemIdentitySha256: item.item_identity_sha256,
        position: item.position,
        reviewStatus: item.review_status,
        recordVersion: item.record_version,
      })),
    };
  }

  async loadLoop9ReviewItem(
    itemIdentitySha256: string,
  ): Promise<Loop9ReviewItem> {
    return loop9ReviewItem(
      await checkedJson<WireLoop9ReviewItem>(
        `/api/v1/loop9-review/items/${encodeURIComponent(itemIdentitySha256)}`,
      ),
    );
  }

  private async saveLoop9Review(
    action: "draft" | "confirm",
    itemIdentitySha256: string,
    input: SaveLoop9ReviewInput,
    verifiedImageSha256s: [string, string] | null,
  ): Promise<SaveLoop9ReviewResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const serializedPayload = JSON.stringify({ action, input });
    const mapKey = `${action}:${itemIdentitySha256}`;
    const pending = this.loop9ReviewIdempotencyKeys.get(mapKey);
    const idempotencyKey =
      pending?.payload === serializedPayload
        ? pending.key
        : crypto.randomUUID();
    this.loop9ReviewIdempotencyKeys.set(mapKey, {
      key: idempotencyKey,
      payload: serializedPayload,
    });
    const result = await checkedJson<{
      item: WireLoop9ReviewItem;
      progress: WireLoop9ReviewProgress;
      review_revision_sha256: string;
    }>(
      `/api/v1/loop9-review/items/${encodeURIComponent(itemIdentitySha256)}/${action}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({
          expected_record_version: input.expectedRecordVersion,
          truth: {
            images: input.truth.images.map((image) => ({
              slot: image.slot,
              image_sha256: image.imageSha256,
              role: image.role,
              ordinary_net: image.ordinaryNet,
              quality_conditions: image.qualityConditions,
            })),
            pair_condition: input.truth.pairCondition,
          },
          ...(verifiedImageSha256s
            ? {
                verified_image_sha256s: verifiedImageSha256s,
              }
            : {}),
        }),
      },
    );
    this.loop9ReviewIdempotencyKeys.delete(mapKey);
    return {
      item: loop9ReviewItem(result.item),
      progress: loop9Progress(result.progress),
      reviewRevisionSha256: result.review_revision_sha256,
    };
  }

  async saveLoop9ReviewDraft(
    itemIdentitySha256: string,
    input: SaveLoop9ReviewInput,
  ): Promise<SaveLoop9ReviewResult> {
    return this.saveLoop9Review(
      "draft",
      itemIdentitySha256,
      input,
      null,
    );
  }

  async confirmLoop9ReviewItem(
    itemIdentitySha256: string,
    input: ConfirmLoop9ReviewInput,
  ): Promise<SaveLoop9ReviewResult> {
    return this.saveLoop9Review(
      "confirm",
      itemIdentitySha256,
      input,
      input.verifiedImageSha256s,
    );
  }

  async exportLoop9Review(
    expectedReviewRevisionSha256: string,
  ): Promise<ExportLoop9ReviewResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const mapKey = "export";
    const serializedPayload = JSON.stringify({
      expectedReviewRevisionSha256,
    });
    const pending = this.loop9ReviewIdempotencyKeys.get(mapKey);
    const idempotencyKey =
      pending?.payload === serializedPayload
        ? pending.key
        : crypto.randomUUID();
    this.loop9ReviewIdempotencyKeys.set(mapKey, {
      key: idempotencyKey,
      payload: serializedPayload,
    });
    const result = await checkedJson<{
      file_name: string;
      canonical_sha256: string;
      review_revision_sha256: string;
    }>("/api/v1/loop9-review/export", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify({
        expected_review_revision_sha256: expectedReviewRevisionSha256,
      }),
    });
    this.loop9ReviewIdempotencyKeys.delete(mapKey);
    return {
      fileName: result.file_name,
      canonicalSha256: result.canonical_sha256,
      reviewRevisionSha256: result.review_revision_sha256,
    };
  }

  async loadSnapshot(): Promise<ConsoleSnapshot> {
    const result = await checkedJson<WireSnapshot>("/api/v1/jobs");
    return {
      eventCursor: result.event_cursor,
      jobs: result.jobs.map(jobSummary),
      resources: (result.resources ?? []).map(resourceSummary),
      startActions: actionMatrix(result.start_actions),
    };
  }

  async loadResources(): Promise<ResourceSummary[]> {
    const result = await checkedJson<{ resources: WireResource[] }>(
      "/api/v1/resources",
    );
    return result.resources.map(resourceSummary);
  }

  async loadJobItems(jobId: string): Promise<JobItem[]> {
    const result = await checkedJson<{ items: WireJobItem[] }>(
      `/api/v1/jobs/${encodeURIComponent(jobId)}/items`,
    );
    return result.items.map(jobItem);
  }

  async loadAuditReviewItems(): Promise<AuditReviewItem[]> {
    const result = await checkedJson<{ items: WireAuditItem[] }>(
      "/api/v1/audit/review-items",
    );
    return result.items.map(auditReviewItem);
  }

  async loadAuditWorkspaceItems(
    view: AuditWorkspaceView,
    jobId?: string,
  ): Promise<AuditWorkspaceResult> {
    const parameters = new URLSearchParams({ view });
    if (jobId) parameters.set("job_id", jobId);
    const result = await checkedJson<{
      items: WireAuditItem[];
      counts: Record<AuditWorkspaceView, number>;
    }>(
      `/api/v1/audit/items?${parameters.toString()}`,
    );
    return {
      items: result.items.map(auditReviewItem),
      counts: result.counts,
    };
  }

  async loadSettlementWorkspace(
    view: AuditWorkspaceView,
    contractSubjectCode = "shanxi_guienbo" as const,
  ): Promise<SettlementWorkspaceResult> {
    const result = await checkedJson<{
      latest_fetch: null | {
        created_at: string;
        started_at: string;
        phase_started_at: string;
        updated_at: string;
        finished_at: string | null;
        elapsed_seconds: number;
        estimated_remaining_seconds: number | null;
        estimate_state: "estimating" | "estimated" | "complete" | "unavailable";
        is_terminal: boolean;
        status: "running" | "complete" | "incomplete";
        is_complete: boolean;
        phase_label: string;
        progress_current: number;
        progress_total: number;
        fetched_count: number;
        recognized_count: number;
        technical_failure_count: number;
        phase: SettlementLatestFetch["phase"];
        metadata_checked: number;
        reused: number;
        images_downloaded: number;
        ocr_completed: number;
        ocr_images_completed: number;
        ocr_images_total: number;
        finalized: number;
      };
      items: WireAuditItem[];
      counts: Record<AuditWorkspaceView, number>;
      source_job_id?: string;
      source_record_version?: number;
      capture_mode?: "batch_v1" | "whole_run_v1";
      visible_prefix_count?: number;
      online_capture_complete?: boolean;
    }>(`/api/v1/settlement/workspace?view=${encodeURIComponent(view)}&contract_subject_code=${encodeURIComponent(contractSubjectCode)}`);
    return {
      items: result.items.map(auditReviewItem),
      counts: result.counts,
      sourceJobId: result.source_job_id ?? null,
      sourceRecordVersion: result.source_record_version ?? 0,
      captureMode: result.capture_mode ?? "batch_v1",
      visiblePrefixCount: result.visible_prefix_count ?? result.items.length,
      onlineCaptureComplete: result.online_capture_complete ?? false,
      latestFetch: result.latest_fetch
        ? {
            createdAt: result.latest_fetch.created_at,
            startedAt: result.latest_fetch.started_at,
            phaseStartedAt: result.latest_fetch.phase_started_at,
            updatedAt: result.latest_fetch.updated_at,
            finishedAt: result.latest_fetch.finished_at,
            elapsedSeconds: result.latest_fetch.elapsed_seconds,
            estimatedRemainingSeconds: result.latest_fetch.estimated_remaining_seconds,
            estimateState: result.latest_fetch.estimate_state,
            isTerminal: result.latest_fetch.is_terminal,
            status: result.latest_fetch.status,
            isComplete: result.latest_fetch.is_complete,
            phaseLabel: result.latest_fetch.phase_label,
            progressCurrent: result.latest_fetch.progress_current,
            progressTotal: result.latest_fetch.progress_total,
            fetchedCount: result.latest_fetch.fetched_count,
            recognizedCount: result.latest_fetch.recognized_count,
            technicalFailureCount:
              result.latest_fetch.technical_failure_count,
            phase: result.latest_fetch.phase,
            metadataChecked: result.latest_fetch.metadata_checked,
            reused: result.latest_fetch.reused,
            imagesDownloaded: result.latest_fetch.images_downloaded,
            ocrCompleted: result.latest_fetch.ocr_completed,
            ocrImagesCompleted: result.latest_fetch.ocr_images_completed,
            ocrImagesTotal: result.latest_fetch.ocr_images_total,
            finalized: result.latest_fetch.finalized,
          }
        : null,
    };
  }

  async loadReadySettlementWaybillNumbers(
    contractSubjectCode = "shanxi_guienbo" as const,
  ): Promise<string[]> {
    const result = await checkedJson<{
      count: number;
      waybill_numbers: string[];
    }>(`/api/v1/settlement/ready-waybill-numbers?contract_subject_code=${encodeURIComponent(contractSubjectCode)}`);
    if (result.count !== result.waybill_numbers.length) {
      throw new Error("可结算运单数量不一致。请刷新后重试。");
    }
    return result.waybill_numbers;
  }

  async prepareSettlementFilterHandoff(
    contractSubjectCode: ContractSubjectCode = "shanxi_guienbo",
  ): Promise<{
    count: number;
    matchedCount: number;
    missingCount: number;
    message: string;
  }> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      count: number;
      matched_count: number;
      missing_count: number;
      message: string;
    }>(
      "/api/v1/platform/settlement-handoffs",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: JSON.stringify({
          expected_record_version: 0,
          contract_subject_code: contractSubjectCode,
        }),
      },
    );
    return {
      count: result.count,
      matchedCount: result.matched_count,
      missingCount: result.missing_count,
      message: result.message,
    };
  }

  async loadProductionReadOnlyStatus(): Promise<ProductionReadOnlyStatus> {
    const result = await checkedJson<{
      status: ProductionReadOnlyStatus["status"];
      target_count: number;
      registered_count: number;
      reviewed_count: number;
      false_normal_count: number;
      guard_active: boolean;
    }>("/api/v1/production-read-only/status");
    return {
      status: result.status,
      targetCount: result.target_count,
      registeredCount: result.registered_count,
      reviewedCount: result.reviewed_count,
      falseNormalCount: result.false_normal_count,
      guardActive: result.guard_active,
    };
  }

  async loadAuditItem(workItemId: string): Promise<AuditReviewItem> {
    return auditReviewItem(
      await checkedJson<WireAuditItem>(
        `/api/v1/audit/items/${encodeURIComponent(workItemId)}`,
      ),
    );
  }

  private async writeAuditItem(
    path: string,
    payload: Record<string, unknown>,
  ): Promise<AuditReviewItem> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{ item: WireAuditItem }>(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify(payload),
    });
    return auditReviewItem(result.item);
  }

  async confirmAuditProblem(
    workItemId: string,
    input: AuditDecisionInput,
  ): Promise<AuditReviewItem> {
    return this.writeAuditItem(
      `/api/v1/audit/items/${encodeURIComponent(workItemId)}/problem-confirmations`,
      {
        expected_record_version: input.expectedRecordVersion,
      },
    );
  }

  async dismissAuditProblem(
    workItemId: string,
    input: AuditDecisionInput,
  ): Promise<AuditReviewItem> {
    return this.writeAuditItem(
      `/api/v1/audit/items/${encodeURIComponent(workItemId)}/problem-dismissals`,
      {
        expected_record_version: input.expectedRecordVersion,
      },
    );
  }

  async revokeAuditAction(
    workItemId: string,
    actionId: string,
    input: AuditRevocationInput,
  ): Promise<AuditReviewItem> {
    return this.writeAuditItem(
      `/api/v1/audit/review-actions/${encodeURIComponent(actionId)}/revoke?work_item_id=${encodeURIComponent(workItemId)}`,
      {
        expected_record_version: input.expectedRecordVersion,
        reason: input.reason,
      },
    );
  }

  async loadWaybillHistory(
    query = "",
    businessOutcome = "",
    contractSubjectCode = "shanxi_guienbo" as const,
  ): Promise<AuditReviewItem[]> {
    const parameters = new URLSearchParams();
    parameters.set("contract_subject_code", contractSubjectCode);
    if (query.trim()) parameters.set("q", query.trim());
    if (businessOutcome) {
      parameters.set("business_outcome", businessOutcome);
    }
    const suffix = `?${parameters.toString()}`;
    const result = await checkedJson<{ items: WireAuditItem[] }>(
      `/api/v1/history/waybills${suffix}`,
    );
    return result.items.map(auditReviewItem);
  }

  async loadDiagnostics(): Promise<DiagnosticsSnapshot> {
    const result = await checkedJson<{
      generated_at: string;
      health: Array<{
        id: string;
        label: string;
        status: "normal" | "attention";
        summary: string;
      }>;
      recent_issues: Array<{
        diagnostic_code: string | null;
        location: string;
        message: string;
        work_item_id: string | null;
      }>;
    }>("/api/v1/diagnostics");
    return {
      generatedAt: result.generated_at,
      health: result.health,
      recentIssues: result.recent_issues.map((issue) => ({
        diagnosticCode: issue.diagnostic_code,
        location: issue.location,
        message: issue.message,
        workItemId: issue.work_item_id,
      })),
    };
  }

  async loadPlatformSession(): Promise<PlatformSession> {
    return platformSession(
      await checkedJson<WirePlatformSession>("/api/v1/platform/session"),
    );
  }

  async selectContractSubject(
    subjectCode: PlatformSession["contractSubject"]["currentSubjectCode"],
    expectedRecordVersion: number,
  ): Promise<PlatformSession["contractSubject"]> {
    if (!this.csrfToken) throw new Error("The local session is not initialized.");
    const result = await checkedJson<WirePlatformSession["contract_subject"]>(
      "/api/v1/platform/contract-subject",
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: JSON.stringify({
          subject_code: subjectCode,
          expected_record_version: expectedRecordVersion,
        }),
      },
    );
    return {
      availableSubjects: result.available_subjects,
      currentSubjectCode: result.current_subject_code,
      recordVersion: result.record_version,
      updatedAt: result.updated_at,
    };
  }

  async loadPlatformCredentials(): Promise<PlatformCredentialStatus> {
    const result = await checkedJson<{
      configured: boolean;
      masked_username: string | null;
      record_version: number;
    }>("/api/v1/platform/credentials", {
      headers: { "Cache-Control": "no-store" },
    });
    return {
      configured: result.configured,
      maskedUsername: result.masked_username,
      recordVersion: result.record_version,
    };
  }

  async savePlatformCredentials(
    input: SavePlatformCredentialInput,
  ): Promise<PlatformCredentialStatus> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const operation = `platform-credentials:save:${input.expectedRecordVersion}:${input.username}`;
    const key = this.platformIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.platformIdempotencyKeys.set(operation, key);
    const result = await checkedJson<{
      configured: boolean;
      masked_username: string | null;
      record_version: number;
    }>("/api/v1/platform/credentials", {
      method: "PUT",
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": key,
      },
      body: JSON.stringify({
        username: input.username,
        password: input.password,
        expected_record_version: input.expectedRecordVersion,
      }),
    });
    this.platformIdempotencyKeys.delete(operation);
    return {
      configured: result.configured,
      maskedUsername: result.masked_username,
      recordVersion: result.record_version,
    };
  }

  async deletePlatformCredentials(
    expectedRecordVersion: number,
  ): Promise<PlatformCredentialStatus> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const operation = `platform-credentials:delete:${expectedRecordVersion}`;
    const key = this.platformIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.platformIdempotencyKeys.set(operation, key);
    const result = await checkedJson<{
      configured: boolean;
      masked_username: string | null;
      record_version: number;
    }>("/api/v1/platform/credentials", {
      method: "DELETE",
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": key,
      },
      body: JSON.stringify({ expected_record_version: expectedRecordVersion }),
    });
    this.platformIdempotencyKeys.delete(operation);
    return {
      configured: result.configured,
      maskedUsername: result.masked_username,
      recordVersion: result.record_version,
    };
  }

  async startPlatformBusinessRead(
    input: StartPlatformBusinessReadInput,
  ): Promise<StartPlatformBusinessReadResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const operation = `platform-business-read:${input.businessScope}:${input.businessDate ?? "current"}`;
    const key = this.platformIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.platformIdempotencyKeys.set(operation, key);
    const result = await checkedJson<{
      created: boolean;
      attached: boolean;
      job: WireJob;
    }>("/api/v1/platform/business-reads", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": key,
      },
      body: JSON.stringify({
        business_scope: input.businessScope,
        contract_subject_code: input.contractSubjectCode,
        ...(input.businessDate ? { business_date: input.businessDate } : {}),
        expected_record_version: input.expectedRecordVersion,
      }),
    });
    this.platformIdempotencyKeys.delete(operation);
    return {
      created: result.created,
      attached: result.attached,
      job: jobSummary(result.job),
    };
  }

  async loadPlatformBusinessReadProgress(
    jobId: string,
  ): Promise<PlatformBusinessReadProgress> {
    return platformBusinessReadProgress(
      await checkedJson<WirePlatformBusinessReadProgress>(
        `/api/v1/platform/business-reads/${encodeURIComponent(jobId)}/progress`,
      ),
    );
  }

  subscribePlatformBusinessReadProgress(
    jobId: string,
    onProgress: (progress: PlatformBusinessReadProgress) => void,
  ): () => void {
    const parameters = new URLSearchParams({
      after: "0",
      client_version: __APP_VERSION__,
    });
    const events = new EventSource(
      `/api/v1/platform/business-reads/${encodeURIComponent(jobId)}/progress/stream?${parameters.toString()}`,
      { withCredentials: true },
    );
    events.addEventListener("progress", (message) => {
      onProgress(
        platformBusinessReadProgress(
          JSON.parse((message as MessageEvent<string>).data) as WirePlatformBusinessReadProgress,
        ),
      );
    });
    return () => events.close();
  }

  async loadDailyReportSettings(): Promise<DailyReportSettings> {
    const result = await checkedJson<{
      shipping_mine: string;
      coal_type: string;
      unloading_place: string;
      query_place_keyword: string;
      output_directory: string;
      confirmed: boolean;
      record_version: number;
    }>("/api/v1/daily/report-settings");
    return {
      shippingMine: result.shipping_mine,
      coalType: result.coal_type,
      unloadingPlace: result.unloading_place,
      queryPlaceKeyword: result.query_place_keyword,
      outputDirectory: result.output_directory,
      confirmed: result.confirmed,
      recordVersion: result.record_version,
    };
  }

  async loadDailyItems(
    businessDate: string,
    contractSubjectCode = "shanxi_guienbo" as const,
  ): Promise<DailyItemsResult> {
    const result = await checkedJson<{
      business_date: string;
      contract_subject_code: ContractSubjectCode;
      items: WireDailyItem[];
      counts: { all: number; needs_review: number; reviewed: number };
      source_job_id: string | null;
      source_record_version: number;
      capture_mode: "batch_v1" | "whole_run_v1";
      visible_prefix_count: number;
      online_capture_complete: boolean;
    }>(`/api/v1/daily/items?business_date=${encodeURIComponent(businessDate)}&contract_subject_code=${encodeURIComponent(contractSubjectCode)}`);
    return {
      businessDate: result.business_date,
      contractSubjectCode: result.contract_subject_code,
      items: result.items.map(dailyItem),
      counts: {
        all: result.counts.all,
        needsReview: result.counts.needs_review,
        reviewed: result.counts.reviewed,
      },
      sourceJobId: result.source_job_id,
      sourceRecordVersion: result.source_record_version,
      captureMode: result.capture_mode,
      visiblePrefixCount: result.visible_prefix_count,
      onlineCaptureComplete: result.online_capture_complete,
    };
  }

  async loadPerformanceSettings(): Promise<PerformanceSettings> {
    const result = await checkedJson<{
      preset: PerformanceSettings["preset"];
      detail_concurrency: number;
      image_concurrency: number;
      network_batch_size: 20 | 50 | 100;
      cpu_ocr_threads: number;
      gpu_idle_minutes: number;
      keep_gpu_ready: boolean;
      record_version: number;
    }>("/api/v1/settings/performance");
    return {
      preset: result.preset,
      detailConcurrency: result.detail_concurrency,
      imageConcurrency: result.image_concurrency,
      networkBatchSize: result.network_batch_size,
      cpuOcrThreads: result.cpu_ocr_threads,
      gpuIdleMinutes: result.gpu_idle_minutes,
      keepGpuReady: result.keep_gpu_ready,
      recordVersion: result.record_version,
    };
  }

  async savePerformanceSettings(settings: PerformanceSettings): Promise<PerformanceSettings> {
    if (!this.csrfToken) throw new Error("The local session is not initialized.");
    const result = await checkedJson<{
      preset: PerformanceSettings["preset"];
      detail_concurrency: number;
      image_concurrency: number;
      network_batch_size: 20 | 50 | 100;
      cpu_ocr_threads: number;
      gpu_idle_minutes: number;
      keep_gpu_ready: boolean;
      record_version: number;
    }>("/api/v1/settings/performance", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": this.csrfToken, "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({
        preset: settings.preset,
        detail_concurrency: settings.detailConcurrency,
        image_concurrency: settings.imageConcurrency,
        network_batch_size: settings.networkBatchSize,
        cpu_ocr_threads: settings.cpuOcrThreads,
        gpu_idle_minutes: settings.gpuIdleMinutes,
        keep_gpu_ready: settings.keepGpuReady,
        expected_record_version: settings.recordVersion,
      }),
    });
    return {
      preset: result.preset,
      detailConcurrency: result.detail_concurrency,
      imageConcurrency: result.image_concurrency,
      networkBatchSize: result.network_batch_size,
      cpuOcrThreads: result.cpu_ocr_threads,
      gpuIdleMinutes: result.gpu_idle_minutes,
      keepGpuReady: result.keep_gpu_ready,
      recordVersion: result.record_version,
    };
  }

  async saveDailyItemRevision(
    platformWaybillId: string,
    businessDate: string,
    expectedRecordVersion: number,
    changes: Partial<Record<DailyEditableField, string | null>>,
    contractSubjectCode = "shanxi_guienbo" as const,
  ): Promise<DailyItemRevisionResult> {
    if (!this.csrfToken) throw new Error("The local session is not initialized.");
    const result = await checkedJson<{
      business_date: string;
      contract_subject_code: ContractSubjectCode;
      item: WireDailyItem;
      counts: { all: number; needs_review: number; reviewed: number };
    }>(
      `/api/v1/daily/items/${encodeURIComponent(platformWaybillId)}/revisions`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: JSON.stringify({
          business_date: businessDate,
          contract_subject_code: contractSubjectCode,
          expected_record_version: expectedRecordVersion,
          changes,
        }),
      },
    );
    return {
      businessDate: result.business_date,
      contractSubjectCode: result.contract_subject_code,
      item: dailyItem(result.item),
      counts: {
        all: result.counts.all,
        needsReview: result.counts.needs_review,
        reviewed: result.counts.reviewed,
      },
    };
  }

  async saveDailyReportSettings(
    input: SaveDailyReportSettingsInput,
  ): Promise<DailyReportSettings> {
    if (!this.csrfToken) throw new Error("The local session is not initialized.");
    const result = await checkedJson<{
      shipping_mine: string;
      coal_type: string;
      unloading_place: string;
      query_place_keyword: string;
      output_directory: string;
      confirmed: boolean;
      record_version: number;
    }>("/api/v1/daily/report-settings", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        shipping_mine: input.shippingMine,
        coal_type: input.coalType,
        unloading_place: input.unloadingPlace,
        query_place_keyword: input.queryPlaceKeyword,
        output_directory: input.outputDirectory,
        confirmed: input.confirmed,
        expected_record_version: input.expectedRecordVersion,
      }),
    });
    return {
      shippingMine: result.shipping_mine,
      coalType: result.coal_type,
      unloadingPlace: result.unloading_place,
      queryPlaceKeyword: result.query_place_keyword,
      outputDirectory: result.output_directory,
      confirmed: result.confirmed,
      recordVersion: result.record_version,
    };
  }

  async findDailyReport(
    businessDate: string,
    contractSubjectCode = "shanxi_guienbo" as const,
  ): Promise<DailyReportRecord | null> {
    const result = await checkedJson<{ report: WireDailyReport | null }>(
      `/api/v1/daily/reports?business_date=${encodeURIComponent(businessDate)}&contract_subject_code=${encodeURIComponent(contractSubjectCode)}`,
    );
    return result.report ? dailyReport(result.report) : null;
  }

  private async writeDailyReport(
    path: string,
    payload: Record<string, unknown>,
  ): Promise<DailyReportRecord> {
    if (!this.csrfToken) throw new Error("The local session is not initialized.");
    const result = await checkedJson<{
      idempotent_replay: boolean;
      report: WireDailyReport;
    }>(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify(payload),
    });
    return dailyReport(result.report);
  }

  async createDailyReport(
    businessDate: string,
    expectedSettingsVersion: number,
    contractSubjectCode = "shanxi_guienbo" as const,
  ): Promise<DailyReportRecord> {
    return this.writeDailyReport("/api/v1/daily/reports", {
      business_date: businessDate,
      contract_subject_code: contractSubjectCode,
      expected_settings_version: expectedSettingsVersion,
    });
  }

  async confirmDailyReport(
    reportId: string,
    expectedRecordVersion: number,
  ): Promise<DailyReportRecord> {
    return this.writeDailyReport(
      `/api/v1/daily/reports/${encodeURIComponent(reportId)}/confirm`,
      { expected_record_version: expectedRecordVersion },
    );
  }

  async saveDailyReportNewCopy(
    reportId: string,
    expectedRecordVersion: number,
  ): Promise<DailyReportRecord> {
    return this.writeDailyReport(
      `/api/v1/daily/reports/${encodeURIComponent(reportId)}/save-new-copy`,
      { expected_record_version: expectedRecordVersion },
    );
  }

  async openDailyReportFolder(
    reportId: string,
    expectedRecordVersion: number,
  ): Promise<void> {
    if (!this.csrfToken) throw new Error("The local session is not initialized.");
    await checkedJson<{ opened: boolean }>(
      `/api/v1/daily/reports/${encodeURIComponent(reportId)}/open-folder`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: JSON.stringify({ expected_record_version: expectedRecordVersion }),
      },
    );
  }

  async switchPlatformConnectionMode(
    mode: "operational_compat" | "strict_shadow",
    expectedRecordVersion: number,
  ): Promise<PlatformSession> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    await checkedJson<{
      connection_mode: string;
      record_version: number;
    }>("/api/v1/platform/connection-mode", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        mode,
        expected_record_version: expectedRecordVersion,
      }),
    });
    return this.loadPlatformSession();
  }

  async startOperationalCapture(
    input: StartOperationalCaptureInput,
  ): Promise<StartOperationalCaptureResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      created: boolean;
      job: WireJob;
      access_window: WirePlatformAccessWindow;
    }>("/api/v1/platform/settlement-captures", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        target_kind: "operational_compat",
        duration_minutes: 720,
        legacy_idle_confirmed: input.legacyIdleConfirmed,
        no_settlement_or_payment_confirmed:
          input.noSettlementOrPaymentConfirmed,
        same_account_session_risk_accepted:
          input.sameAccountSessionRiskAccepted,
        expected_record_version: 0,
      }),
    });
    return {
      created: result.created,
      job: jobSummary(result.job),
      accessWindow: platformAccessWindow(result.access_window),
    };
  }

  async startBusinessConnectionSession(
    input: StartOperationalCaptureInput,
  ): Promise<StartBusinessConnectionSessionResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      created: boolean;
      business_session: WireBusinessConnectionSession;
      access_window: WirePlatformAccessWindow;
    }>("/api/v1/platform/business-session/start", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        legacy_idle_confirmed: input.legacyIdleConfirmed,
        no_settlement_or_payment_confirmed:
          input.noSettlementOrPaymentConfirmed,
        same_account_session_risk_accepted:
          input.sameAccountSessionRiskAccepted,
        expected_record_version: 0,
      }),
    });
    return {
      created: result.created,
      businessSession: businessConnectionSession(result.business_session),
      accessWindow: platformAccessWindow(result.access_window),
    };
  }

  async beginBusinessConnectionRead(
    businessSessionId: string,
    expectedRecordVersion: number,
    expectedBrowserRecordVersion: number,
  ): Promise<BeginBusinessConnectionReadResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      created: boolean;
      business_session: WireBusinessConnectionSession;
      job: WireJob;
    }>("/api/v1/platform/business-session/read", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        business_session_id: businessSessionId,
        expected_record_version: expectedRecordVersion,
        expected_browser_record_version: expectedBrowserRecordVersion,
      }),
    });
    return {
      created: result.created,
      businessSession: businessConnectionSession(result.business_session),
      job: jobSummary(result.job),
    };
  }

  async closeBusinessConnectionSession(
    businessSessionId: string,
    expectedRecordVersion: number,
    expectedBrowserRecordVersion: number,
  ): Promise<BusinessConnectionSession> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      business_session: WireBusinessConnectionSession;
    }>("/api/v1/platform/business-session/close", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        business_session_id: businessSessionId,
        expected_record_version: expectedRecordVersion,
        expected_browser_record_version: expectedBrowserRecordVersion,
      }),
    });
    return businessConnectionSession(result.business_session);
  }

  async createPlatformAccessWindow(
    input: CreatePlatformAccessWindowInput,
  ): Promise<PlatformAccessWindow> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      access_window: WirePlatformAccessWindow;
    }>("/api/v1/platform/access-windows", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        purpose: input.purpose,
        job_id: `${
          input.purpose === "formal_locked_set"
            ? "loop9-read-contract-validation"
            : "loop9-contract-discovery"
        }-${crypto.randomUUID()}`,
        duration_minutes: 60,
        legacy_idle_confirmed: input.legacyIdleConfirmed,
        no_settlement_or_payment_confirmed:
          input.noSettlementOrPaymentConfirmed,
        same_account_session_risk_accepted:
          input.sameAccountSessionRiskAccepted,
        expected_record_version: 0,
      }),
    });
    return platformAccessWindow(result.access_window);
  }

  private async writePlatformControl(
    path: string,
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformSession> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    await checkedJson<{ platform_session: object }>(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        access_window_id: accessWindowId,
        expected_record_version: expectedRecordVersion,
      }),
    });
    return this.loadPlatformSession();
  }

  async startPlatformHumanLogin(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformSession> {
    return this.writePlatformControl(
      "/api/v1/platform/session/human-login/start",
      accessWindowId,
      expectedRecordVersion,
    );
  }

  async returnPlatformHumanLogin(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformSession> {
    return this.writePlatformControl(
      "/api/v1/platform/session/human-login/return",
      accessWindowId,
      expectedRecordVersion,
    );
  }

  async startPlatformDiscoveryCapture(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformSession> {
    return this.writePlatformControl(
      "/api/v1/platform/discovery/start",
      accessWindowId,
      expectedRecordVersion,
    );
  }

  async stopPlatformDiscoveryCapture(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<{
    evidenceId: string;
    canonicalSha256: string;
    observationCount: number;
  }> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      discovery_evidence: {
        evidence_id: string;
        canonical_sha256: string;
        observation_count: number;
      };
    }>("/api/v1/platform/discovery/stop", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        access_window_id: accessWindowId,
        expected_record_version: expectedRecordVersion,
      }),
    });
    return {
      evidenceId: result.discovery_evidence.evidence_id,
      canonicalSha256: result.discovery_evidence.canonical_sha256,
      observationCount: result.discovery_evidence.observation_count,
    };
  }

  async validatePlatformReadContract(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<{
    evidenceId: string;
    canonicalSha256: string;
    selectionSha256: string;
    listItemCount: number;
    detailAttemptCount: number;
    imageCount: number;
  }> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const result = await checkedJson<{
      contract_validation: {
        evidence_id: string;
        canonical_sha256: string;
        selection_sha256: string;
        list_item_count: number;
        detail_attempt_count: number;
        image_count: number;
      };
    }>("/api/v1/platform/contract-validation", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({
        access_window_id: accessWindowId,
        expected_record_version: expectedRecordVersion,
      }),
    });
    return {
      evidenceId: result.contract_validation.evidence_id,
      canonicalSha256: result.contract_validation.canonical_sha256,
      selectionSha256: result.contract_validation.selection_sha256,
      listItemCount: result.contract_validation.list_item_count,
      detailAttemptCount: result.contract_validation.detail_attempt_count,
      imageCount: result.contract_validation.image_count,
    };
  }

  async closePlatformSession(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformSession> {
    return this.writePlatformControl(
      "/api/v1/platform/session/close",
      accessWindowId,
      expectedRecordVersion,
    );
  }

  async loadRuntimeLogs(query: RuntimeLogQuery = {}): Promise<RuntimeLogPage> {
    const parameters = new URLSearchParams();
    if (query.before) parameters.set("before", query.before);
    if (query.after) parameters.set("after", query.after);
    if (query.limit) parameters.set("limit", String(query.limit));
    if (query.level) parameters.set("level", query.level);
    if (query.source) parameters.set("source", query.source);
    if (query.text) parameters.set("text", query.text);
    const suffix = parameters.size ? `?${parameters.toString()}` : "";
    const result = await checkedJson<{
      events: Array<{
        event_id: string;
        created_at: string;
        level: RuntimeLogEvent["level"];
        source: string;
        event_code: string;
        stream: RuntimeLogEvent["stream"];
        message: string;
        diagnostic_code: string | null;
        job_id: string | null;
        work_item_id: string | null;
      }>;
      earliest_cursor: string | null;
      latest_cursor: string | null;
      has_more_older: boolean;
    }>(`/api/v1/diagnostics/logs${suffix}`);
    return {
      events: result.events.map((event) => ({
        eventId: event.event_id,
        createdAt: event.created_at,
        level: event.level,
        source: event.source,
        eventCode: event.event_code,
        stream: event.stream,
        message: event.message,
        diagnosticCode: event.diagnostic_code,
        jobId: event.job_id,
        workItemId: event.work_item_id,
      })),
      earliestCursor: result.earliest_cursor,
      latestCursor: result.latest_cursor,
      hasMoreOlder: result.has_more_older,
    };
  }

  subscribeRuntimeLogs(
    afterCursor: string | null,
    onEvent: (event: RuntimeLogEvent) => void,
  ): () => void {
    const parameters = new URLSearchParams({
      after: afterCursor ?? "0",
      client_version: __APP_VERSION__,
    });
    const events = new EventSource(
      `/api/v1/diagnostics/logs/stream?${parameters.toString()}`,
      { withCredentials: true },
    );
    events.addEventListener("runtime-log", (message) => {
      const payload = JSON.parse((message as MessageEvent<string>).data) as {
        event_id: string;
        created_at: string;
        level: RuntimeLogEvent["level"];
        source: string;
        event_code: string;
        stream: RuntimeLogEvent["stream"];
        message: string;
        diagnostic_code: string | null;
        job_id: string | null;
        work_item_id: string | null;
      };
      onEvent({
        eventId: payload.event_id,
        createdAt: payload.created_at,
        level: payload.level,
        source: payload.source,
        eventCode: payload.event_code,
        stream: payload.stream,
        message: payload.message,
        diagnosticCode: payload.diagnostic_code,
        jobId: payload.job_id,
        workItemId: payload.work_item_id,
      });
    });
    return () => events.close();
  }

  async createAuditJob(
    expectedRecordVersion: number,
  ): Promise<CreateJobResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!Number.isInteger(expectedRecordVersion) || expectedRecordVersion < 0) {
      throw new Error("The start action record version is invalid.");
    }
    this.createIdempotencyKey ??= crypto.randomUUID();
    const result = await checkedJson<{
      created: boolean;
      job: WireJob;
    }>("/api/v1/jobs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "X-Idempotency-Key": this.createIdempotencyKey,
      },
      body: JSON.stringify({
        task_type: "audit",
        scope: {
          label: "单条假数据审核",
          fixture_id: "audit-normal-001",
        },
        expected_record_version: expectedRecordVersion,
      }),
    });
    this.createIdempotencyKey = null;
    return {
      created: result.created,
      job: jobSummary(result.job),
    };
  }

  async createFixtureJob(
    fixtureId: Loop3FixtureId,
    expectedRecordVersion: number,
  ): Promise<CreateJobResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    const definition = fixtureDefinitions[fixtureId];
    if (!definition) {
      throw new Error("The requested protected fixture is not declared.");
    }
    if (!Number.isInteger(expectedRecordVersion) || expectedRecordVersion < 0) {
      throw new Error("The start action record version is invalid.");
    }

    const idempotencyKey =
      this.fixtureIdempotencyKeys.get(fixtureId) ?? crypto.randomUUID();
    this.fixtureIdempotencyKeys.set(fixtureId, idempotencyKey);
    const result = await checkedJson<{
      created: boolean;
      job: WireJob;
    }>("/api/v1/jobs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "X-Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify({
        task_type: definition.taskType,
        job_kind: "test_fixture",
        scope: {
          label: definition.displayName,
          fixture_id: fixtureId,
        },
        expected_record_version: expectedRecordVersion,
      }),
    });
    this.fixtureIdempotencyKeys.delete(fixtureId);
    return {
      created: result.created,
      job: jobSummary(result.job),
    };
  }

  async loadTemplateFamilies(): Promise<TemplateFamilyIndex> {
    const result = await checkedJson<WireTemplateFamilyIndex>(
      "/api/v1/template-studio/families",
    );
    return mapTemplateFamilyIndex(result);
  }

  async loadTemplateFamily(
    familyId: string,
  ): Promise<TemplateVersionSnapshot> {
    const result = await checkedJson<WireTemplateVersionSnapshot>(
      `/api/v1/template-studio/families/${encodeURIComponent(familyId)}`,
    );
    return mapTemplateVersion(result);
  }

  async unlockTemplateMaintenance(
    accessCode: string,
  ): Promise<TemplateFamilyIndex> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!accessCode.trim()) {
      throw new Error("The maintenance access code is required.");
    }
    const operation = "template:maintenance-session";
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    const result = await checkedJson<WireTemplateFamilyIndex>(
      "/api/v1/template-studio/developer/revalidate",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "X-Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({
          access_code: accessCode,
          action: "template.maintenance_session",
          resource_id: "template-studio",
        }),
      },
    );
    this.templateIdempotencyKeys.delete(operation);
    return mapTemplateFamilyIndex(result);
  }

  async uploadTemplateReference(
    file: File,
  ): Promise<StagedTemplateReference> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!file.name.trim() || file.size < 1) {
      throw new Error("The reference image file is empty.");
    }
    if (file.type !== "image/png" && file.type !== "image/jpeg") {
      throw new Error("The reference image must be PNG or JPEG.");
    }
    const operation = `template:reference-upload:${file.name}:${file.size}:${file.lastModified}`;
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    const result = await checkedJson<{ upload: WireStagedTemplateReference }>(
      "/api/v1/template-studio/reference-images",
      {
        method: "POST",
        headers: {
          "Content-Type": file.type,
          "X-DaHe-File-Name": encodeURIComponent(file.name),
          "X-CSRF-Token": this.csrfToken,
          "X-Idempotency-Key": idempotencyKey,
        },
        body: file,
      },
    );
    this.templateIdempotencyKeys.delete(operation);
    return mapStagedTemplateReference(result.upload);
  }

  async abandonTemplateReference(
    stagedReferenceId: string,
    expectedRecordVersion: number,
  ): Promise<void> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!stagedReferenceId.trim()) {
      throw new Error("The staged reference identifier is required.");
    }
    if (!Number.isInteger(expectedRecordVersion) || expectedRecordVersion < 1) {
      throw new Error("The staged reference record version is invalid.");
    }
    const operation = `template:reference-abandon:${stagedReferenceId}:${expectedRecordVersion}`;
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    await checkedJson<object>(
      `/api/v1/template-studio/reference-images/${encodeURIComponent(stagedReferenceId)}/abandon`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "X-Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({
          expected_record_version: expectedRecordVersion,
        }),
      },
    );
    this.templateIdempotencyKeys.delete(operation);
  }

  async createTemplateFromStagedReference(
    stagedReferenceId: string,
    expectedRecordVersion: number,
    familyName: string,
    role: TemplateRole,
    draft: TemplateDraft,
  ): Promise<{ created: boolean; template: TemplateVersionSnapshot }> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!stagedReferenceId.trim()) {
      throw new Error("The staged reference identifier is required.");
    }
    if (!Number.isInteger(expectedRecordVersion) || expectedRecordVersion < 1) {
      throw new Error("The staged reference record version is invalid.");
    }
    if (!familyName.trim()) {
      throw new Error("The template family name is required.");
    }
    if (role !== "loading" && role !== "unloading") {
      throw new Error("The template role is invalid.");
    }
    if (draft.anchors.length < 1) {
      throw new Error("The template draft requires a fixed-content anchor.");
    }
    const operation = `template:create-from-reference:${stagedReferenceId}:${expectedRecordVersion}`;
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    const result = await checkedJson<{
      created: boolean;
      template: WireTemplateVersionSnapshot;
    }>("/api/v1/template-studio/templates/from-staged-reference", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "X-Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify({
        staged_reference_id: stagedReferenceId,
        expected_record_version: expectedRecordVersion,
        family_name: familyName.trim(),
        role,
        draft: serializeTemplateDraft(draft),
      }),
    });
    this.templateIdempotencyKeys.delete(operation);
    return {
      created: result.created,
      template: mapTemplateVersion(result.template),
    };
  }

  async saveTemplateDraft(
    versionId: string,
    expectedRecordVersion: number,
    draft: TemplateDraft,
  ): Promise<TemplateVersionSnapshot> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!Number.isInteger(expectedRecordVersion) || expectedRecordVersion < 1) {
      throw new Error("The template record version is invalid.");
    }
    const operation = `template:save:${versionId}:${expectedRecordVersion}`;
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    const result = await checkedJson<WireTemplateVersionSnapshot>(
      `/api/v1/template-studio/templates/${encodeURIComponent(versionId)}/draft`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "X-Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({
          expected_record_version: expectedRecordVersion,
          draft: serializeTemplateDraft(draft),
        }),
      },
    );
    this.templateIdempotencyKeys.delete(operation);
    return mapTemplateVersion(result);
  }

  async runTemplateDevelopmentCheck(
    versionId: string,
    expectedRecordVersion: number,
    evaluationId?: string,
  ): Promise<TemplateVersionSnapshot> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!Number.isInteger(expectedRecordVersion) || expectedRecordVersion < 1) {
      throw new Error("The template record version is invalid.");
    }
    if (!evaluationId?.trim()) {
      throw new Error(
        "A completed development evaluation identifier is required.",
      );
    }
    const operation = `template:development-check:${versionId}:${expectedRecordVersion}`;
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    const result = await checkedJson<WireTemplateVersionSnapshot>(
      `/api/v1/template-studio/templates/${encodeURIComponent(versionId)}/development-tested`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "X-Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({
          expected_record_version: expectedRecordVersion,
          evaluation_id: evaluationId,
        }),
      },
    );
    this.templateIdempotencyKeys.delete(operation);
    return mapTemplateVersion(result);
  }

  async revalidateTemplateShadowAction(
    accessCode: string,
    versionId: string,
  ): Promise<string> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!accessCode.trim()) {
      throw new Error("The maintenance access code is required.");
    }
    if (!versionId.trim()) {
      throw new Error("The template version identifier is required.");
    }
    const operation = `template:shadow-revalidate:${versionId}`;
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    const result = await checkedJson<
      WireTemplateFamilyIndex & {
        authorization_token?: string | null;
      }
    >("/api/v1/template-studio/developer/revalidate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "X-Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify({
        access_code: accessCode,
        action: "template.publish_shadow",
        resource_id: versionId,
      }),
    });
    if (!result.authorization_token?.trim()) {
      throw new Error(
        "The backend did not issue a shadow publication authorization.",
      );
    }
    this.templateIdempotencyKeys.delete(operation);
    return result.authorization_token;
  }

  async loadTemplateFamilyVersions(
    familyId: string,
  ): Promise<TemplateRollbackOptions> {
    if (!familyId.trim()) {
      throw new Error("The template family identifier is required.");
    }
    const result = await checkedJson<WireTemplateRollbackOptions>(
      `/api/v1/template-studio/families/${encodeURIComponent(familyId)}/versions`,
    );
    return mapTemplateRollbackOptions(result);
  }

  async revalidateTemplateRollbackAction(
    accessCode: string,
    familyId: string,
  ): Promise<string> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!accessCode.trim()) {
      throw new Error("The maintenance access code is required.");
    }
    if (!familyId.trim()) {
      throw new Error("The template family identifier is required.");
    }
    const operation = `template:rollback-revalidate:${familyId}`;
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    const result = await checkedJson<
      WireTemplateFamilyIndex & {
        authorization_token?: string | null;
      }
    >("/api/v1/template-studio/developer/revalidate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": this.csrfToken,
        "X-Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify({
        access_code: accessCode,
        action: "template.rollback_shadow",
        resource_id: familyId,
      }),
    });
    if (!result.authorization_token?.trim()) {
      throw new Error(
        "The backend did not issue a shadow rollback authorization.",
      );
    }
    this.templateIdempotencyKeys.delete(operation);
    return result.authorization_token;
  }

  async rollbackTemplateShadow(
    familyId: string,
    targetVersionId: string,
    expectedRecordVersion: number,
    reason: string,
    developerAuthorization: string,
  ): Promise<TemplateRollbackResult> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!familyId.trim() || !targetVersionId.trim()) {
      throw new Error("The rollback target is required.");
    }
    if (!Number.isInteger(expectedRecordVersion) || expectedRecordVersion < 1) {
      throw new Error("The shadow pointer record version is invalid.");
    }
    if (!reason.trim() || !developerAuthorization.trim()) {
      throw new Error(
        "Shadow rollback requires a reason and developer revalidation.",
      );
    }
    const operation =
      `template:rollback:${familyId}:${targetVersionId}:` +
      `${expectedRecordVersion}`;
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    const result = await checkedJson<{
      applied: boolean;
      shadow_pointer: {
        family_id: string;
        version_id: string;
        record_version: number;
      };
    }>(
      `/api/v1/template-studio/families/${encodeURIComponent(familyId)}/rollback`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "X-Idempotency-Key": idempotencyKey,
          "X-DaHe-Developer-Authorization": developerAuthorization,
        },
        body: JSON.stringify({
          target_version_id: targetVersionId,
          expected_record_version: expectedRecordVersion,
          reason: reason.trim(),
        }),
      },
    );
    this.templateIdempotencyKeys.delete(operation);
    return {
      applied: result.applied,
      familyId: result.shadow_pointer.family_id,
      versionId: result.shadow_pointer.version_id,
      recordVersion: result.shadow_pointer.record_version,
    };
  }

  async runTemplateVersionAction(
    versionId: string,
    actionId: "start_shadow" | "restore_shadow",
    expectedRecordVersion: number,
    evidence?: {
      evaluationId: string;
      developerAuthorization: string;
    },
  ): Promise<TemplateVersionSnapshot> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (actionId === "restore_shadow") {
      throw new Error(
        "Template rollback requires family rollback context and is not available through this version action.",
      );
    }
    if (actionId !== "start_shadow") {
      throw new Error(
        "The requested action is not a declared template lifecycle action.",
      );
    }
    if (!Number.isInteger(expectedRecordVersion) || expectedRecordVersion < 1) {
      throw new Error("The template record version is invalid.");
    }
    if (
      !evidence?.evaluationId.trim() ||
      !evidence.developerAuthorization.trim()
    ) {
      throw new Error(
        "Shadow publication requires reviewed evaluation evidence and developer revalidation.",
      );
    }
    const operation = `template:${actionId}:${versionId}:${expectedRecordVersion}`;
    const idempotencyKey =
      this.templateIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.templateIdempotencyKeys.set(operation, idempotencyKey);
    const result = await checkedJson<WireTemplateVersionSnapshot>(
      `/api/v1/template-studio/templates/${encodeURIComponent(versionId)}/shadow`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "X-Idempotency-Key": idempotencyKey,
          "X-DaHe-Developer-Authorization":
            evidence.developerAuthorization,
        },
        body: JSON.stringify({
          expected_record_version: expectedRecordVersion,
          evaluation_id: evidence.evaluationId,
        }),
      },
    );
    this.templateIdempotencyKeys.delete(operation);
    return mapTemplateVersion(result);
  }

  subscribe(
    afterCursor: number,
    onEvent: (event: ConsoleEvent) => void,
  ): () => void {
    const events = new EventSource(
      `/api/v1/events?after=${encodeURIComponent(afterCursor)}&client_version=${encodeURIComponent(__APP_VERSION__)}`,
      { withCredentials: true },
    );
    events.onmessage = (message) => {
      const payload = JSON.parse(message.data) as {
        event_id: number;
        aggregate_id: string;
        record_version: number;
      };
      onEvent({
        eventId: payload.event_id,
        aggregateId: payload.aggregate_id,
        recordVersion: payload.record_version,
      });
    };
    return () => events.close();
  }

  async runJobAction(
    jobId: string,
    actionId: string,
    recordVersion: number,
  ): Promise<void> {
    if (!this.csrfToken) {
      throw new Error("The local session is not initialized.");
    }
    if (!jobControlActions.has(actionId)) {
      throw new Error("The requested job action is not a declared control.");
    }
    if (!Number.isInteger(recordVersion) || recordVersion < 0) {
      throw new Error("The job action record version is invalid.");
    }

    const operation = `${jobId}:${actionId}:${recordVersion}`;
    const idempotencyKey =
      this.actionIdempotencyKeys.get(operation) ?? crypto.randomUUID();
    this.actionIdempotencyKeys.set(operation, idempotencyKey);
    await checkedJson<object>(
      `/api/v1/jobs/${encodeURIComponent(jobId)}/${actionId}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": this.csrfToken,
          "X-Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({ expected_record_version: recordVersion }),
      },
    );
    this.actionIdempotencyKeys.delete(operation);
  }
}

export const browserAppServices = new BrowserAppServices();
