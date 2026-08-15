import type {
  StagedTemplateReference,
  TemplateDraft,
  TemplateFamilyIndex,
  TemplateRollbackOptions,
  TemplateRollbackResult,
  TemplateRole,
  TemplateVersionSnapshot,
} from "../api/templateContracts";
import type {
  LockedSetReviewIndex,
  LockedSetReviewItem,
  SaveLockedSetReviewInput,
  SaveLockedSetReviewResult,
} from "../api/lockedSetReviewContracts";
import type {
  ConfirmLoop9ReviewInput,
  ExportLoop9ReviewResult,
  Loop9ReviewIndex,
  Loop9ReviewItem,
  SaveLoop9ReviewInput,
  SaveLoop9ReviewResult,
} from "../api/loop9ReviewContracts";
import type {
  AuditDecisionInput,
  AuditReviewItem,
  AuditRevocationInput,
  AuditWorkspaceResult,
  AuditWorkspaceView,
  SettlementWorkspaceResult,
  DiagnosticsSnapshot,
  RuntimeLogEvent,
  RuntimeLogPage,
  RuntimeLogQuery,
} from "../api/auditContracts";

export interface ServerAction {
  visible: boolean;
  enabled: boolean;
  reason: string | null;
  label: string;
  expectedRecordVersion: number | null;
}

export interface JobCounts {
  total: number;
  processed: number;
  remaining: number;
  waitingUser: number;
  failed: number;
}

export interface JobSummary {
  jobId: string;
  taskType: string;
  jobKind: "business" | "test_fixture";
  displayName: string;
  scopeLabel: string;
  runMode: "shadow" | "operational";
  jobStatus: string;
  statusLabel: string;
  currentStage: string | null;
  currentStageLabel: string | null;
  activeStageLabels: string[];
  activeResources: JobResourceUsage[];
  waitingReason: string | null;
  latestCheckpointLabel: string | null;
  progressLabel: string;
  diagnosticCode: string | null;
  recordVersion: number;
  counts: JobCounts;
  actions: Record<string, ServerAction>;
  createdAt?: string;
  updatedAt?: string;
}

export interface JobResourceUsage {
  resourceId: string;
  displayName: string;
}

export interface JobItem {
  workItemId: string;
  recordVersion: number;
  waybillNumber: string;
  vehicleNumber: string;
  status: string;
  currentStage: string;
  businessOutcome: string | null;
  isTerminalOutcome: boolean;
  platformLoadingNet: string | null;
  platformUnloadingNet: string | null;
  ticketLoadingNet: string | null;
  ticketUnloadingNet: string | null;
  decision: string | null;
  reviewReason: string | null;
}

export interface ResourceSummary {
  resourceId: string;
  displayName: string;
  statusLabel: string;
  capacity: number;
  inUse: number;
  waitingJobs: number;
  holderLabel: string | null;
}

export interface ConsoleSnapshot {
  eventCursor: number;
  jobs: JobSummary[];
  resources: ResourceSummary[];
  startActions: Record<string, ServerAction>;
}

export interface BootstrapResult {
  applicationVersion: string;
  csrfToken: string;
  lockedSetReviewEnabled: boolean;
  loop9ReviewEnabled?: boolean;
  productionReadOnly?: boolean;
}

export interface UpdateStatus {
  state: "idle" | "checking" | "available" | "up_to_date" | "installing" | "failed" | "unavailable";
  currentVersion: string;
  availableVersion: string | null;
  updateAvailable: boolean;
  checkedAt: string | null;
  errorCode: string | null;
}

export interface EnvironmentSnapshot {
  application: {
    version: string;
    commit: string;
    resourceSha256: string;
  };
  windows: {
    release: string;
    version: string;
    architecture: string;
  };
  database: {
    schemaRevision: string;
    integrity: string;
  };
  runtime: {
    edgeWorker: string | null;
    ocrCpu: string | null;
  };
  resources: {
    diskFreeBytes: number;
    cpuCount: number | null;
    gpu: { available: boolean; deviceCount: number; devices?: string[] };
  };
}

export interface ProductionReadOnlyStatus {
  status:
    | "operational_read_only_with_guard"
    | "operational_read_only_accepted"
    | "operational_read_only_active";
  targetCount: number;
  registeredCount: number;
  reviewedCount: number;
  falseNormalCount: number;
  guardActive: boolean;
}

export interface DailyReportSettings {
  shippingMine: string;
  coalType: string;
  unloadingPlace: string;
  queryPlaceKeyword: string;
  outputDirectory: string;
  confirmed: boolean;
  recordVersion: number;
  captureStartTime: string;
  captureEndMode: "system_current_time" | "fixed_time";
  captureFixedEndDayOffset: 0 | 1;
  captureFixedEndTime: string;
  captureRangeCoversReportWindow: boolean;
}

export interface DailyReportRecord {
  contractSubjectCode: ContractSubjectCode;
  reportId: string;
  businessDate: string;
  status: "pending_confirmation" | "confirmed";
  fileName: string;
  fileSha256: string;
  dataSnapshotSha256: string;
  outputDirectory: string;
  rowCount: number;
  candidateCount: number;
  windowExcludedCount: number;
  missingEffectiveTimeCount: number;
  loadingNetTotal: string;
  recordVersion: number;
  createdAt: string;
  confirmedAt: string | null;
  stale: boolean;
}

export type DailyEditableField =
  | "loading_net_tonnes"
  | "loading_time"
  | "unloading_net_tonnes"
  | "unloading_time";

export interface DailyTicketReference {
  sha256: string;
  url: string;
}

export interface DailyItem {
  platformWaybillId: string;
  waybillNumber: string | null;
  vehicleNumber: string | null;
  loadingTicket: DailyTicketReference | null;
  unloadingTicket: DailyTicketReference | null;
  machineFields: Record<DailyEditableField, string | null>;
  effectiveFields: Record<DailyEditableField, string | null>;
  fieldSources: Record<DailyEditableField, "machine" | "manual">;
  fieldIssues: Record<DailyEditableField, { hasIssue: boolean; message: string | null }>;
  reviewState: "reviewed" | "needs_review";
  materializedAt: string;
  timePrefill: { loadingDate: string; unloadingDate: string };
  recordVersion: number;
  updatedAt: string;
}

export interface DailyItemsResult {
  businessDate: string;
  contractSubjectCode: ContractSubjectCode;
  items: DailyItem[];
  counts: { all: number; needsReview: number; reviewed: number };
  sourceJobId: string | null;
  sourceRecordVersion: number;
  captureMode: "batch_v1" | "whole_run_v1";
  visiblePrefixCount: number;
  onlineCaptureComplete: boolean;
}

export interface DailyItemRevisionResult {
  businessDate: string;
  contractSubjectCode: ContractSubjectCode;
  item: DailyItem;
  counts: { all: number; needsReview: number; reviewed: number };
}

export type PerformancePreset = "responsive" | "balanced" | "speed";
export interface PerformanceSettings {
  preset: PerformancePreset;
  detailConcurrency: number;
  imageConcurrency: number;
  networkBatchSize: 20 | 50 | 100;
  cpuOcrThreads: number;
  gpuIdleMinutes: number;
  keepGpuReady: boolean;
  recordVersion: number;
}

export interface SaveDailyReportSettingsInput {
  shippingMine: string;
  coalType: string;
  unloadingPlace: string;
  queryPlaceKeyword: string;
  outputDirectory: string;
  confirmed: boolean;
  expectedRecordVersion: number;
  captureStartTime: string;
  captureEndMode: "system_current_time" | "fixed_time";
  captureFixedEndDayOffset: 0 | 1;
  captureFixedEndTime: string;
}

export interface PlatformAction {
  enabled: boolean;
  reason: string | null;
}

export interface PlatformAccessWindow {
  accessWindowId: string;
  purpose: "contract_discovery" | "formal_locked_set" | "production_shadow";
  expiresAt: string;
  consumedAt: string | null;
  expired: boolean;
  recordVersion: number;
}

export interface BusinessConnectionSession {
  businessSessionId: string;
  status: "active" | "closed";
  expiresAt: string;
  expired: boolean;
  recordVersion: number;
}

export type ContractSubjectCode =
  | "shanxi_guienbo"
  | "shanghai_jinyisheng";

export interface PlatformSession {
  enabled: boolean;
  runMode: "shadow" | "operational";
  connectionMode: "operational_compat" | "strict_shadow";
  connectionModeLabel: string;
  connectionModeRecordVersion: number;
  browserLifecycle: "stopped" | "ready";
  browserControlMode: "idle" | "automated" | "human_login" | "human_handoff";
  recordVersion: number;
  runtimeAvailable: boolean;
  runtimeRunning: boolean;
  selectedBrowser: string | null;
  discoveryCapturing: boolean;
  visibleBrowserRunning: boolean;
  controlMode: "idle" | "automated" | "human_login" | "human_handoff";
  humanHandoffReady: boolean;
  loginState: "ready" | "login_required" | "unavailable";
  activeJobId: string | null;
  warmSessionReusable: boolean;
  connectionStatus: {
    code: "browser_closed" | "opening" | "login_required" | "ready" | "reading" | "downloading" | "error";
    label: "浏览器关闭" | "正在打开" | "等待登录" | "连接就绪" | "正在读取" | "正在下载" | "连接异常";
  };
  contractSubject: {
    availableSubjects: Array<{
      code: ContractSubjectCode;
      label: string;
    }>;
    currentSubjectCode: ContractSubjectCode;
    recordVersion: number;
    updatedAt: string;
  };
  contractCandidateSelected: boolean;
  contractSelectionSha256: string | null;
  accessWindow: PlatformAccessWindow | null;
  businessSession: BusinessConnectionSession | null;
  waitingReason: string | null;
  availableActions: Record<
    | "create_access_window"
    | "switch_connection_mode"
    | "start_business_session"
    | "begin_business_read"
    | "close_business_session"
    | "start_operational_capture"
    | "start_human_login"
    | "return_human_login"
    | "start_discovery_capture"
    | "stop_discovery_capture"
    | "validate_read_contract"
    | "close_session",
    PlatformAction
  >;
}

export interface PlatformDiscoveryEvidence {
  evidenceId: string;
  canonicalSha256: string;
  observationCount: number;
}

export interface PlatformContractValidationEvidence {
  evidenceId: string;
  canonicalSha256: string;
  selectionSha256: string;
  listItemCount: number;
  detailAttemptCount: number;
  imageCount: number;
}

export interface CreatePlatformAccessWindowInput {
  purpose: "contract_discovery" | "formal_locked_set";
  legacyIdleConfirmed: boolean;
  noSettlementOrPaymentConfirmed: boolean;
  sameAccountSessionRiskAccepted: boolean;
}

export interface StartOperationalCaptureInput {
  legacyIdleConfirmed: boolean;
  noSettlementOrPaymentConfirmed: boolean;
  sameAccountSessionRiskAccepted: boolean;
}

export interface StartOperationalCaptureResult {
  created: boolean;
  job: JobSummary;
  accessWindow: PlatformAccessWindow;
}

export interface StartBusinessConnectionSessionResult {
  created: boolean;
  businessSession: BusinessConnectionSession;
  accessWindow: PlatformAccessWindow;
}

export interface BeginBusinessConnectionReadResult {
  created: boolean;
  businessSession: BusinessConnectionSession;
  job: JobSummary;
}

export interface PlatformCredentialStatus {
  configured: boolean;
  maskedUsername: string | null;
  recordVersion: number;
}

export interface SavePlatformCredentialInput {
  username: string;
  password: string;
  expectedRecordVersion: number;
}

export interface StartPlatformBusinessReadInput {
  businessScope: "settlement" | "daily";
  businessDate?: string;
  expectedRecordVersion: number;
  contractSubjectCode: ContractSubjectCode;
}

export interface StartPlatformBusinessReadResult {
  created: boolean;
  attached: boolean;
  job: JobSummary;
}

export interface PlatformBusinessReadProgress {
  jobId: string;
  phase: BusinessWorkspaceProgress["phase"];
  label: string;
  current: number;
  total: number;
  fetched: number;
  recognized: number;
  missingFields: number;
  technicalFailed: number;
  committedBatches: number;
  startedAt: string | null;
  phaseStartedAt: string | null;
  updatedAt: string | null;
  finishedAt: string | null;
  elapsedSeconds: number;
  estimatedRemainingSeconds: number | null;
  estimateState: "estimating" | "estimated" | "complete" | "unavailable";
  isTerminal: boolean;
  sourceJobId: string;
  sourceRecordVersion: number;
  captureMode: "batch_v1" | "whole_run_v1";
  visiblePrefixCount: number;
  onlineCaptureComplete: boolean;
  reviewJob: JobSummary | null;
}

export interface BusinessWorkspaceProgress {
  phase:
    | "idle"
    | "opening_browser"
    | "waiting_login"
    | "login"
    | "read"
    | "download"
    | "offline_review"
    | "recognize"
    | "finalize"
    | "complete"
    | "incomplete";
  label: string;
  current: number;
  total: number;
  startedAt?: string | null;
  phaseStartedAt?: string | null;
  updatedAt?: string | null;
  finishedAt?: string | null;
  elapsedSeconds?: number;
  estimatedRemainingSeconds?: number | null;
  estimateState?: "estimating" | "estimated" | "complete" | "unavailable";
  isTerminal?: boolean;
  error?: boolean;
}

export interface CreateJobResult {
  created: boolean;
  job: JobSummary;
}

export interface ConsoleEvent {
  eventId: number;
  aggregateId: string;
  recordVersion: number;
}

export interface AppServices {
  bootstrap(): Promise<BootstrapResult>;
  loadReadinessVersion?(): Promise<string>;
  loadSnapshot(): Promise<ConsoleSnapshot>;
  loadResources(): Promise<ResourceSummary[]>;
  loadJobItems(jobId: string): Promise<JobItem[]>;
  createAuditJob(expectedRecordVersion: number): Promise<CreateJobResult>;
  createFixtureJob(
    fixtureId: Loop3FixtureId,
    expectedRecordVersion: number,
  ): Promise<CreateJobResult>;
  subscribe(
    afterCursor: number,
    onEvent: (event: ConsoleEvent) => void,
  ): () => void;
  runJobAction(
    jobId: string,
    actionId: string,
    recordVersion: number,
  ): Promise<void>;
  loadAuditReviewItems?(): Promise<AuditReviewItem[]>;
  loadAuditWorkspaceItems?(
    view: AuditWorkspaceView,
    jobId?: string,
  ): Promise<AuditWorkspaceResult>;
  loadSettlementWorkspace?(
    view: AuditWorkspaceView,
    contractSubjectCode?: ContractSubjectCode,
  ): Promise<SettlementWorkspaceResult>;
  loadReadySettlementWaybillNumbers?(
    contractSubjectCode?: ContractSubjectCode,
  ): Promise<string[]>;
  prepareSettlementFilterHandoff?(
    contractSubjectCode?: ContractSubjectCode,
  ): Promise<{
    count: number;
    matchedCount: number;
    missingCount: number;
    message: string;
  }>;
  loadProductionReadOnlyStatus?(): Promise<ProductionReadOnlyStatus>;
  loadAuditItem?(workItemId: string): Promise<AuditReviewItem>;
  confirmAuditProblem?(
    workItemId: string,
    input: AuditDecisionInput,
  ): Promise<AuditReviewItem>;
  dismissAuditProblem?(
    workItemId: string,
    input: AuditDecisionInput,
  ): Promise<AuditReviewItem>;
  revokeAuditAction?(
    workItemId: string,
    actionId: string,
    input: AuditRevocationInput,
  ): Promise<AuditReviewItem>;
  loadWaybillHistory?(
    query?: string,
    businessOutcome?: string,
    contractSubjectCode?: ContractSubjectCode,
  ): Promise<AuditReviewItem[]>;
  loadDiagnostics?(): Promise<DiagnosticsSnapshot>;
  loadPlatformSession?(): Promise<PlatformSession>;
  selectContractSubject?(
    subjectCode: ContractSubjectCode,
    expectedRecordVersion: number,
  ): Promise<PlatformSession["contractSubject"]>;
  createPlatformAccessWindow?(
    input: CreatePlatformAccessWindowInput,
  ): Promise<PlatformAccessWindow>;
  switchPlatformConnectionMode?(
    mode: "operational_compat" | "strict_shadow",
    expectedRecordVersion: number,
  ): Promise<PlatformSession>;
  startOperationalCapture?(
    input: StartOperationalCaptureInput,
  ): Promise<StartOperationalCaptureResult>;
  startBusinessConnectionSession?(
    input: StartOperationalCaptureInput,
  ): Promise<StartBusinessConnectionSessionResult>;
  beginBusinessConnectionRead?(
    businessSessionId: string,
    expectedRecordVersion: number,
    expectedBrowserRecordVersion: number,
  ): Promise<BeginBusinessConnectionReadResult>;
  closeBusinessConnectionSession?(
    businessSessionId: string,
    expectedRecordVersion: number,
    expectedBrowserRecordVersion: number,
  ): Promise<BusinessConnectionSession>;
  loadPlatformCredentials?(): Promise<PlatformCredentialStatus>;
  savePlatformCredentials?(
    input: SavePlatformCredentialInput,
  ): Promise<PlatformCredentialStatus>;
  deletePlatformCredentials?(
    expectedRecordVersion: number,
  ): Promise<PlatformCredentialStatus>;
  startPlatformBusinessRead?(
    input: StartPlatformBusinessReadInput,
  ): Promise<StartPlatformBusinessReadResult>;
  loadPlatformBusinessReadProgress?(
    jobId: string,
  ): Promise<PlatformBusinessReadProgress>;
  subscribePlatformBusinessReadProgress?(
    jobId: string,
    onProgress: (progress: PlatformBusinessReadProgress) => void,
  ): () => void;
  loadDailyReportSettings?(): Promise<DailyReportSettings>;
  saveDailyReportSettings?(
    input: SaveDailyReportSettingsInput,
  ): Promise<DailyReportSettings>;
  findDailyReport?(businessDate: string, contractSubjectCode?: ContractSubjectCode): Promise<DailyReportRecord | null>;
  createDailyReport?(
    businessDate: string,
    expectedSettingsVersion: number,
    contractSubjectCode?: ContractSubjectCode,
  ): Promise<DailyReportRecord>;
  confirmDailyReport?(
    reportId: string,
    expectedRecordVersion: number,
  ): Promise<DailyReportRecord>;
  saveDailyReportNewCopy?(
    reportId: string,
    expectedRecordVersion: number,
  ): Promise<DailyReportRecord>;
  openDailyReportFolder?(
    reportId: string,
    expectedRecordVersion: number,
  ): Promise<void>;
  loadDailyItems?(
    businessDate: string,
    contractSubjectCode?: ContractSubjectCode,
  ): Promise<DailyItemsResult>;
  saveDailyItemRevision?(
    platformWaybillId: string,
    businessDate: string,
    expectedRecordVersion: number,
    changes: Partial<Record<DailyEditableField, string | null>>,
    contractSubjectCode?: ContractSubjectCode,
  ): Promise<DailyItemRevisionResult>;
  loadPerformanceSettings?(): Promise<PerformanceSettings>;
  savePerformanceSettings?(settings: PerformanceSettings): Promise<PerformanceSettings>;
  startPlatformHumanLogin?(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformSession>;
  returnPlatformHumanLogin?(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformSession>;
  startPlatformDiscoveryCapture?(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformSession>;
  stopPlatformDiscoveryCapture?(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformDiscoveryEvidence>;
  validatePlatformReadContract?(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformContractValidationEvidence>;
  closePlatformSession?(
    accessWindowId: string,
    expectedRecordVersion: number,
  ): Promise<PlatformSession>;
  loadRuntimeLogs?(query?: RuntimeLogQuery): Promise<RuntimeLogPage>;
  subscribeRuntimeLogs?(
    afterCursor: string | null,
    onEvent: (event: RuntimeLogEvent) => void,
  ): () => void;
  shutdownApplication?(): Promise<void>;
  loadUpdateStatus?(): Promise<UpdateStatus>;
  checkForUpdates?(): Promise<UpdateStatus>;
  importUpdatePackage?(manifest: File, application: File): Promise<UpdateStatus>;
  installUpdate?(): Promise<UpdateStatus>;
  recordBreadcrumb?(page: "settlement" | "daily" | "history" | "system"): Promise<void>;
  loadEnvironmentSnapshot?(): Promise<EnvironmentSnapshot>;
  exportDiagnosticBundle?(): Promise<void>;
  openDiagnosticsDirectory?(): Promise<void>;
  loadLockedSetReview?(): Promise<LockedSetReviewIndex>;
  loadLockedSetReviewItem?(sampleId: string): Promise<LockedSetReviewItem>;
  saveLockedSetReviewItem?(
    sampleId: string,
    input: SaveLockedSetReviewInput,
  ): Promise<SaveLockedSetReviewResult>;
  loadLoop9Review?(): Promise<Loop9ReviewIndex>;
  loadLoop9ReviewItem?(
    itemIdentitySha256: string,
  ): Promise<Loop9ReviewItem>;
  saveLoop9ReviewDraft?(
    itemIdentitySha256: string,
    input: SaveLoop9ReviewInput,
  ): Promise<SaveLoop9ReviewResult>;
  confirmLoop9ReviewItem?(
    itemIdentitySha256: string,
    input: ConfirmLoop9ReviewInput,
  ): Promise<SaveLoop9ReviewResult>;
  exportLoop9Review?(
    expectedReviewRevisionSha256: string,
  ): Promise<ExportLoop9ReviewResult>;
  loadTemplateFamilies?(): Promise<TemplateFamilyIndex>;
  loadTemplateFamily?(familyId: string): Promise<TemplateVersionSnapshot>;
  unlockTemplateMaintenance?(accessCode: string): Promise<TemplateFamilyIndex>;
  uploadTemplateReference?(file: File): Promise<StagedTemplateReference>;
  abandonTemplateReference?(
    stagedReferenceId: string,
    expectedRecordVersion: number,
  ): Promise<void>;
  createTemplateFromStagedReference?(
    stagedReferenceId: string,
    expectedRecordVersion: number,
    familyName: string,
    role: TemplateRole,
    draft: TemplateDraft,
  ): Promise<{ created: boolean; template: TemplateVersionSnapshot }>;
  saveTemplateDraft?(
    versionId: string,
    expectedRecordVersion: number,
    draft: TemplateDraft,
  ): Promise<TemplateVersionSnapshot>;
  runTemplateDevelopmentCheck?(
    versionId: string,
    expectedRecordVersion: number,
    evaluationId?: string,
  ): Promise<TemplateVersionSnapshot>;
  revalidateTemplateShadowAction?(
    accessCode: string,
    versionId: string,
  ): Promise<string>;
  loadTemplateFamilyVersions?(
    familyId: string,
  ): Promise<TemplateRollbackOptions>;
  revalidateTemplateRollbackAction?(
    accessCode: string,
    familyId: string,
  ): Promise<string>;
  rollbackTemplateShadow?(
    familyId: string,
    targetVersionId: string,
    expectedRecordVersion: number,
    reason: string,
    developerAuthorization: string,
  ): Promise<TemplateRollbackResult>;
  runTemplateVersionAction?(
    versionId: string,
    actionId: "start_shadow" | "restore_shadow",
    expectedRecordVersion: number,
    evidence?: {
      evaluationId: string;
      developerAuthorization: string;
    },
  ): Promise<TemplateVersionSnapshot>;
}

export type Loop3FixtureId =
  | "audit-batch-long-001"
  | "audit-batch-short-002"
  | "loading-probe-001";

export class ApiVersionMismatchError extends Error {
  constructor() {
    super("The operator console and backend versions differ.");
    this.name = "ApiVersionMismatchError";
  }
}

export class TemplateMaintenanceRequiredError extends Error {
  constructor() {
    super("Template maintenance authorization is required.");
    this.name = "TemplateMaintenanceRequiredError";
  }
}
