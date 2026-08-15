import {
  FileSpreadsheet,
  FolderOpen,
  LoaderCircle,
  Save,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type {
  AppServices,
  BusinessWorkspaceProgress,
  ContractSubjectCode,
  DailyEditableField,
  DailyItem,
  DailyItemRevisionResult,
  DailyItemsResult,
  DailyReportRecord,
  DailyReportSettings,
  JobSummary,
  PlatformBusinessReadProgress,
} from "../../app/contracts";
import { ImageViewer } from "../../components/ImageViewer";
import { ChineseDatePicker } from "../../components/ChineseDatePicker";
import { ChineseDateTimeInput } from "../../components/ChineseDateTimeInput";
import { useToast } from "../../components/ToastContext";
import {
  BusinessFilterTabs,
  BusinessOperationBar,
  BusinessProgress,
} from "../business/BusinessWorkspace";
import {
  businessDateForShanghaiClock,
  selectInitialBusinessDate,
} from "./businessDate";

declare const __APP_VERSION__: string;

type DailyView = "all" | "needsReview" | "reviewed";

function initialBusinessDate(): string {
  const current = businessDateForShanghaiClock(new Date());
  return selectInitialBusinessDate(localStorage.getItem("dahe:last-daily-business-date"), current);
}

function localInput(value: string | null, includeSeconds: boolean): string {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "";
  const parts = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: includeSeconds ? "2-digit" : undefined,
    hourCycle: "h23",
  }).formatToParts(parsed);
  const get = (type: string) => parts.find((part) => part.type === type)?.value ?? "00";
  return `${get("year")}-${get("month")}-${get("day")}T${get("hour")}:${get("minute")}${includeSeconds ? `:${get("second")}` : ""}`;
}

function apiTime(value: string, includeSeconds: boolean): string | null {
  if (!value) return null;
  return `${value}${includeSeconds && value.length === 16 ? ":00" : ""}+08:00`;
}

function dailyProgress(
  job: JobSummary | null,
  progress: PlatformBusinessReadProgress | null,
  message: string | null,
): BusinessWorkspaceProgress {
  if (message) return { phase: "incomplete", label: message, current: 0, total: 0, error: true };
  if (!job) return { phase: "idle", label: "尚未启动", current: 0, total: 0 };
  const total = progress?.total ?? job.counts.total;
  const timing = progress ? {
    startedAt: progress.startedAt,
    phaseStartedAt: progress.phaseStartedAt,
    updatedAt: progress.updatedAt,
    finishedAt: progress.finishedAt,
    elapsedSeconds: progress.elapsedSeconds,
    estimatedRemainingSeconds: progress.estimatedRemainingSeconds,
    estimateState: progress.estimateState,
    isTerminal: progress.isTerminal,
  } : {};
  if (job.jobStatus === "succeeded") {
    if (!progress) {
      return {
        phase: "finalize",
        label: `正在整理结果 0/${total}`,
        current: 0,
        total,
        ...timing,
      };
    }
    const resolved = Math.min(
      progress.recognized + progress.missingFields + progress.technicalFailed,
      total,
    );
    if (resolved < total) {
      return {
        phase: "offline_review",
        label: `正在离线审核 ${progress.visiblePrefixCount}/${total}`,
        current: progress.visiblePrefixCount,
        total,
        ...timing,
      };
    }
    return {
      phase: "complete",
      label: `已完成 ${resolved}/${total}`,
      current: resolved,
      total,
      ...timing,
    };
  }
  if (job.jobStatus === "failed") return { phase: "incomplete", label: job.progressLabel, current: job.counts.processed, total, error: true, ...timing };
  if (
    job.waitingReason === "credential_required" ||
    job.waitingReason === "login_required" ||
    job.diagnosticCode === "CF-DAILY-LOGIN-REQUIRED" ||
    job.diagnosticCode === "CF-LOGIN-INTERVENTION-REQUIRED" ||
    job.diagnosticCode === "CF-LOGIN-REQUIRED"
  ) return { phase: "login", label: "正在登录平台", current: 0, total, ...timing };
  const stage = job.currentStage ?? "";
  if (stage.includes("login")) return { phase: "login", label: "正在登录平台", current: 0, total, ...timing };
  if (progress?.label) return { phase: progress.phase, label: progress.label, current: progress.current, total, ...timing };
  if (stage.includes("acquire") || stage.includes("read")) return { phase: "read", label: `正在读取运单 ${progress?.fetched ?? 0}/${total}`, current: progress?.fetched ?? 0, total, ...timing };
  if (stage.includes("download") || stage.includes("evidence")) return { phase: "download", label: `正在下载磅单 ${Math.min((progress?.fetched ?? 0) * 2, total * 2)}/${total * 2}`, current: progress?.fetched ?? 0, total, ...timing };
  if (stage.includes("recognize")) return { phase: "recognize", label: `正在识别磅单 ${progress?.recognized ?? 0}/${total}`, current: progress?.recognized ?? 0, total, ...timing };
  if (stage.includes("final") || stage.includes("complete")) return { phase: "finalize", label: `正在整理结果 ${progress?.recognized ?? 0}/${total}`, current: progress?.recognized ?? 0, total, ...timing };
  return { phase: "read", label: job.currentStageLabel ?? job.statusLabel, current: job.counts.processed, total, ...timing };
}

function versionedEvidenceUrl(url: string): string {
  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}client_version=${encodeURIComponent(__APP_VERSION__)}`;
}

function DailyItemRow({ item, businessDate, contractSubjectCode, services, onSaved }: {
  item: DailyItem;
  businessDate: string;
  contractSubjectCode: ContractSubjectCode;
  services: AppServices;
  onSaved: (result: DailyItemRevisionResult) => void;
}) {
  const initial = useMemo(() => ({
    loading_net_tonnes: item.effectiveFields.loading_net_tonnes ?? "",
    loading_time: localInput(item.effectiveFields.loading_time, true),
    unloading_net_tonnes: item.effectiveFields.unloading_net_tonnes ?? "",
    unloading_time: localInput(item.effectiveFields.unloading_time, false),
  }), [item]);
  const [draft, setDraft] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [viewer, setViewer] = useState<{ url: string; label: string } | null>(null);
  const changed = (Object.keys(initial) as DailyEditableField[]).some((field) => draft[field] !== initial[field]);
  const requiresReviewConfirmation = item.reviewState === "needs_review";
  const invalidTime = [draft.loading_time, draft.unloading_time].some(
    (value) => value !== "" && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value),
  );
  const save = async () => {
    if (!services.saveDailyItemRevision || (!changed && !requiresReviewConfirmation)) return;
    const changes: Partial<Record<DailyEditableField, string | null>> = {};
    (Object.keys(initial) as DailyEditableField[]).forEach((field) => {
      if (draft[field] === initial[field] && !item.fieldIssues[field].hasIssue) return;
      if (field === "loading_time") changes[field] = apiTime(draft[field], true);
      else if (field === "unloading_time") changes[field] = apiTime(draft[field], false);
      else changes[field] = draft[field] || null;
    });
    setBusy(true);
    setError(null);
    try {
      onSaved(await services.saveDailyItemRevision(
        item.platformWaybillId,
        businessDate,
        item.recordVersion,
        changes,
        contractSubjectCode,
      ));
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "保存失败，请重试。");
    } finally {
      setBusy(false);
    }
  };
  const field = (name: DailyEditableField, label: string, type: "number" | "datetime", seconds = false) => (
    <div className={item.fieldIssues[name].hasIssue ? "daily-field field-error" : "daily-field"}>
      <span>{label}</span>
      {type === "number" ? (
        <input aria-label={label} type="number" step="0.01" min="0" value={draft[name]} onChange={(event) => setDraft((value) => ({ ...value, [name]: event.target.value }))} />
      ) : (
        <ChineseDateTimeInput
          value={draft[name]}
          includeSeconds={seconds}
          prefillDate={name === "loading_time" ? item.timePrefill.loadingDate : item.timePrefill.unloadingDate}
          onChange={(next) => setDraft((value) => ({ ...value, [name]: next }))}
        />
      )}
    </div>
  );
  const ticket = (side: "loading" | "unloading") => {
    const ref = side === "loading" ? item.loadingTicket : item.unloadingTicket;
    const label = side === "loading" ? "装货磅单" : "卸货磅单";
    const evidenceUrl = ref ? versionedEvidenceUrl(ref.url) : null;
    return (
      <div className="daily-ticket-block">
        <button className="daily-ticket-thumb" type="button" disabled={!evidenceUrl} onClick={() => evidenceUrl && setViewer({ url: evidenceUrl, label })}>
          {evidenceUrl ? <img loading="lazy" src={evidenceUrl} alt={label} /> : <span>未提供图片</span>}
        </button>
        <div className="daily-ticket-fields">
          {side === "loading" ? (
            <>{field("loading_net_tonnes", "出矿净重（吨）", "number")}{field("loading_time", "出矿时间", "datetime", true)}</>
          ) : (
            <>{field("unloading_net_tonnes", "收货净重（吨）", "number")}{field("unloading_time", "卸车时间", "datetime", false)}</>
          )}
        </div>
      </div>
    );
  };
  return (
    <article className="daily-item-row">
      <div className="daily-item-identity"><strong>{item.waybillNumber ?? "运单号缺失"}</strong><span>{item.vehicleNumber ?? "车牌缺失"}</span></div>
      {ticket("loading")}
      {ticket("unloading")}
      <div className="daily-item-save">
        <button className="button" type="button" disabled={(!changed && !requiresReviewConfirmation) || busy || invalidTime} onClick={() => void save()}>
          {busy ? <LoaderCircle className="spin" aria-hidden="true" size={17} /> : <Save aria-hidden="true" size={17} />}保存
        </button>
        {error ? <span className="field-error-text" role="alert">{error}</span> : null}
      </div>
      {viewer ? <ImageViewer {...viewer} onClose={() => setViewer(null)} /> : null}
    </article>
  );
}

export function DailyWorkspace({ services, jobs, productionReadOnly = false, workspaceRevision = 0, contractSubjectCode = "shanxi_guienbo" }: { services: AppServices; jobs: JobSummary[]; productionReadOnly?: boolean; workspaceRevision?: number; contractSubjectCode?: ContractSubjectCode }) {
  const { showToast } = useToast();
  const [businessDate, setBusinessDate] = useState(initialBusinessDate);
  const [view, setView] = useState<DailyView>("all");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [itemsResult, setItemsResult] = useState<DailyItemsResult | null>(null);
  const [loadingBusinessDate, setLoadingBusinessDate] = useState(true);
  const [progress, setProgress] = useState<PlatformBusinessReadProgress | null>(null);
  const [reportSettings, setReportSettings] = useState<DailyReportSettings | null>(null);
  const [report, setReport] = useState<DailyReportRecord | null>(null);
  const [startedJob, setStartedJob] = useState<JobSummary | null>(null);
  const loadGeneration = useRef(0);
  const selectedBusinessDate = useRef(businessDate);
  const activeSourceJobId = useRef<string | null>(null);
  const dailyJobs = useMemo(() => jobs.filter((job) => job.taskType === "daily" && job.scopeLabel.includes(businessDate)), [businessDate, jobs]);
  const currentJob = useMemo(() => [...dailyJobs].sort((a, b) => (b.updatedAt ?? "").localeCompare(a.updatedAt ?? ""))[0] ?? null, [dailyJobs]);
  const sourceJob = startedJob === null
    ? currentJob
    : jobs.find((job) => job.jobId === startedJob.jobId) ?? startedJob;

  useEffect(() => {
    selectedBusinessDate.current = businessDate;
    localStorage.setItem("dahe:last-daily-business-date", businessDate);
  }, [businessDate]);
  useEffect(() => {
    if (!services.loadDailyItems) return;
    const generation = ++loadGeneration.current;
    void services.loadDailyItems(businessDate, contractSubjectCode).then(
      (result) => {
        if (
          generation !== loadGeneration.current ||
          result.businessDate !== businessDate ||
          selectedBusinessDate.current !== businessDate ||
          (activeSourceJobId.current !== null && result.sourceJobId !== activeSourceJobId.current)
        ) return;
        setItemsResult(result);
        setLoadingBusinessDate(false);
        setMessage(null);
      },
      (error: unknown) => {
        if (generation !== loadGeneration.current || selectedBusinessDate.current !== businessDate) return;
        setItemsResult(null);
        setLoadingBusinessDate(false);
        setMessage(error instanceof Error ? error.message : "装卸车明细暂时无法读取。");
      },
    );
    return () => {
      if (loadGeneration.current === generation) loadGeneration.current += 1;
    };
  }, [businessDate, contractSubjectCode, currentJob?.jobStatus, currentJob?.updatedAt, services, workspaceRevision]);
  useEffect(() => {
    if (!productionReadOnly || !services.loadDailyReportSettings || !services.findDailyReport) return;
    void Promise.all([services.loadDailyReportSettings(), services.findDailyReport(businessDate, contractSubjectCode)]).then(([settings, found]) => { setReportSettings(settings); setReport(found); });
  }, [businessDate, contractSubjectCode, productionReadOnly, services]);
  useEffect(() => {
    if (!sourceJob || !services.loadPlatformBusinessReadProgress) return;
    void services.loadPlatformBusinessReadProgress(sourceJob.jobId).then((next) => {
      if (next.sourceJobId === sourceJob.jobId) setProgress(next);
    }).catch(() => undefined);
  }, [services, sourceJob, workspaceRevision]);
  const currentJobId = sourceJob?.jobId;
  useEffect(() => {
    if (!currentJobId || !services.subscribePlatformBusinessReadProgress) return;
    return services.subscribePlatformBusinessReadProgress(currentJobId, (next) => {
      if (next.sourceJobId === currentJobId) setProgress(next);
    });
  }, [currentJobId, services]);
  const start = async () => {
    if (!services.startPlatformBusinessRead) return;
    setBusy(true); setMessage(null);
    try {
      setItemsResult(null);
      setLoadingBusinessDate(true);
      setProgress(null);
      const result = await services.startPlatformBusinessRead({ businessScope: "daily", businessDate, expectedRecordVersion: 0, contractSubjectCode });
      if (result.job?.jobId) {
        activeSourceJobId.current = result.job.jobId;
        setStartedJob(result.job);
      }
    }
    catch (error) { setMessage(error instanceof Error ? error.message : "获取任务未能开始。"); }
    finally { setBusy(false); }
  };
  const runAction = async (action: "pause" | "resume" | "cancel") => {
    const actionJob = progress?.reviewJob ?? sourceJob;
    if (!actionJob?.actions[action]?.enabled) return;
    await services.runJobAction(actionJob.jobId, action, actionJob.recordVersion);
  };
  const createReport = async () => {
    if (!reportSettings || !services.createDailyReport) return;
    setBusy(true); setMessage(null);
    try {
      let effectiveSettings = reportSettings;
      if (effectiveSettings.recordVersion === 0) {
        if (!services.saveDailyReportSettings) {
          throw new Error("报表默认设置尚未初始化，请到系统设置保存一次。");
        }
        effectiveSettings = await services.saveDailyReportSettings({
          shippingMine: effectiveSettings.shippingMine,
          coalType: effectiveSettings.coalType,
          unloadingPlace: effectiveSettings.unloadingPlace,
          queryPlaceKeyword: effectiveSettings.queryPlaceKeyword,
          outputDirectory: effectiveSettings.outputDirectory,
          confirmed: true,
          expectedRecordVersion: 0,
          captureStartTime: effectiveSettings.captureStartTime,
          captureEndMode: effectiveSettings.captureEndMode,
          captureFixedEndDayOffset: effectiveSettings.captureFixedEndDayOffset,
          captureFixedEndTime: effectiveSettings.captureFixedEndTime,
        });
        setReportSettings(effectiveSettings);
      }
      const created = await services.createDailyReport(businessDate, effectiveSettings.recordVersion, contractSubjectCode);
      setReport(created);
      showToast(
        `报表已生成：候选 ${created.candidateCount} 条，纳入 ${created.rowCount} 条，窗口外 ${created.windowExcludedCount} 条，缺少时间 ${created.missingEffectiveTimeCount} 条。`,
        "success",
      );
    }
    catch (error) { setMessage(error instanceof Error ? error.message : "报表生成失败。"); }
    finally { setBusy(false); }
  };
  const openReportFolder = async () => {
    if (!report || !services.openDailyReportFolder) return;
    try { await services.openDailyReportFolder(report.reportId, report.recordVersion); }
    catch (error) { setMessage(error instanceof Error ? error.message : "无法打开报表所在文件夹。"); }
  };
  const filteredItems = (itemsResult?.items ?? []).filter((item) => {
    if (view === "needsReview") return item.reviewState === "needs_review";
    if (view === "reviewed") return item.reviewState === "reviewed";
    return true;
  });
  return (
    <section className="daily-workspace" aria-labelledby="daily-title">
      <h1 className="visually-hidden" id="daily-title">装卸车明细</h1>
      <BusinessOperationBar
        job={progress?.reviewJob ?? sourceJob}
        busy={busy}
        startDisabled={!services.startPlatformBusinessRead}
        onStart={() => void start()}
        onAction={(action) => void runAction(action)}
        pauseDisabled={!progress?.onlineCaptureComplete}
        pauseDisabledReason="下载完成后可暂停离线审核"
        moduleActions={<>
          <button className="button excel-action" type="button" disabled={busy || !reportSettings || (reportSettings.recordVersion === 0 && !services.saveDailyReportSettings) || !itemsResult?.items.length || itemsResult.counts.needsReview > 0} onClick={() => void createReport()}><FileSpreadsheet aria-hidden="true" size={17} />生成报表</button>
          {report ? <button className="button" type="button" disabled={!services.openDailyReportFolder} onClick={() => void openReportFolder()}><FolderOpen aria-hidden="true" size={17} />打开所在文件夹</button> : null}
        </>}
        trailing={<div className="business-date-control">
          <span>业务日</span>
          <ChineseDatePicker value={businessDate} onChange={(next) => {
            loadGeneration.current += 1;
            selectedBusinessDate.current = next;
            activeSourceJobId.current = null;
            setStartedJob(null);
            setProgress(null);
            setItemsResult(null);
            setLoadingBusinessDate(true);
            setMessage(null);
            setBusinessDate(next);
          }} />
        </div>}
      />
      <BusinessProgress progress={dailyProgress(sourceJob, progress, message)} />
      <div className="business-filter-line">
        <BusinessFilterTabs
          items={[
            { id: "all", label: "全部", count: itemsResult?.counts.all ?? 0 },
            { id: "needsReview", label: "待核对", count: itemsResult?.counts.needsReview ?? 0 },
            { id: "reviewed", label: "已核对", count: itemsResult?.counts.reviewed ?? 0 },
          ]}
          value={view}
          onChange={setView}
        />
        {report?.stale ? <span className="field-error-text">字段已修改，请重新生成报表</span> : null}
      </div>
      <div className="daily-item-list">
        {loadingBusinessDate ? <p className="quiet-empty" role="status" aria-label="正在读取该业务日">正在读取该业务日</p> : null}
        {filteredItems.map((item) => <DailyItemRow key={`${item.platformWaybillId}:${item.recordVersion}`} item={item} businessDate={businessDate} contractSubjectCode={contractSubjectCode} services={services} onSaved={(saved) => {
          if (
            saved.businessDate !== selectedBusinessDate.current ||
            saved.contractSubjectCode !== contractSubjectCode
          ) return;
          setItemsResult((current) => {
            if (!current || current.businessDate !== saved.businessDate) return current;
            const items = current.items.map((value) => value.platformWaybillId === saved.item.platformWaybillId ? saved.item : value);
            return {
              ...current,
              items,
              counts: saved.counts,
            };
          });
          setReport((current) => current ? { ...current, stale: true } : current);
          if (saved.item.reviewState === "reviewed") {
            showToast("已保存，已移入已核对。", "success");
          } else {
            showToast("已保存，仍有字段待核对。", "warning");
          }
        }} />)}
      </div>
      {!loadingBusinessDate && itemsResult && itemsResult.items.length === 0 ? <p className="quiet-empty">该业务日暂无已保存的装卸车明细。</p> : null}
    </section>
  );
}
