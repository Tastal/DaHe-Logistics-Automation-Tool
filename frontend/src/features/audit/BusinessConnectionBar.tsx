import { useEffect, useMemo, useState, type ReactNode } from "react";

import type {
  AppServices,
  BusinessWorkspaceProgress,
  JobSummary,
  PlatformBusinessReadProgress,
  ContractSubjectCode,
} from "../../app/contracts";
import type { SettlementLatestFetch } from "../../api/auditContracts";
import {
  BusinessOperationBar,
  BusinessProgress,
} from "../business/BusinessWorkspace";

function settlementProgress(
  latestFetch: SettlementLatestFetch | null,
  job: JobSummary | null,
  liveProgress: PlatformBusinessReadProgress | null,
  message: string | null,
): BusinessWorkspaceProgress {
  if (message) {
    return { phase: "incomplete", label: message, current: 0, total: 0, error: true };
  }
  if (liveProgress) {
    return {
      phase: liveProgress.phase,
      label: liveProgress.label,
      current: liveProgress.current,
      total: liveProgress.total,
      startedAt: liveProgress.startedAt,
      phaseStartedAt: liveProgress.phaseStartedAt,
      updatedAt: liveProgress.updatedAt,
      finishedAt: liveProgress.finishedAt,
      elapsedSeconds: liveProgress.elapsedSeconds,
      estimatedRemainingSeconds: liveProgress.estimatedRemainingSeconds,
      estimateState: liveProgress.estimateState,
      isTerminal: liveProgress.isTerminal,
      error: liveProgress.phase === "incomplete",
    };
  }
  if (!latestFetch) {
    return {
      phase: job ? "read" : "idle",
      label: job?.progressLabel || "尚未启动",
      current: job?.counts?.processed ?? 0,
      total: job?.counts?.total ?? 0,
    };
  }
  const total = latestFetch.progressTotal;
  const phaseLabels: Record<SettlementLatestFetch["phase"], string> = {
    opening_browser: "正在打开浏览器",
    waiting_login: "等待登录成丰",
    login: "正在登录平台",
    read: `正在成丰读取运单 ${latestFetch.metadataChecked}/${total}`,
    download: `正在下载磅单 ${latestFetch.imagesDownloaded}/${total * 2}`,
    recognize: latestFetch.ocrImagesCompleted === 0
      ? "成丰读取完成，已释放平台；正在核对历史结果"
      : `成丰读取完成，已释放平台；正在识别磅单 ${latestFetch.ocrImagesCompleted}/${latestFetch.ocrImagesTotal}`,
    offline_review: `正在离线审核 ${latestFetch.finalized}/${total}`,
    finalize: `正在整理结果 ${latestFetch.finalized}/${total}`,
    complete: `已完成 ${latestFetch.finalized}/${total}`,
    incomplete: latestFetch.phaseLabel,
  };
  const current = latestFetch.phase === "recognize"
    ? latestFetch.ocrImagesCompleted
    : latestFetch.phase === "offline_review"
      ? latestFetch.finalized
    : latestFetch.phase === "finalize" || latestFetch.phase === "complete"
      ? latestFetch.finalized
      : latestFetch.metadataChecked || latestFetch.progressCurrent;
  return {
    phase: latestFetch.phase,
    label: phaseLabels[latestFetch.phase],
    current,
    total: latestFetch.phase === "recognize" ? latestFetch.ocrImagesTotal : total,
    startedAt: latestFetch.startedAt,
    phaseStartedAt: latestFetch.phaseStartedAt,
    updatedAt: latestFetch.updatedAt,
    finishedAt: latestFetch.finishedAt,
    elapsedSeconds: latestFetch.elapsedSeconds,
    estimatedRemainingSeconds: latestFetch.estimatedRemainingSeconds,
    estimateState: latestFetch.estimateState,
    isTerminal: latestFetch.isTerminal,
    error: latestFetch.phase === "incomplete",
  };
}

export function BusinessConnectionBar({
  services,
  jobs = [],
  latestFetch = null,
  onChanged = () => undefined,
  onStarted = () => undefined,
  trailing = null,
  contractSubjectCode = "shanxi_guienbo",
}: {
  services: AppServices;
  jobs?: JobSummary[];
  latestFetch?: SettlementLatestFetch | null;
  onChanged?: () => void;
  onStarted?: (sourceJobId: string) => void;
  trailing?: ReactNode;
  contractSubjectCode?: ContractSubjectCode;
}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [liveProgress, setLiveProgress] = useState<PlatformBusinessReadProgress | null>(null);
  const [startedJob, setStartedJob] = useState<JobSummary | null>(null);
  const job = useMemo(
    () =>
      [...jobs]
        .filter((value) => value.taskType === "settlement_capture")
        .sort((a, b) => (b.updatedAt ?? "").localeCompare(a.updatedAt ?? ""))[0] ?? null,
    [jobs],
  );
  const sourceJob = startedJob === null
    ? job
    : jobs.find((value) => value.jobId === startedJob.jobId) ?? startedJob;
  const jobId = sourceJob?.jobId;
  const currentProgress = liveProgress?.sourceJobId === jobId ? liveProgress : null;
  useEffect(() => {
    if (!jobId || !services.subscribePlatformBusinessReadProgress) return;
    return services.subscribePlatformBusinessReadProgress(jobId, (next) => {
      if (next.sourceJobId === jobId) setLiveProgress(next);
    });
  }, [jobId, services]);
  if (!services.startPlatformBusinessRead) return null;

  const run = async (action: "pause" | "resume" | "cancel") => {
    const actionJob = currentProgress?.reviewJob ?? sourceJob;
    if (!actionJob?.actions[action]?.enabled) return;
    setMessage(null);
    try {
      await services.runJobAction(actionJob.jobId, action, actionJob.recordVersion);
      onChanged();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "操作未完成，请重试。");
    }
  };
  const start = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await services.startPlatformBusinessRead?.({
        businessScope: "settlement",
        expectedRecordVersion: 0,
        contractSubjectCode,
      });
      if (result?.job?.jobId) {
        setLiveProgress(null);
        setStartedJob(result.job);
        onStarted(result.job.jobId);
      }
      onChanged();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "获取任务未能开始。");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="business-workspace-controls" aria-label="成丰运单获取">
      <BusinessOperationBar
        job={currentProgress?.reviewJob ?? sourceJob}
        busy={busy}
        onStart={() => void start()}
        onAction={(action) => void run(action)}
        pauseDisabledReason={
          !currentProgress?.onlineCaptureComplete
            ? "下载完成后可暂停离线审核"
            : null
        }
        pauseDisabled={!currentProgress?.onlineCaptureComplete}
        collapseTrailing
        trailing={trailing}
      />
      <BusinessProgress progress={settlementProgress(latestFetch, sourceJob, currentProgress, message)} />
    </section>
  );
}
