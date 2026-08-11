import { useEffect, useMemo, useState } from "react";

import type {
  AppServices,
  BusinessWorkspaceProgress,
  JobSummary,
  PlatformBusinessReadProgress,
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
      current: job?.counts.processed ?? 0,
      total: job?.counts.total ?? 0,
    };
  }
  const total = latestFetch.progressTotal;
  const phaseLabels: Record<SettlementLatestFetch["phase"], string> = {
    login: "正在登录平台",
    read: `正在成丰读取运单 ${latestFetch.metadataChecked}/${total}`,
    download: `正在下载磅单 ${latestFetch.imagesDownloaded}/${total * 2}`,
    recognize: latestFetch.ocrImagesCompleted === 0
      ? "成丰读取完成，已释放平台；正在核对历史结果"
      : `成丰读取完成，已释放平台；正在识别磅单 ${latestFetch.ocrImagesCompleted}/${latestFetch.ocrImagesTotal}`,
    finalize: `正在整理结果 ${latestFetch.finalized}/${total}`,
    complete: `已完成 ${latestFetch.finalized}/${total}`,
    incomplete: latestFetch.phaseLabel,
  };
  const current = latestFetch.phase === "recognize"
    ? latestFetch.ocrImagesCompleted
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
}: {
  services: AppServices;
  jobs?: JobSummary[];
  latestFetch?: SettlementLatestFetch | null;
  onChanged?: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [liveProgress, setLiveProgress] = useState<PlatformBusinessReadProgress | null>(null);
  const job = useMemo(
    () =>
      [...jobs]
        .filter((value) => value.taskType === "settlement_capture")
        .sort((a, b) => (b.updatedAt ?? "").localeCompare(a.updatedAt ?? ""))[0] ?? null,
    [jobs],
  );
  const jobId = job?.jobId;
  useEffect(() => {
    if (!jobId || !services.subscribePlatformBusinessReadProgress) return;
    return services.subscribePlatformBusinessReadProgress(jobId, setLiveProgress);
  }, [jobId, services]);
  if (!services.startPlatformBusinessRead) return null;

  const run = async (action: "pause" | "resume" | "cancel") => {
    if (!job?.actions[action]?.enabled) return;
    setMessage(null);
    try {
      await services.runJobAction(job.jobId, action, job.recordVersion);
      onChanged();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "操作未完成，请重试。");
    }
  };
  const start = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await services.startPlatformBusinessRead?.({
        businessScope: "settlement",
        expectedRecordVersion: 0,
      });
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
        job={job}
        busy={busy}
        onStart={() => void start()}
        onAction={(action) => void run(action)}
      />
      <BusinessProgress progress={settlementProgress(latestFetch, job, liveProgress, message)} />
    </section>
  );
}
