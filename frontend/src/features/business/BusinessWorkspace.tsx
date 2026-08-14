import { LoaderCircle, Pause, Play, RefreshCw, X } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";

import type {
  BusinessWorkspaceProgress,
  JobSummary,
} from "../../app/contracts";
import { ResponsiveSecondaryActions } from "../../components/ResponsiveSecondaryActions";

export function BusinessOperationBar({
  job,
  busy = false,
  startDisabled = false,
  onStart,
  onAction,
  moduleActions,
  trailing,
  collapseTrailing = false,
  pauseDisabledReason,
  pauseDisabled = false,
}: {
  job: JobSummary | null;
  busy?: boolean;
  startDisabled?: boolean;
  onStart: () => void;
  onAction: (action: "pause" | "resume" | "cancel") => void;
  moduleActions?: ReactNode;
  trailing?: ReactNode;
  collapseTrailing?: boolean;
  pauseDisabledReason?: string | null;
  pauseDisabled?: boolean;
}) {
  const resumable = Boolean(job?.actions.resume?.visible && job.actions.resume.enabled);
  const pausable = Boolean(
    !pauseDisabled && job?.actions.pause?.visible && job.actions.pause.enabled
  );
  const toggleAction = resumable ? "resume" : "pause";
  const toggleEnabled = resumable || pausable;
  const cancelEnabled = Boolean(job?.actions.cancel?.visible && job.actions.cancel.enabled);

  return (
    <div className="business-operation-bar">
      <button
        className="button primary"
        type="button"
        disabled={busy || startDisabled}
        onClick={onStart}
      >
        {busy ? (
          <LoaderCircle className="spin" aria-hidden="true" size={17} />
        ) : (
          <RefreshCw aria-hidden="true" size={17} />
        )}
        启动
      </button>
      <ResponsiveSecondaryActions>
        <button
          className="button"
          type="button"
          disabled={!toggleEnabled}
          title={!toggleEnabled ? pauseDisabledReason ?? undefined : undefined}
          onClick={() => onAction(toggleAction)}
        >
          {resumable ? (
            <Play aria-hidden="true" size={17} />
          ) : (
            <Pause aria-hidden="true" size={17} />
          )}
          {resumable ? "继续" : "暂停"}
        </button>
        <button
          className="button"
          type="button"
          disabled={!cancelEnabled}
          onClick={() => onAction("cancel")}
        >
          <X aria-hidden="true" size={17} />
          取消
        </button>
        {moduleActions}
        {collapseTrailing && trailing ? (
          <div className="business-operation-trailing">{trailing}</div>
        ) : null}
      </ResponsiveSecondaryActions>
      {!collapseTrailing && trailing ? (
        <div className="business-operation-trailing">{trailing}</div>
      ) : null}
    </div>
  );
}

export function BusinessProgress({
  progress,
}: {
  progress: BusinessWorkspaceProgress;
}) {
  const [clock, setClock] = useState(() => Date.now());
  const isTerminal = progress.isTerminal
    ?? (progress.phase === "complete" || progress.phase === "incomplete");
  useEffect(() => {
    if (progress.phase === "idle" || isTerminal) return;
    const timer = window.setInterval(() => setClock(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [isTerminal, progress.phase]);
  const timing = useMemo(() => {
    const baseElapsed = Math.max(0, progress.elapsedSeconds ?? 0);
    const updated = progress.updatedAt ? Date.parse(progress.updatedAt) : Number.NaN;
    const drift = Number.isFinite(updated) && !isTerminal
      ? Math.max(0, Math.floor((clock - updated) / 1_000))
      : 0;
    const elapsed = baseElapsed + drift;
    const remainingBase = progress.estimatedRemainingSeconds;
    const remaining = typeof remainingBase === "number"
      ? Math.max(0, remainingBase - drift)
      : null;
    return { elapsed, remaining };
  }, [clock, isTerminal, progress.elapsedSeconds, progress.estimatedRemainingSeconds, progress.updatedAt]);
  const formatDuration = (seconds: number) => {
    const whole = Math.max(0, Math.floor(seconds));
    const hours = Math.floor(whole / 3_600);
    const minutes = Math.floor((whole % 3_600) / 60);
    const rest = whole % 60;
    return hours > 0
      ? `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(rest).padStart(2, "0")}`
      : `${String(minutes).padStart(2, "0")}:${String(rest).padStart(2, "0")}`;
  };
  const visibleLabel = progress.label?.trim() ?? "";
  const timingLabel = progress.phase === "idle" || !visibleLabel
    ? ""
    : progress.estimateState === "estimated" && timing.remaining !== null
      ? ` · 已用时 ${formatDuration(timing.elapsed)} · 预计还需 ${formatDuration(timing.remaining)}`
      : isTerminal
        ? ` · 用时 ${formatDuration(timing.elapsed)}`
        : ` · 已用时 ${formatDuration(timing.elapsed)} · 正在估算`;
  const percentage = progress.total > 0
    ? Math.min(100, Math.max(0, (progress.current / progress.total) * 100))
    : progress.phase === "complete"
      ? 100
      : 0;
  return (
    <div
      className={`workspace-progress${progress.error ? " is-error" : ""}`}
      role="status"
      aria-label={visibleLabel}
    >
      <div className="workspace-progress-label">{visibleLabel}{timingLabel}</div>
      <div
        className="workspace-progress-track"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={progress.total || 1}
        aria-valuenow={Math.min(progress.current, progress.total || 1)}
      >
        <div style={{ width: `${percentage}%` }} />
      </div>
    </div>
  );
}

export function BusinessFilterTabs<T extends string>({
  items,
  value,
  onChange,
}: {
  items: ReadonlyArray<{ id: T; label: string; count: number }>;
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div className="business-filter-tabs" role="group" aria-label="筛选业务结果">
      {items.map((item) => (
        <button
          key={item.id}
          className="filter-button"
          type="button"
          aria-pressed={value === item.id}
          onClick={() => onChange(item.id)}
        >
          {item.label} <strong>{item.count}</strong>
        </button>
      ))}
    </div>
  );
}
