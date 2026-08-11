import type { JobSummary } from "../../app/contracts";
import { ActionBar } from "./ActionBar";

interface JobPanelProps {
  job: JobSummary;
  onAction: (
    actionId: string,
    expectedRecordVersion: number | null,
  ) => void;
  onContractError: (actionId: string) => void;
  busyAction?: string | null;
}

function StatusMark({ label }: { label: string }) {
  return (
    <span className="status-mark">
      <span aria-hidden="true" className="status-symbol">
        ●
      </span>
      {label}
    </span>
  );
}

export function JobPanel({
  job,
  onAction,
  onContractError,
  busyAction = null,
}: JobPanelProps) {
  const failed = job.jobStatus === "failed";
  const progress =
    job.counts.total === 0
      ? 0
      : Math.round((job.counts.processed / job.counts.total) * 100);

  return (
    <article className="work-panel" aria-labelledby={`job-${job.jobId}`}>
      <div className="work-panel-heading">
        <div>
          <div className="mode-row">
            <span className="mode-badge">
              {job.jobKind === "test_fixture" ? "受保护演练" : "影子测试"}
            </span>
            <StatusMark
              label={failed ? "本任务处理失败" : job.statusLabel}
            />
          </div>
          <h2 id={`job-${job.jobId}`}>{job.displayName}</h2>
          {job.taskType === "loading_probe" ? (
            <p className="probe-boundary">
              调度演练，不是正式装卸车业务
            </p>
          ) : null}
        </div>
        <ActionBar
          actions={job.actions}
          jobName={job.displayName}
          scopeLabel={job.scopeLabel}
          onAction={onAction}
          onContractError={onContractError}
          busyAction={busyAction}
        />
      </div>

      <dl className="job-facts">
        <div>
          <dt>业务范围</dt>
          <dd>{job.scopeLabel}</dd>
        </div>
        <div>
          <dt>当前进度 / 同时进行</dt>
          <dd>
            {job.currentStageLabel ?? "尚未进入处理阶段"}
            {job.activeStageLabels.filter(
              (label) => label !== job.currentStageLabel,
            ).length > 0
              ? `；同时：${job.activeStageLabels
                  .filter((label) => label !== job.currentStageLabel)
                  .join("、")}`
              : null}
          </dd>
        </div>
        <div>
          <dt>当前自动处理</dt>
          <dd>
            {job.activeResources.length > 0
              ? job.activeResources
                  .map((resource) => resource.displayName)
                  .join("、")
              : "当前未占用自动处理资源"}
          </dd>
        </div>
        {job.waitingReason ? (
          <div>
            <dt>等待原因</dt>
            <dd>{job.waitingReason}</dd>
          </div>
        ) : null}
        <div>
          <dt>最近保存进度</dt>
          <dd>{job.latestCheckpointLabel ?? "尚无已保存检查点"}</dd>
        </div>
      </dl>

      {failed ? (
        <div className="job-failure" role="alert">
          <strong>数据已保护，未完成的处理已经停止。</strong>
          <p>请复制诊断编号并联系开发者。</p>
          <p className="diagnostic-code">
            诊断编号：{job.diagnosticCode ?? "暂未提供"}
          </p>
        </div>
      ) : (
        <>
          <div
            className="progress-track"
            role="progressbar"
            aria-label="任务进度"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress}
          >
            <span style={{ width: `${progress}%` }} />
          </div>
          <p className="progress-copy">{job.progressLabel}</p>
        </>
      )}

      <dl className="count-strip">
        <div>
          <dt>已处理</dt>
          <dd>{job.counts.processed}</dd>
        </div>
        <div>
          <dt>仍需处理</dt>
          <dd>{job.counts.remaining}</dd>
        </div>
        <div>
          <dt>需要人员处理</dt>
          <dd>{job.counts.waitingUser}</dd>
        </div>
        <div>
          <dt>处理失败</dt>
          <dd>{job.counts.failed}</dd>
        </div>
      </dl>
    </article>
  );
}
