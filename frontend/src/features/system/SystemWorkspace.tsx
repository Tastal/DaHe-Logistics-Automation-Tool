import { type ReactNode, useEffect, useState } from "react";
import {
  Activity,
  Archive,
  Bug,
  Database,
  Download,
  FileCog,
  FolderOpen,
  Copy,
  SlidersHorizontal,
} from "lucide-react";

import type {
  AppServices,
  JobSummary,
  ResourceSummary,
} from "../../app/contracts";
import type { DiagnosticsSnapshot } from "../../api/auditContracts";
import { CredentialSettings } from "./CredentialSettings";
import { DailyReportSettingsPanel } from "./DailyReportSettings";
import { PerformanceSettingsPanel } from "./PerformanceSettings";
import { PlatformSessionPanel } from "./PlatformSessionPanel";
import { RuntimeLogTerminal } from "./RuntimeLogTerminal";

export type SystemSection =
  | "status"
  | "diagnostics"
  | "templates"
  | "settings"
  | "data";

const sections: Array<{
  id: SystemSection;
  label: string;
  icon: typeof Activity;
}> = [
  { id: "status", label: "运行状态", icon: Activity },
  { id: "diagnostics", label: "运行诊断", icon: Bug },
  { id: "templates", label: "识别模板", icon: FileCog },
  { id: "settings", label: "参数设置", icon: SlidersHorizontal },
  { id: "data", label: "数据管理", icon: Database },
];

function EmptySystemSection({
  icon: Icon,
  title,
}: {
  icon: typeof Activity;
  title: string;
}) {
  return (
    <div className="detail-empty">
      <Icon aria-hidden="true" size={28} />
      <h2 className="visually-hidden">{title}</h2>
      <p>当前阶段没有可安全使用的设置。</p>
    </div>
  );
}

function JobStatusRow({ job }: { job: JobSummary }) {
  const time = (value: string | undefined) => value
    ? new Intl.DateTimeFormat("zh-CN", { timeZone: "Asia/Shanghai", hour: "2-digit", minute: "2-digit", month: "2-digit", day: "2-digit", hourCycle: "h23" }).format(new Date(value))
    : "时间未知";
  return (
    <li>
      <div>
        <strong>{job.displayName}</strong>
        <span>
          {job.currentStageLabel ?? job.statusLabel}
          {job.waitingReason ? ` · ${job.waitingReason}` : ""}
        </span>
        {job.latestCheckpointLabel ? (
          <small>最近检查点：{job.latestCheckpointLabel}</small>
        ) : null}
        <small>创建 {time(job.createdAt)} · 最近更新 {time(job.updatedAt)}</small>
      </div>
      <div className="status-row-trailing">
        <span>{job.statusLabel}</span>
        <small>
          {job.activeResources.length > 0
            ? job.activeResources.map((resource) => resource.displayName).join("、")
            : "当前未占用自动处理资源"}
        </small>
      </div>
    </li>
  );
}

export function SystemWorkspace({
  services,
  jobs,
  resources,
  section,
  onSectionChange,
  onOpenTemplates,
  templateContent,
  developerContent,
  productionReadOnly = false,
}: {
  services: AppServices;
  jobs: JobSummary[];
  resources: ResourceSummary[];
  section: SystemSection;
  onSectionChange: (section: SystemSection) => void;
  onOpenTemplates: () => void;
  templateContent?: ReactNode;
  developerContent?: ReactNode;
  productionReadOnly?: boolean;
}) {
  const [diagnostics, setDiagnostics] =
    useState<DiagnosticsSnapshot | null>(null);
  const [diagnosticError, setDiagnosticError] = useState<string | null>(null);
  const [diagnosticAction, setDiagnosticAction] = useState<string | null>(null);

  const runDiagnosticAction = async (
    action: (() => Promise<void>) | undefined,
    success: string,
  ) => {
    if (!action) return;
    setDiagnosticAction(null);
    try {
      await action();
      setDiagnosticAction(success);
    } catch {
      setDiagnosticAction("操作失败，请稍后重试。");
    }
  };

  const copyDiagnosticSummary = async () => {
    if (!services.loadEnvironmentSnapshot) return;
    try {
      const snapshot = await services.loadEnvironmentSnapshot();
      const summary = [
        `版本：${snapshot.application.version}`,
        `提交：${snapshot.application.commit}`,
        `Schema：${snapshot.database.schemaRevision}`,
        `数据库：${snapshot.database.integrity}`,
        `Windows：${snapshot.windows.release} ${snapshot.windows.architecture}`,
        `剩余磁盘：${(snapshot.resources.diskFreeBytes / 1024 ** 3).toFixed(1)} GB`,
        `CPU：${snapshot.resources.cpuCount ?? "未知"} 核`,
        `GPU：${snapshot.resources.gpu.available ? "可用" : "不可用"}`,
      ].join("\n");
      await navigator.clipboard.writeText(summary);
      setDiagnosticAction("诊断摘要已复制。");
    } catch {
      setDiagnosticAction("复制失败，请稍后重试。");
    }
  };

  useEffect(() => {
    if (section !== "diagnostics" || !services.loadDiagnostics) return;
    void services
      .loadDiagnostics()
      .then((next) => {
        setDiagnosticError(null);
        setDiagnostics(next);
      })
      .catch(() => setDiagnosticError("诊断信息加载失败。"));
  }, [section, services]);

  return (
    <section className="system-workspace" aria-labelledby="system-title">
      <h1 className="visually-hidden" id="system-title">系统</h1>
      <aside className="workspace-list-pane">
        <nav className="system-section-nav" aria-label="系统功能">
          {sections.filter(({ id }) => !productionReadOnly || id !== "templates").map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              aria-current={section === id}
              onClick={() => {
                onSectionChange(id);
                if (id === "templates") onOpenTemplates();
              }}
            >
              <Icon aria-hidden="true" size={18} />
              {label}
            </button>
          ))}
        </nav>
      </aside>
      <div className="workspace-detail-pane system-detail-pane">
        {section === "status" ? (
          <div className="system-content">
            <h2 className="visually-hidden">运行状态</h2>
            <PlatformSessionPanel services={services} productionReadOnly={productionReadOnly} />
            <section aria-labelledby="system-jobs-title">
              <h3 id="system-jobs-title">任务</h3>
              <ul className="status-rows">
                {jobs.filter((job) => !productionReadOnly || job.jobKind !== "test_fixture").map((job) => (
                  <JobStatusRow key={job.jobId} job={job} />
                ))}
              </ul>
              {jobs.length === 0 ? <p>当前没有任务记录。</p> : null}
            </section>
            <section aria-labelledby="system-resources-title">
              <h3 id="system-resources-title">本地资源</h3>
              <ul className="status-rows">
                {resources.map((resource) => (
                  <li key={resource.resourceId}>
                    <strong>{resource.displayName}</strong>
                    <span>
                      {resource.statusLabel}，{resource.inUse}/
                      {resource.capacity}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
            {developerContent}
          </div>
        ) : null}

        {section === "diagnostics" ? (
          <div className="system-content">
            <header className="system-toolbar">
              <h2 className="visually-hidden">运行诊断</h2>
              <button
                className="button"
                type="button"
                onClick={() => void runDiagnosticAction(
                  services.exportDiagnosticBundle
                    ? () => services.exportDiagnosticBundle!()
                    : undefined,
                  "诊断包已导出。",
                )}
              >
                <Download aria-hidden="true" size={17} />
                导出诊断包
              </button>
              <button
                className="button"
                type="button"
                onClick={() => void runDiagnosticAction(
                  services.openDiagnosticsDirectory
                    ? () => services.openDiagnosticsDirectory!()
                    : undefined,
                  "已打开诊断目录。",
                )}
              >
                <FolderOpen aria-hidden="true" size={17} />
                打开诊断目录
              </button>
              <button
                className="button"
                type="button"
                onClick={() => void copyDiagnosticSummary()}
              >
                <Copy aria-hidden="true" size={17} />
                复制诊断摘要
              </button>
            </header>
            {diagnosticAction ? (
              <p className="inline-message" role="status">{diagnosticAction}</p>
            ) : null}
            <RuntimeLogTerminal services={services} />
            {diagnosticError ? (
              <p className="inline-message">{diagnosticError}</p>
            ) : null}
            <ul className="diagnostic-health">
              {diagnostics?.health.map((health) => (
                <li key={health.id}>
                  <span
                    className={`health-dot health-${health.status}`}
                    aria-hidden="true"
                  />
                  <div>
                    <strong>{health.label}</strong>
                    <span>{health.summary}</span>
                  </div>
                </li>
              ))}
            </ul>
            <details className="collapsible-history">
              <summary id="recent-issues-title">最近问题 {diagnostics?.recentIssues.length ?? 0}</summary>
              <ul className="status-rows">
                {diagnostics?.recentIssues.map((issue, index) => (
                  <li key={`${issue.workItemId ?? "unknown"}-${index}`}>
                    <strong>{issue.location}</strong>
                    <span>
                      {issue.message}
                      {issue.diagnosticCode
                        ? `，诊断编号 ${issue.diagnosticCode}`
                        : ""}
                    </span>
                  </li>
                ))}
              </ul>
              {diagnostics && diagnostics.recentIssues.length === 0 ? (
                <p>当前没有技术问题。</p>
              ) : null}
            </details>
          </div>
        ) : null}

        {section === "templates"
          ? templateContent ?? (
              <EmptySystemSection icon={FileCog} title="识别模板" />
            )
          : null}
        {section === "settings" ? (
          <div className="system-content settings-content">
            <CredentialSettings services={services} />
            <PerformanceSettingsPanel services={services} />
            {productionReadOnly ? <DailyReportSettingsPanel services={services} /> : null}
          </div>
        ) : null}
        {section === "data" ? (
          <EmptySystemSection icon={Archive} title="数据管理" />
        ) : null}
      </div>
    </section>
  );
}
