import { type ReactNode, useEffect, useState } from "react";
import {
  Activity,
  Bug,
  Download,
  FileCog,
  FolderOpen,
  Copy,
  SlidersHorizontal,
} from "lucide-react";

import type { AppServices, JobSummary, ResourceSummary } from "../../app/contracts";
import type { DiagnosticsSnapshot } from "../../api/auditContracts";
import { CredentialSettings } from "./CredentialSettings";
import { DailyReportSettingsPanel } from "./DailyReportSettings";
import { PerformanceSettingsPanel } from "./PerformanceSettings";
import { RuntimeLogTerminal } from "./RuntimeLogTerminal";

export type SystemSection =
  | "diagnostics"
  | "templates"
  | "settings";

const sections: Array<{
  id: SystemSection;
  label: string;
  icon: typeof Activity;
}> = [
  { id: "diagnostics", label: "运行诊断", icon: Bug },
  { id: "templates", label: "识别模板", icon: FileCog },
  { id: "settings", label: "参数设置", icon: SlidersHorizontal },
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
  void jobs;
  void resources;
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
        {section === "diagnostics" ? (
          <div className="system-content">
            <h2 className="visually-hidden">运行诊断</h2>
            {diagnosticAction ? (
              <p className="inline-message" role="status">{diagnosticAction}</p>
            ) : null}
            <RuntimeLogTerminal services={services} diagnosticActions={<>
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
                导出诊断
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
                打开目录
              </button>
              <button
                className="button"
                type="button"
                onClick={() => void copyDiagnosticSummary()}
              >
                <Copy aria-hidden="true" size={17} />
                复制摘要
              </button>
            </>} />
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
            {developerContent}
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
      </div>
    </section>
  );
}
