import { useCallback, useEffect, useRef, useState } from "react";
import {
  Archive,
  CircleDollarSign,
  ClipboardList,
  Send,
  Settings,
  Power,
  RefreshCw,
} from "lucide-react";
import { Tooltip } from "../components/Tooltip";

import type {
  AppServices,
  ConsoleSnapshot,
  ContractSubjectCode,
  Loop3FixtureId,
  PlatformSession,
  ResourceSummary,
  ServerAction,
  UpdateStatus,
} from "./contracts";
import { ApiVersionMismatchError } from "./contracts";
import { AuditReviewQueue } from "../features/audit/AuditReviewQueue";
import { DailyWorkspace } from "../features/daily/DailyWorkspace";
import { WaybillHistory } from "../features/audit/WaybillHistory";
import {
  TemplateStudio,
} from "../features/templates/TemplateStudio";
import {
  SystemWorkspace,
  type SystemSection,
} from "../features/system/SystemWorkspace";
import { hasRecoverableTemplateCreation } from "../features/templates/templateRecovery";
import {
  LockedSetReview,
  type LockedSetReviewNavigationState,
} from "../features/lockedSetReview/LockedSetReview";
import { Loop9HumanReview } from "../features/lockedSetReview/Loop9HumanReview";

export type {
  AppServices,
  ConsoleSnapshot,
  JobItem,
  JobSummary,
  ServerAction,
} from "./contracts";
export { ApiVersionMismatchError } from "./contracts";

type PageId =
  | "daily"
  | "settlement"
  | "history"
  | "system"
  | "dispatch";

type SystemView =
  | SystemSection
  | "locked_set_review"
  | "loop9_review";

const navigation: Array<{
  id: PageId;
  label: string;
  icon: typeof CircleDollarSign;
  group: "business" | "other";
}> = [
  {
    id: "settlement",
    label: "运费结算",
    icon: CircleDollarSign,
    group: "business",
  },
  {
    id: "daily",
    label: "装卸车明细",
    icon: ClipboardList,
    group: "business",
  },
  { id: "dispatch", label: "派单", icon: Send, group: "business" },
  { id: "history", label: "历史数据", icon: Archive, group: "other" },
  { id: "system", label: "系统", icon: Settings, group: "other" },
];

interface AppProps {
  services: AppServices;
}

const protectedFixtureActions: Array<{
  actionId: string;
  fixtureId: Loop3FixtureId;
  note: string;
}> = [
  {
    actionId: "start_audit_long",
    fixtureId: "audit-batch-long-001",
    note: "冻结假数据，用于验证长批次、公平轮转和任务隔离。",
  },
  {
    actionId: "start_audit_short",
    fixtureId: "audit-batch-short-002",
    note: "冻结假数据，用于验证短任务不会被长批次永久阻塞。",
  },
  {
    actionId: "start_loading_probe",
    fixtureId: "loading-probe-001",
    note: "调度演练，不是正式装卸车业务",
  },
];

function ProtectedPracticePanel({
  actions,
  busyActions,
  onStart,
  onContractError,
}: {
  actions: Record<string, ServerAction>;
  busyActions: ReadonlySet<string>;
  onStart: (
    actionId: string,
    fixtureId: Loop3FixtureId,
    expectedRecordVersion: number,
  ) => void;
  onContractError: () => void;
}) {
  const entries = protectedFixtureActions.flatMap((definition) => {
    const action = actions[definition.actionId];
    return action?.visible ? [{ definition, action }] : [];
  });

  useEffect(() => {
    if (
      entries.some(
        ({ action }) =>
          (!action.enabled && !action.reason) ||
          action.expectedRecordVersion === null,
      )
    ) {
      onContractError();
    }
  }, [entries, onContractError]);

  const validEntries = entries.filter(
    ({ action }) =>
      (action.enabled || action.reason) &&
      action.expectedRecordVersion !== null,
  );
  if (validEntries.length === 0) {
    return null;
  }

  return (
    <section
      className="protected-practice"
      aria-labelledby="protected-practice-title"
    >
      <div>
        <h2 id="protected-practice-title">受保护假演练</h2>
        <p>只使用冻结夹具和临时数据，不连接真实业务。</p>
      </div>
      <div className="practice-actions">
        {validEntries.map(({ definition, action }) => {
          const busy = busyActions.has(definition.actionId);
          return (
            <div className="practice-action" key={definition.actionId}>
              <Tooltip
                content={
                  !action.enabled && action.reason
                    ? action.reason
                    : definition.note
                }
                disabledControl={!action.enabled || busy}
              >
                <button
                  className="button"
                  type="button"
                  disabled={!action.enabled || busy}
                  onClick={() =>
                    onStart(
                      definition.actionId,
                      definition.fixtureId,
                      action.expectedRecordVersion as number,
                    )
                  }
                >
                  {busy ? "正在建立任务…" : action.label}
                </button>
              </Tooltip>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export function App({ services }: AppProps) {
  const [recoverTemplateAtStartup] = useState(() =>
    hasRecoverableTemplateCreation(),
  );
  const [page, setPage] = useState<PageId>(() => {
    if (recoverTemplateAtStartup) return "system";
    const saved = window.localStorage.getItem("dahe:last-page");
    return navigation.some((item) => item.id === saved)
      ? (saved as PageId)
      : "settlement";
  });
  const [systemView, setSystemView] = useState<SystemView>(
    recoverTemplateAtStartup ? "templates" : "diagnostics",
  );
  const [platformSession, setPlatformSession] = useState<PlatformSession | null>(null);
  const [snapshot, setSnapshot] = useState<ConsoleSnapshot | null>(null);
  const [resources, setResources] = useState<ResourceSummary[]>([]);
  const [workspaceRevision, setWorkspaceRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busyStartActions, setBusyStartActions] = useState<Set<string>>(
    () => new Set(),
  );
  const [blockingVersionError, setBlockingVersionError] = useState(false);
  const [lockedSetReviewEnabled, setLockedSetReviewEnabled] =
    useState(false);
  const [loop9ReviewEnabled, setLoop9ReviewEnabled] = useState(false);
  const [productionReadOnly, setProductionReadOnly] = useState(false);
  const [lockedSetReviewNavigation, setLockedSetReviewNavigation] =
    useState<LockedSetReviewNavigationState>({
      dirty: false,
      saving: false,
    });
  const [message, setMessage] = useState<string | null>(null);
  const [showShutdownConfirm, setShowShutdownConfirm] = useState(false);
  const [showUpdateConfirm, setShowUpdateConfirm] = useState(false);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [updating, setUpdating] = useState(false);
  const [updateManifestFile, setUpdateManifestFile] = useState<File | null>(null);
  const [updateApplicationFile, setUpdateApplicationFile] = useState<File | null>(null);
  const [shuttingDown, setShuttingDown] = useState(false);
  const [applicationExited, setApplicationExited] = useState(false);
  const createPending = useRef(new Set<string>());
  const active = useRef(true);
  const lastAppliedCursor = useRef(-1);
  const refreshRequested = useRef(false);
  const refreshInFlight = useRef<Promise<ConsoleSnapshot | null> | null>(null);

  const navigateToPage = useCallback(
    (nextPage: PageId) => {
      const leavingLockedSetReview =
        page === "system" &&
        (systemView === "locked_set_review" ||
          systemView === "loop9_review");
      if (leavingLockedSetReview && lockedSetReviewNavigation.saving) {
        setMessage("当前人工标注正在保存，请等待保存完成后再离开。");
        return;
      }
      if (
        leavingLockedSetReview &&
        lockedSetReviewNavigation.dirty &&
        !window.confirm(
          "当前填写尚未保存。离开后将丢失这些修改，是否继续？",
        )
      ) {
        setMessage("当前填写尚未保存，已留在锁定集人工复核。");
        return;
      }
      setMessage(null);
      setPage(nextPage);
      window.localStorage.setItem("dahe:last-page", nextPage);
      if (nextPage === "system") {
        setSystemView("diagnostics");
      }
      if (nextPage !== "dispatch") {
        void services.recordBreadcrumb?.(nextPage);
      }
    },
    [lockedSetReviewNavigation, page, services, systemView],
  );

  const applySnapshot = useCallback((next: ConsoleSnapshot) => {
    if (!active.current || next.eventCursor < lastAppliedCursor.current) {
      return false;
    }
    lastAppliedCursor.current = next.eventCursor;
    setSnapshot(next);
    return true;
  }, []);

  const refreshSnapshot = useCallback((): Promise<ConsoleSnapshot | null> => {
    refreshRequested.current = true;
    if (refreshInFlight.current) {
      return refreshInFlight.current;
    }

    const drain = (async () => {
      let latestApplied: ConsoleSnapshot | null = null;
      while (refreshRequested.current) {
        refreshRequested.current = false;
        const next = await services.loadSnapshot();
        if (applySnapshot(next)) {
          latestApplied = next;
        }
      }
      return latestApplied;
    })();

    refreshInFlight.current = drain;
    const release = () => {
      if (refreshInFlight.current === drain) {
        refreshInFlight.current = null;
      }
    };
    void drain.then(release, release);
    return drain;
  }, [applySnapshot, services]);

  const refreshResources = useCallback(async () => {
    const next = await services.loadResources();
    if (active.current) {
      setResources(next);
    }
    return next;
  }, [services]);

  useEffect(() => {
    let disposed = false;
    let unsubscribe: () => void = () => {};
    active.current = true;

    async function start() {
      try {
        const bootstrap = await services.bootstrap();
        const [fresh, freshResources] = await Promise.all([
          services.loadSnapshot(),
          services.loadResources(),
        ]);
        if (disposed) {
          return;
        }
        applySnapshot(fresh);
        setResources(freshResources);
        setLockedSetReviewEnabled(bootstrap.lockedSetReviewEnabled);
        setLoop9ReviewEnabled(bootstrap.loop9ReviewEnabled ?? false);
        setProductionReadOnly(bootstrap.productionReadOnly ?? false);
        if (services.loadUpdateStatus) {
          void services.loadUpdateStatus().then((status) => {
            if (!disposed) setUpdateStatus(status);
          });
        }
        if (bootstrap.loop9ReviewEnabled) {
          setPage("system");
          setSystemView("loop9_review");
        }
        setLoading(false);
        unsubscribe = services.subscribe(
          fresh.eventCursor,
          (event) => {
            if (event.eventId <= lastAppliedCursor.current) {
              return;
            }
            setWorkspaceRevision((value) => value + 1);
            void Promise.all([refreshSnapshot(), refreshResources()]).catch(
              () => {
                if (active.current) {
                  setMessage(
                    "任务或资源状态暂时无法更新，当前页面内容已保留。系统会在下一次变化时重新核对。",
                  );
                }
              },
            );
          },
        );
      } catch (error) {
        if (disposed) {
          return;
        }
        if (error instanceof ApiVersionMismatchError) {
          setBlockingVersionError(true);
        } else {
          setMessage("操作台暂时无法加载，已有数据不会因此改变。请重新打开页面。");
        }
        setLoading(false);
      }
    }

    void start();
    return () => {
      disposed = true;
      active.current = false;
      unsubscribe();
    };
  }, [applySnapshot, refreshResources, refreshSnapshot, services]);

  useEffect(() => {
    if (loading || !services.loadPlatformSession) return undefined;
    let disposed = false;
    const refreshPlatformSession = () => {
      if (document.visibilityState === "hidden") return;
      void services.loadPlatformSession?.().then(
        (next) => { if (!disposed) setPlatformSession(next); },
        () => {
          if (!disposed) {
            setPlatformSession((current) => current ?? null);
          }
        },
      );
    };
    const handleVisibility = () => {
      if (document.visibilityState === "visible") refreshPlatformSession();
    };
    refreshPlatformSession();
    const timer = window.setInterval(refreshPlatformSession, 2000);
    document.addEventListener("visibilitychange", handleVisibility);
    window.addEventListener("focus", refreshPlatformSession);
    return () => {
      disposed = true;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", handleVisibility);
      window.removeEventListener("focus", refreshPlatformSession);
    };
  }, [loading, services]);

  const executeStart = useCallback(
    async (
      actionId: string,
      createJob: () => ReturnType<AppServices["createAuditJob"]>,
    ) => {
      if (createPending.current.has(actionId)) {
        return;
      }
      createPending.current.add(actionId);
      setBusyStartActions((current) => new Set(current).add(actionId));
      setMessage(null);
      try {
        await createJob();
        setPage("settlement");
        await Promise.all([refreshSnapshot(), refreshResources()]);
      } catch (error) {
        if (error instanceof ApiVersionMismatchError) {
          setBlockingVersionError(true);
        } else {
          setMessage(
            "任务尚未确认建立。请保持页面打开，系统会使用同一次请求继续核对。",
          );
        }
      } finally {
        createPending.current.delete(actionId);
        setBusyStartActions((current) => {
          const next = new Set(current);
          next.delete(actionId);
          return next;
        });
      }
    },
    [refreshResources, refreshSnapshot],
  );

  const startProtectedFixture = useCallback(
    (
      actionId: string,
      fixtureId: Loop3FixtureId,
      expectedRecordVersion: number,
    ) => {
      const action = snapshot?.startActions[actionId];
      if (
        !action?.enabled ||
        action.expectedRecordVersion !== expectedRecordVersion
      ) {
        return;
      }
      void executeStart(actionId, () =>
        services.createFixtureJob(fixtureId, expectedRecordVersion),
      );
    },
    [executeStart, services, snapshot?.startActions],
  );

  const handleContractError = useCallback(() => {
    setBlockingVersionError(true);
  }, []);

  const shutdownApplication = useCallback(async () => {
    if (!services.shutdownApplication || shuttingDown) return;
    setShuttingDown(true);
    setMessage(null);
    try {
      await services.shutdownApplication();
      setShowShutdownConfirm(false);
      setApplicationExited(true);
    } catch (error) {
      setShuttingDown(false);
      setMessage(
        error instanceof Error
          ? error.message
          : "程序暂时无法退出，请稍后重试。",
      );
    }
  }, [services, shuttingDown]);

  const checkOnlineUpdate = useCallback(async () => {
    if (updating) return;
    if (!services.checkForUpdates) return;
    setUpdating(true);
    setMessage(null);
    try {
      const status = await services.checkForUpdates();
      setUpdateStatus(status);
      setMessage(
        status.updateAvailable
          ? `发现新版本 ${status.availableVersion}。`
          : status.state === "up_to_date"
            ? "当前已是最新版本。"
            : "暂时无法检查更新，不影响继续使用。",
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "暂时无法检查更新。");
    } finally {
      setUpdating(false);
    }
  }, [services, updating]);

  const handleUpdateClick = useCallback(() => {
    if (updating) return;
    if (services.importUpdatePackage) {
      setShowUpdateConfirm(true);
      return;
    }
    if (updateStatus?.updateAvailable) {
      setShowUpdateConfirm(true);
      return;
    }
    void checkOnlineUpdate();
  }, [checkOnlineUpdate, services.importUpdatePackage, updateStatus, updating]);

  const installUpdate = useCallback(async () => {
    if (!services.installUpdate || updating) return;
    setUpdating(true);
    setMessage(null);
    try {
      const status = await services.installUpdate();
      setUpdateStatus(status);
      setShowUpdateConfirm(false);
      setMessage("正在退出当前版本并准备安装更新。完成后会自动重新打开。");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "更新暂时无法安装。");
      setShowUpdateConfirm(false);
    } finally {
      setUpdating(false);
    }
  }, [services, updating]);

  const importUpdate = useCallback(async () => {
    if (
      !services.importUpdatePackage ||
      !updateManifestFile ||
      !updateApplicationFile ||
      updating
    ) return;
    setUpdating(true);
    setMessage(null);
    try {
      const status = await services.importUpdatePackage(
        updateManifestFile,
        updateApplicationFile,
      );
      setUpdateStatus(status);
      setMessage(`本地更新包 ${status.availableVersion} 已校验，可以安装。`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "本地更新包校验失败。");
    } finally {
      setUpdating(false);
    }
  }, [services, updateApplicationFile, updateManifestFile, updating]);

  if (blockingVersionError) {
    return (
      <main className="blocking-page">
        <section role="alert" className="blocking-message">
          <p className="mode-badge">需要重新打开</p>
          <h1>操作台版本不一致</h1>
          <p>请关闭此页面并重新打开大禾物流自动化平台。</p>
        </section>
      </main>
    );
  }

  if (loading) {
    return (
      <main className="blocking-page" aria-busy="true">
        <section className="loading-shell" aria-label="正在打开操作台">
          <span />
          <span />
          <span />
        </section>
      </main>
    );
  }

  if (applicationExited) {
    return (
      <main className="shutdown-page">
        <Power aria-hidden="true" size={30} />
        <h1>程序已退出</h1>
        <p>可以关闭此页面。再次使用时，请从桌面打开“大禾物流自动化平台”。</p>
      </main>
    );
  }

  const businessNavigation = navigation.filter(
    (item) => item.group === "business",
  );
  const connectionStatus = platformSession?.connectionStatus ?? {
    code: "error" as const,
    label: "连接异常" as const,
  };
  const contractSubjectCode =
    platformSession?.contractSubject.currentSubjectCode ?? "shanxi_guienbo";
  const contractSubjects = platformSession?.contractSubject.availableSubjects ?? [
    { code: "shanxi_guienbo" as const, label: "山西贵恩博" },
    { code: "shanghai_jinyisheng" as const, label: "上海晋亿晟" },
  ];
  const selectContractSubject = async (subjectCode: ContractSubjectCode) => {
    if (
      !platformSession ||
      !services.selectContractSubject ||
      subjectCode === contractSubjectCode
    ) return;
    setMessage(null);
    try {
      const next = await services.selectContractSubject(
        subjectCode,
        platformSession.contractSubject.recordVersion,
      );
      setPlatformSession((current) =>
        current ? { ...current, contractSubject: next } : current,
      );
      setWorkspaceRevision((value) => value + 1);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "签约主体未能切换。");
    }
  };
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        跳到主要内容
      </a>
      <header className="mobile-header">
        <strong><span>大禾物流</span><span>自动化平台</span></strong>
      </header>
      <nav className="side-navigation" aria-label="主导航">
        <div className="product-name">
          <span className="product-mark" aria-hidden="true">
            <img src="/dahe-logo.png" alt="" />
          </span>
          <strong><span>大禾物流</span><span>自动化平台</span></strong>
        </div>
        <div className="business-subject-heading">
          <span className="navigation-group-label">业务</span>
          <div className="contract-subject-switcher" aria-label="签约主体">
            {contractSubjects.map((subject) => (
              <button
                className="contract-subject-button"
                type="button"
                key={subject.code}
                aria-pressed={subject.code === contractSubjectCode}
                onClick={() => void selectContractSubject(subject.code)}
              >
                {subject.label}
              </button>
            ))}
          </div>
        </div>
        <ul>
          {businessNavigation.map((item) => (
            <li key={item.id}>
              <button
                type="button"
                disabled={
                  page === "system" &&
                  (systemView === "locked_set_review" ||
                    systemView === "loop9_review") &&
                  lockedSetReviewNavigation.saving
                }
                aria-current={page === item.id ? "page" : undefined}
                onClick={() => navigateToPage(item.id)}
              >
                <item.icon aria-hidden="true" size={19} />
                <span>{item.label}</span>
              </button>
            </li>
          ))}
        </ul>
        <section className="platform-connection-summary" aria-labelledby="platform-connection-title">
          <span className="navigation-group-label" id="platform-connection-title">成丰平台连接状态</span>
          <span
            className={`platform-connection-pill connection-${connectionStatus.code}`}
            role="status"
            aria-label={`成丰平台连接状态：${connectionStatus.label}`}
          >
            {connectionStatus.label}
          </span>
        </section>
        <ul className="navigation-secondary utility-navigation" aria-label="工具">
          <li>
            <Tooltip content="系统设置">
              <button
                className="utility-icon-button settings-button"
                type="button"
                disabled={
                  page === "system" &&
                  (systemView === "locked_set_review" || systemView === "loop9_review") &&
                  lockedSetReviewNavigation.saving
                }
                aria-current={page === "system" ? "page" : undefined}
                aria-label="系统设置"
                onClick={() => navigateToPage("system")}
              >
                <Settings aria-hidden="true" size={20} />
              </button>
            </Tooltip>
          </li>
          <li>
            <Tooltip content="历史数据">
              <button
                className="utility-icon-button history-button"
                type="button"
                aria-current={page === "history" ? "page" : undefined}
                aria-label="历史数据"
                onClick={() => navigateToPage("history")}
              >
                <Archive aria-hidden="true" size={20} />
              </button>
            </Tooltip>
          </li>
          {services.checkForUpdates ? (
            <li>
              <Tooltip content="版本更新">
                        <button
                  className="utility-icon-button update-button"
                          type="button"
                          disabled={updating}
                          aria-label={
                            updateStatus?.updateAvailable
                      ? `有新版本 ${updateStatus.availableVersion}，版本更新`
                      : "版本更新"
                          }
                          onClick={() => void handleUpdateClick()}
                        >
                          <RefreshCw aria-hidden="true" size={18} />
                          {updateStatus?.updateAvailable ? (
                            <span className="update-dot" aria-hidden="true" />
                          ) : null}
                        </button>
              </Tooltip>
            </li>
          ) : null}
          {services.shutdownApplication ? (
            <li>
              <Tooltip content="退出程序">
                        <button
                  className="utility-icon-button power-button"
                          type="button"
                          aria-label="退出程序"
                          onClick={() => setShowShutdownConfirm(true)}
                        >
                          <Power aria-hidden="true" size={18} />
                        </button>
              </Tooltip>
            </li>
          ) : null}
        </ul>
      </nav>

      <main id="main-content" tabIndex={-1}>
        {message ? (
          <div className="global-message" role="alert">
            {message}
          </div>
        ) : null}

        {page === "settlement" ? (
          <div className="business-page">
            <AuditReviewQueue
              key={`settlement:${contractSubjectCode}`}
              services={services}
              jobs={snapshot?.jobs ?? []}
              workspaceRevision={workspaceRevision}
              contractSubjectCode={contractSubjectCode}
            />
          </div>
        ) : null}

        {page === "history" ? (
          <WaybillHistory
            key={`history:${contractSubjectCode}`}
            services={services}
            contractSubjectCode={contractSubjectCode}
          />
        ) : null}

        {page === "system" &&
        systemView !== "locked_set_review" &&
        systemView !== "loop9_review" ? (
          <SystemWorkspace
            services={services}
            jobs={snapshot?.jobs ?? []}
            resources={resources}
            section={systemView}
            onSectionChange={setSystemView}
            onOpenTemplates={() => setSystemView("templates")}
            productionReadOnly={productionReadOnly}
            templateContent={
              systemView === "templates" && !productionReadOnly ? (
                <TemplateStudio
                  services={services}
                  onBack={() => setSystemView("diagnostics")}
                />
              ) : undefined
            }
            developerContent={
              productionReadOnly ? undefined : <section className="developer-tools">
                {snapshot ? (
                  <ProtectedPracticePanel
                    actions={snapshot.startActions}
                    busyActions={busyStartActions}
                    onStart={startProtectedFixture}
                    onContractError={handleContractError}
                  />
                ) : null}
                {lockedSetReviewEnabled ? (
                  <button
                    className="button"
                    type="button"
                    onClick={() => setSystemView("locked_set_review")}
                  >
                    打开锁定集复核
                  </button>
                ) : null}
                {loop9ReviewEnabled ? (
                  <button
                    className="button"
                    type="button"
                    onClick={() => setSystemView("loop9_review")}
                  >
                    打开 Loop 9 人工复核
                  </button>
                ) : null}
              </section>
            }
          />
        ) : null}

        {page === "system" && systemView === "locked_set_review" ? (
          <LockedSetReview
            services={services}
            onBack={() => setSystemView("diagnostics")}
            onNavigationStateChange={setLockedSetReviewNavigation}
          />
        ) : null}

        {page === "system" && systemView === "loop9_review" ? (
          <Loop9HumanReview
            services={services}
            onBack={() => setSystemView("diagnostics")}
            onNavigationStateChange={setLockedSetReviewNavigation}
          />
        ) : null}

        {page === "daily" ? (
          <div className="business-page">
            <DailyWorkspace
              key={`daily:${contractSubjectCode}`}
              services={services}
              jobs={snapshot?.jobs ?? []}
              productionReadOnly={productionReadOnly}
              workspaceRevision={workspaceRevision}
              contractSubjectCode={contractSubjectCode}
            />
          </div>
        ) : null}

        {page === "dispatch" ? (
          <section className="placeholder-page">
            <Send aria-hidden="true" size={30} />
            <h1 className="visually-hidden">派单</h1>
            <p>当前阶段尚未启用。</p>
          </section>
        ) : null}
      </main>
      {showUpdateConfirm ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="shutdown-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="update-title"
          >
            <h2 id="update-title">
              {updateStatus?.updateAvailable
                ? `安装 ${updateStatus.availableVersion} 更新？`
                : "软件更新"}
            </h2>
            <p>
              {updateStatus?.updateAvailable
                ? "程序会先确认没有未完成任务，再退出当前版本并安装。"
                : "可以在线检查更新，或导入已下载的正式更新包。"}
            </p>
            {services.importUpdatePackage ? (
              <div className="update-import-fields">
                <label>
                  <span>更新清单</span>
                  <input
                    type="file"
                    accept="application/json,.json"
                    onChange={(event) => setUpdateManifestFile(event.target.files?.[0] ?? null)}
                  />
                </label>
                <label>
                  <span>应用 ZIP</span>
                  <input
                    type="file"
                    accept="application/zip,.zip"
                    onChange={(event) => setUpdateApplicationFile(event.target.files?.[0] ?? null)}
                  />
                </label>
                <button
                  className="button"
                  type="button"
                  disabled={updating || !updateManifestFile || !updateApplicationFile}
                  onClick={() => void importUpdate()}
                >
                  导入更新包
                </button>
              </div>
            ) : null}
            <div className="dialog-actions">
              <button
                className="button"
                type="button"
                disabled={updating}
                onClick={() => setShowUpdateConfirm(false)}
              >
                取消
              </button>
              {updateStatus?.updateAvailable ? (
                <button
                  className="button primary"
                  type="button"
                  disabled={updating}
                  onClick={() => void installUpdate()}
                >
                  {updating ? "正在准备…" : "安装更新"}
                </button>
              ) : (
                <button
                  className="button primary"
                  type="button"
                  disabled={updating || !services.checkForUpdates}
                  onClick={() => void checkOnlineUpdate()}
                >
                  {updating ? "正在检查…" : "检查更新"}
                </button>
              )}
            </div>
          </section>
        </div>
      ) : null}
      {showShutdownConfirm ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="shutdown-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="shutdown-title"
          >
            <h2 id="shutdown-title">退出大禾物流自动化平台？</h2>
            <p>
              退出会取消正在进行的运费结算或装卸车读取；重启后不会自动继续。
            </p>
            <div className="dialog-actions">
              <button
                className="button"
                type="button"
                disabled={shuttingDown}
                onClick={() => setShowShutdownConfirm(false)}
              >
                取消
              </button>
              <button
                className="button danger"
                type="button"
                disabled={shuttingDown}
                onClick={() => void shutdownApplication()}
              >
                {shuttingDown ? "正在退出…" : "退出程序"}
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}
