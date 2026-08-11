import {
  CircleStop,
  BriefcaseBusiness,
  ExternalLink,
  FileCheck2,
  FlaskConical,
  Link2,
  LogOut,
  Radar,
  X,
} from "lucide-react";
import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";

import type { AppServices, PlatformAction, PlatformSession } from "../../app/contracts";
import { Tooltip } from "../../components/Tooltip";

const unavailable: PlatformAction = { enabled: false, reason: "当前状态不允许执行此操作。" };

function statusLabel(session: PlatformSession): string {
  if (!session.enabled) return "未启用";
  if (!session.runtimeAvailable) return "浏览器环境未就绪";
  if (session.browserControlMode === "human_login") return "等待登录";
  if (session.browserControlMode === "human_handoff") return "人员正在使用平台";
  if (session.browserControlMode === "automated") return "程序正在只读采集";
  if (session.browserLifecycle === "ready") return "浏览器已就绪";
  return "未连接";
}

function ActionButton({
  action,
  busy,
  children,
  onClick,
}: {
  action: PlatformAction;
  busy: boolean;
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <Tooltip content={action.reason ?? "可执行"} disabledControl={!action.enabled || busy}>
      <button className="button" type="button" disabled={!action.enabled || busy} onClick={onClick}>
        {children}
      </button>
    </Tooltip>
  );
}

export function PlatformSessionPanel({
  services,
  productionReadOnly = false,
}: {
  services: AppServices;
  productionReadOnly?: boolean;
}) {
  const [session, setSession] = useState<PlatformSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sealedCount, setSealedCount] = useState<number | null>(null);
  const [validatedImageCount, setValidatedImageCount] = useState<number | null>(null);
  const [confirmations, setConfirmations] = useState({
    legacyIdleConfirmed: false,
    noSettlementOrPaymentConfirmed: false,
    sameAccountSessionRiskAccepted: false,
  });

  const refresh = useCallback(async () => {
    if (!services.loadPlatformSession) return;
    setSession(await services.loadPlatformSession());
  }, [services]);

  useEffect(() => {
    let active = true;
    void services.loadPlatformSession?.().then((next) => {
      if (active) setSession(next);
    }).catch(() => {
      if (active) setError("成丰连接状态加载失败。");
    });
    return () => { active = false; };
  }, [services]);

  const allConfirmed = useMemo(() => Object.values(confirmations).every(Boolean), [confirmations]);
  const activeWindow = session?.accessWindow && !session.accessWindow.expired && session.accessWindow.consumedAt === null
    ? session.accessWindow
    : null;

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "操作未完成，请刷新后重试。");
    } finally {
      setBusy(false);
    }
  };

  if (!services.loadPlatformSession) return null;

  if (productionReadOnly) {
    return (
      <section className="platform-session-panel" aria-labelledby="platform-session-title">
        <header className="compact-section-heading">
          <div className="title-row">
            <Link2 aria-hidden="true" size={18} />
            <h3 id="platform-session-title">成丰连接</h3>
          </div>
          <div className="platform-heading-status">
            <span className="status-pill">业务连接</span>
            <span className="status-pill">{session ? statusLabel(session) : "读取中"}</span>
          </div>
        </header>
        {error ? <p className="inline-message" role="alert">{error}</p> : null}
      </section>
    );
  }

  const createAction = session?.availableActions.create_access_window ?? unavailable;
  const guardedCreateAction = {
    ...createAction,
    enabled: createAction.enabled && allConfirmed,
    reason: createAction.enabled && !allConfirmed ? "请先确认三项当前安全条件。" : createAction.reason,
  };

  return (
    <section className="platform-session-panel" aria-labelledby="platform-session-title">
      <header className="compact-section-heading">
        <div className="title-row">
          <Link2 aria-hidden="true" size={18} />
          <h3 id="platform-session-title">成丰连接</h3>
        </div>
        <div className="platform-heading-status">
          <span className="status-pill">{session?.connectionModeLabel ?? "读取中"}</span>
          <span className="status-pill">{session ? statusLabel(session) : "读取中"}</span>
        </div>
      </header>

      {error ? <p className="inline-message" role="alert">{error}</p> : null}

      {session?.connectionMode === "operational_compat" ? (
        <div className="system-business-status">
          <span>业务读取请在“运费结算”页面操作。</span>
          <ActionButton
            action={session.availableActions.switch_connection_mode}
            busy={busy}
            onClick={() => void run(async () => {
              await services.switchPlatformConnectionMode?.("strict_shadow", session.connectionModeRecordVersion);
            })}
          >
            <FlaskConical aria-hidden="true" size={17} />
            切换到验证连接
          </ActionButton>
        </div>
      ) : null}

      {session?.connectionMode === "strict_shadow" ? (
        <>
          {!activeWindow ? (
            <div className="connection-mode-switch">
              <ActionButton
                action={session.availableActions.switch_connection_mode}
                busy={busy}
                onClick={() => void run(async () => {
                  await services.switchPlatformConnectionMode?.("operational_compat", session.connectionModeRecordVersion);
                })}
              >
                <BriefcaseBusiness aria-hidden="true" size={17} />
                切换到业务连接
              </ActionButton>
            </div>
          ) : null}
          {!activeWindow && session.enabled ? (
            <fieldset className="platform-confirmations">
              <legend>建立验证窗口前确认</legend>
              <label>
                <input type="checkbox" checked={confirmations.legacyIdleConfirmed} onChange={(event) => setConfirmations((current) => ({ ...current, legacyIdleConfirmed: event.target.checked }))} />
                旧程序已完全停止
              </label>
              <label>
                <input type="checkbox" checked={confirmations.noSettlementOrPaymentConfirmed} onChange={(event) => setConfirmations((current) => ({ ...current, noSettlementOrPaymentConfirmed: event.target.checked }))} />
                当前没有采集、下载、结算交接或付款
              </label>
              <label>
                <input type="checkbox" checked={confirmations.sameAccountSessionRiskAccepted} onChange={(event) => setConfirmations((current) => ({ ...current, sameAccountSessionRiskAccepted: event.target.checked }))} />
                接受新登录可能使旧程序登录态失效
              </label>
            </fieldset>
          ) : null}

          {session?.browserControlMode === "human_login" ? <p className="platform-process-note">请在独立窗口完成登录，再归还程序控制。</p> : null}
          {session?.browserControlMode === "human_handoff" ? <p className="platform-process-note">请只查看待结算列表、打开一条运单详情和两张磅单；本次窗口不能继续业务操作。</p> : null}
          {sealedCount !== null ? <p className="platform-process-note">只读结构已封存，共记录 {sealedCount} 条脱敏结构。</p> : null}
          {validatedImageCount !== null ? <p className="platform-process-note">只读合同验证已完成，列表、详情和 {validatedImageCount} 张磅单图片均通过安全边界。</p> : null}

          <div className="compact-actions">
            {!activeWindow ? (
              <ActionButton
                action={guardedCreateAction}
                busy={busy}
                onClick={() => void run(async () => {
                  await services.createPlatformAccessWindow?.({
                    ...confirmations,
                    purpose: session?.contractCandidateSelected ? "formal_locked_set" : "contract_discovery",
                  });
                })}
              >
                <FlaskConical aria-hidden="true" size={17} />
                {session?.contractCandidateSelected ? "建立 60 分钟验证窗口" : "建立 60 分钟只读窗口"}
              </ActionButton>
            ) : null}

            {session && activeWindow ? (
              <>
                <ActionButton action={session.availableActions.start_human_login} busy={busy} onClick={() => void run(async () => {
                  await services.startPlatformHumanLogin?.(activeWindow.accessWindowId, session.recordVersion);
                })}>
                  <ExternalLink aria-hidden="true" size={17} />
                  打开成丰登录页
                </ActionButton>
                <ActionButton action={session.availableActions.return_human_login} busy={busy} onClick={() => void run(async () => {
                  await services.returnPlatformHumanLogin?.(activeWindow.accessWindowId, session.recordVersion);
                })}>
                  <LogOut aria-hidden="true" size={17} />
                  登录完成，归还控制
                </ActionButton>
                {activeWindow.purpose === "contract_discovery" ? (
                  <>
                    <ActionButton action={session.availableActions.start_discovery_capture} busy={busy} onClick={() => void run(async () => {
                      setSealedCount(null);
                      await services.startPlatformDiscoveryCapture?.(activeWindow.accessWindowId, session.recordVersion);
                    })}>
                      <Radar aria-hidden="true" size={17} />
                      开始记录只读结构
                    </ActionButton>
                    <ActionButton action={session.availableActions.stop_discovery_capture} busy={busy} onClick={() => void run(async () => {
                      const evidence = await services.stopPlatformDiscoveryCapture?.(activeWindow.accessWindowId, session.recordVersion);
                      if (evidence) setSealedCount(evidence.observationCount);
                    })}>
                      <CircleStop aria-hidden="true" size={17} />
                      停止并封存
                    </ActionButton>
                  </>
                ) : (
                  <ActionButton action={session.availableActions.validate_read_contract} busy={busy} onClick={() => void run(async () => {
                    const evidence = await services.validatePlatformReadContract?.(activeWindow.accessWindowId, session.recordVersion);
                    if (evidence) setValidatedImageCount(evidence.imageCount);
                  })}>
                    <FileCheck2 aria-hidden="true" size={17} />
                    验证只读合同
                  </ActionButton>
                )}
                <ActionButton action={session.availableActions.close_session} busy={busy} onClick={() => void run(async () => {
                  await services.closePlatformSession?.(activeWindow.accessWindowId, session.recordVersion);
                })}>
                  <X aria-hidden="true" size={17} />
                  关闭验证窗口
                </ActionButton>
              </>
            ) : null}
          </div>
        </>
      ) : null}
    </section>
  );
}
