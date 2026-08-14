import { AlertTriangle, Check, Copy, ExternalLink, FileImage } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { AppServices, ContractSubjectCode, JobSummary } from "../../app/contracts";
import type {
  AuditReviewItem,
  AuditWorkspaceCounts,
  AuditWorkspaceView,
  SettlementWorkspaceResult,
} from "../../api/auditContracts";
import { ImageViewer } from "../../components/ImageViewer";
import { useToast } from "../../components/ToastContext";
import { BusinessFilterTabs } from "../business/BusinessWorkspace";
import { BusinessConnectionBar } from "./BusinessConnectionBar";

declare const __APP_VERSION__: string;

const filters: Array<{ id: AuditWorkspaceView; label: string }> = [
  { id: "all", label: "全部" },
  { id: "waiting_review", label: "待核对" },
  { id: "confirmed_problem", label: "问题运单" },
  { id: "normal_ready", label: "可结算" },
];

function evidenceUrl(sha256: string | null): string | null {
  return sha256
    ? `/api/v1/evidence/${sha256}?client_version=${encodeURIComponent(__APP_VERSION__)}`
    : null;
}

function weight(value: string | null): string {
  return value ? `${value} t` : "未识别";
}

async function copyText(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.append(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("浏览器没有允许复制，请重试。");
}

function TicketEvidence({
  side,
  sha256,
  ticketWeight,
  platformWeight,
  ocrIssue,
  onOpen,
}: {
  side: "装货" | "卸货";
  sha256: string | null;
  ticketWeight: string | null;
  platformWeight: string | null;
  ocrIssue: boolean;
  onOpen: (url: string, label: string) => void;
}) {
  const url = evidenceUrl(sha256);
  return (
    <section className="settlement-ticket" aria-label={`${side}磅单`}>
      <button
        className="settlement-ticket-image"
        type="button"
        disabled={!url}
        aria-label={url ? `放大查看${side}磅单` : `${side}磅单未提供`}
        onClick={() => url && onOpen(url, `${side}磅单`)}
      >
        {url ? (
          <img loading="lazy" src={url} alt={`${side}磅单原图`} />
        ) : (
          <span><FileImage aria-hidden="true" size={22} />未提供图片</span>
        )}
      </button>
      <dl className="settlement-weights">
        <div className={ocrIssue ? "is-error" : ""}>
          <dt>识别</dt>
          <dd>{weight(ticketWeight)}</dd>
        </div>
        <div>
          <dt>平台</dt>
          <dd>{weight(platformWeight)}</dd>
        </div>
      </dl>
    </section>
  );
}

export function AuditReviewQueue({
  services,
  jobs = [],
  workspaceRevision = 0,
  contractSubjectCode = "shanxi_guienbo",
}: {
  services: AppServices;
  jobs?: JobSummary[];
  productionReadOnly?: boolean;
  workspaceRevision?: number;
  contractSubjectCode?: ContractSubjectCode;
}) {
  const { showToast } = useToast();
  const [workspace, setWorkspace] = useState<SettlementWorkspaceResult>({
    items: [],
    counts: { all: 0, waiting_review: 0, confirmed_problem: 0, normal_ready: 0 },
    latestFetch: null,
  });
  const [view, setView] = useState<AuditWorkspaceView>("all");
  const [message, setMessage] = useState<string | null>(null);
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [viewer, setViewer] = useState<{ url: string; label: string } | null>(null);
  const [handoffPending, setHandoffPending] = useState(false);
  const loadGeneration = useRef(0);
  const activeSourceJobId = useRef<string | null>(null);
  const settlementRevision = useMemo(
    () =>
      jobs
        .filter((job) => job.taskType === "settlement_capture" || job.taskType === "audit")
        .map((job) => `${job.jobId}:${job.updatedAt ?? job.recordVersion}`)
        .sort()
        .join("|"),
    [jobs],
  );
  const refresh = useCallback(async () => {
    if (!services.loadSettlementWorkspace) return;
    try {
      const result = await services.loadSettlementWorkspace(
        view,
        contractSubjectCode,
      );
      if (
        activeSourceJobId.current !== null &&
        result.sourceJobId !== activeSourceJobId.current
      ) return;
      setWorkspace(result);
      setMessage(null);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "运单结果暂时无法读取。");
    }
  }, [contractSubjectCode, services, view]);

  useEffect(() => {
    const load = services.loadSettlementWorkspace;
    if (!load) return;
    let active = true;
    const generation = ++loadGeneration.current;
    void load(view, contractSubjectCode).then(
      (result) => {
        if (
          !active ||
          generation !== loadGeneration.current ||
          (activeSourceJobId.current !== null && result.sourceJobId !== activeSourceJobId.current)
        ) return;
        setWorkspace(result);
        setMessage(null);
      },
      (error: unknown) => {
        if (!active) return;
        setMessage(error instanceof Error ? error.message : "运单结果暂时无法读取。");
      },
    );
    return () => {
      active = false;
      if (loadGeneration.current === generation) loadGeneration.current += 1;
    };
  }, [contractSubjectCode, revision, services, settlementRevision, view, workspaceRevision]);

  const decide = async (item: AuditReviewItem, decision: "normal" | "problem") => {
    const action = decision === "normal" ? item.availableActions.confirm_normal : item.availableActions.confirm_problem;
    if (!action?.enabled) return;
    setPendingId(item.workItemId);
    setMessage(null);
    try {
      if (decision === "normal") {
        await services.dismissAuditProblem?.(item.workItemId, {
          expectedRecordVersion: item.recordVersion,
        });
      } else {
        await services.confirmAuditProblem?.(item.workItemId, {
          expectedRecordVersion: item.recordVersion,
        });
      }
      await refresh();
      showToast(decision === "normal" ? "已确认无误。" : "已列为问题运单。", "success");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "操作失败，请重试。", "error");
    } finally {
      setPendingId(null);
    }
  };

  const counts: AuditWorkspaceCounts = workspace.counts;
  const copyReadyWaybills = async () => {
    if (!services.loadReadySettlementWaybillNumbers) return;
    setHandoffPending(true);
    try {
      const values = await services.loadReadySettlementWaybillNumbers(
        contractSubjectCode,
      );
      if (!values.length) throw new Error("当前没有可复制的运单号。");
      await copyText(values.join("\n"));
      showToast(`已复制 ${values.length} 个可结算运单号。`, "success");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "复制失败，请重试。", "error");
    } finally {
      setHandoffPending(false);
    }
  };
  const openSettlementFilter = async () => {
    if (!services.prepareSettlementFilterHandoff) return;
    setHandoffPending(true);
    try {
      const result = await services.prepareSettlementFilterHandoff(
        contractSubjectCode,
      );
      showToast(result.message, result.missingCount > 0 ? "warning" : "success");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "成丰批量筛选未完成。", "error");
    } finally {
      setHandoffPending(false);
    }
  };
  const emptyText = !workspace.latestFetch
    ? "尚未获取运单"
    : workspace.latestFetch.status === "incomplete"
      ? "本次获取未完整，尚无可显示的运单"
      : counts.all === 0
        ? "本次没有可结算运单"
        : "当前筛选没有运单";

  return (
    <section className="settlement-workspace" aria-labelledby="settlement-title">
      <h1 id="settlement-title" className="visually-hidden">运费结算</h1>
      <BusinessConnectionBar
        services={services}
        jobs={jobs}
        latestFetch={workspace.latestFetch}
        onChanged={() => setRevision((value) => value + 1)}
        onStarted={(sourceJobId) => {
          activeSourceJobId.current = sourceJobId;
          setWorkspace({
            items: [],
            counts: { all: 0, waiting_review: 0, confirmed_problem: 0, normal_ready: 0 },
            latestFetch: null,
            sourceJobId,
            sourceRecordVersion: 0,
            captureMode: "whole_run_v1",
            visiblePrefixCount: 0,
            onlineCaptureComplete: false,
          });
        }}
        trailing={counts.normal_ready > 0 ? (
          <div className="settlement-handoff-actions">
            <button
              className="button"
              type="button"
              disabled={handoffPending}
              onClick={() => void copyReadyWaybills()}
            >
              <Copy aria-hidden="true" size={17} />复制运单号
            </button>
            <button
              className="button"
              type="button"
              disabled={handoffPending}
              onClick={() => void openSettlementFilter()}
            >
              <ExternalLink aria-hidden="true" size={17} />打开成丰筛选
            </button>
          </div>
        ) : null}
        contractSubjectCode={contractSubjectCode}
      />
      <div className="business-filter-row">
        <BusinessFilterTabs
          items={filters.map((filter) => ({ ...filter, count: counts[filter.id] }))}
          value={view}
          onChange={setView}
        />
      </div>
      {message ? <p className="inline-message" role="status">{message}</p> : null}
      <div className="settlement-waybills">
        {workspace.items.map((item) => (
          <article className="settlement-waybill" key={item.workItemId}>
            <div className="settlement-identity">
              <strong title={item.waybillId}>{item.waybillId}</strong>
              <span>{item.vehicleNumber || "车牌未记录"}</span>
            </div>
            <TicketEvidence
              side="装货"
              sha256={item.loadingImageSha256}
              ticketWeight={item.ticketLoadingNet}
              platformWeight={item.platformLoadingNet}
              ocrIssue={item.reviewHighlightRoles.includes("loading")}
              onOpen={(url, label) => setViewer({ url, label })}
            />
            <TicketEvidence
              side="卸货"
              sha256={item.unloadingImageSha256}
              ticketWeight={item.ticketUnloadingNet}
              platformWeight={item.platformUnloadingNet}
              ocrIssue={item.reviewHighlightRoles.includes("unloading")}
              onOpen={(url, label) => setViewer({ url, label })}
            />
            <div className="settlement-decisions" aria-label="人工判断">
              <button
                className="button"
                type="button"
                aria-pressed={item.businessOutcome === "normal_ready"}
                disabled={pendingId === item.workItemId || !item.availableActions.confirm_normal?.enabled}
                onClick={() => void decide(item, "normal")}
              >
                <Check aria-hidden="true" size={17} />确认无误
              </button>
              <button
                className="button danger"
                type="button"
                aria-pressed={item.businessOutcome === "confirmed_problem"}
                disabled={pendingId === item.workItemId || !item.availableActions.confirm_problem?.enabled}
                onClick={() => void decide(item, "problem")}
              >
                <AlertTriangle aria-hidden="true" size={17} />异常
              </button>
            </div>
          </article>
        ))}
      </div>
      {workspace.items.length === 0 ? (
        <div className="workspace-empty"><FileImage aria-hidden="true" size={24} /><strong>{emptyText}</strong></div>
      ) : null}
      {viewer ? <ImageViewer {...viewer} onClose={() => setViewer(null)} /> : null}
    </section>
  );
}
