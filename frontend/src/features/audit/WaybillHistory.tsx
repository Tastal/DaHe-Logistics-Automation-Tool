import { FormEvent, useEffect, useState } from "react";
import { ChevronLeft, Clock3, History, Search } from "lucide-react";

import type { AppServices, ContractSubjectCode } from "../../app/contracts";
import type { AuditReviewItem } from "../../api/auditContracts";

const outcomeLabels: Record<string, string> = {
  normal_ready: "审核通过",
  awaiting_review: "待核对",
  confirmed_problem: "问题运单",
};

const eventLabels: Record<string, string> = {
  audit_decision_created: "机器核对完成",
  correction: "历史更正（旧版）",
  problem_confirmation: "异常",
  problem_dismissal: "确认无误",
  revocation: "撤销人工决定",
};

function usesNarrowMasterDetail(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(max-width: 800px)").matches
  );
}

export function WaybillHistory({
  services,
  contractSubjectCode,
}: {
  services: AppServices;
  contractSubjectCode: ContractSubjectCode;
}) {
  const [items, setItems] = useState<AuditReviewItem[]>([]);
  const [selected, setSelected] = useState<AuditReviewItem | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = async (query = "", outcome = "") => {
    if (!services.loadWaybillHistory) return;
    const next = await services.loadWaybillHistory(
      query,
      outcome,
      contractSubjectCode,
    );
    setItems(next);
    setSelected((current) => {
      if (current && next.some((item) => item.workItemId === current.workItemId)) {
        return current;
      }
      return usesNarrowMasterDetail() ? null : (next[0] ?? null);
    });
  };

  useEffect(() => {
    if (!services.loadWaybillHistory) return;
    let active = true;
    void services
      .loadWaybillHistory("", "", contractSubjectCode)
      .then((next) => {
        if (!active) return;
        setItems(next);
        setSelected(usesNarrowMasterDetail() ? null : (next[0] ?? null));
      })
      .catch(() => {
        if (active) setMessage("历史数据加载失败。");
      });
    return () => {
      active = false;
    };
  }, [contractSubjectCode, services]);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    void load(String(form.get("query")), String(form.get("outcome"))).catch(
      () => setMessage("查询失败，请重试。"),
    );
  };

  const selectItem = (item: AuditReviewItem) => {
    if (!services.loadAuditItem) {
      setSelected(item);
      return;
    }
    void services
      .loadAuditItem(item.workItemId)
      .then(setSelected)
      .catch(() => setMessage("运单详情加载失败。"));
  };

  return (
    <section
      className={`history-workspace${selected ? " has-selection" : ""}`}
      aria-labelledby="history-title"
    >
      <h1 className="visually-hidden" id="history-title">历史数据</h1>
      <aside className="workspace-list-pane">
        <form className="history-search" onSubmit={submit}>
          <label>
            <span>运单号</span>
            <input name="query" />
          </label>
          <label>
            <span>业务结果</span>
            <select name="outcome">
              <option value="">全部</option>
              <option value="normal_ready">审核通过</option>
              <option value="awaiting_review">待核对</option>
              <option value="confirmed_problem">问题运单</option>
            </select>
          </label>
          <button className="button" type="submit">
            <Search aria-hidden="true" size={17} />
            查询运单
          </button>
        </form>
        <ul className="waybill-list">
          {items.map((item) => (
            <li key={item.workItemId}>
              <button
                type="button"
                aria-current={selected?.workItemId === item.workItemId}
                onClick={() => selectItem(item)}
              >
                <span className="waybill-list-main">
                  <strong>{item.waybillId}</strong>
                  <small>{item.vehicleNumber || "未记录车辆"}</small>
                </span>
                <span className={`status-text status-${item.businessOutcome}`}>
                  {outcomeLabels[item.businessOutcome ?? ""] ?? "技术问题"}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </aside>
      <div className="workspace-detail-pane">
        {message ? (
          <p className="inline-message" role="status">
            {message}
          </p>
        ) : null}
        {selected ? (
          <article className="history-detail">
            <button
              className="button mobile-back"
              type="button"
              onClick={() => setSelected(null)}
            >
              <ChevronLeft aria-hidden="true" size={18} />
              返回历史列表
            </button>
            <header className="detail-heading">
              <div className="title-row">
                <Clock3 aria-hidden="true" size={20} />
                <h2>{selected.waybillId}</h2>
              </div>
              <span className={`status-text status-${selected.businessOutcome}`}>
                {outcomeLabels[selected.businessOutcome ?? ""] ?? "技术问题"}
              </span>
            </header>
            <dl className="history-facts">
              <div>
                <dt>车辆</dt>
                <dd>{selected.vehicleNumber || "未记录"}</dd>
              </div>
              <div>
                <dt>装货磅单净重</dt>
                <dd>{selected.ticketLoadingNet ?? "未识别"}</dd>
              </div>
              <div>
                <dt>卸货磅单净重</dt>
                <dd>{selected.ticketUnloadingNet ?? "未识别"}</dd>
              </div>
              <div>
                <dt>记录版本</dt>
                <dd>{selected.recordVersion}</dd>
              </div>
            </dl>
            <section className="timeline" aria-labelledby="timeline-title">
              <h3 id="timeline-title">处理记录</h3>
              <ol>
                {selected.timeline.map((event) => (
                  <li key={event.eventId}>
                    <span aria-hidden="true" />
                    <div>
                      <strong>
                        {eventLabels[event.eventType] ?? event.eventType}
                      </strong>
                      <time dateTime={event.createdAt}>{event.createdAt}</time>
                    </div>
                  </li>
                ))}
              </ol>
              {selected.timeline.length === 0 ? (
                <p>当前没有可显示的处理记录。</p>
              ) : null}
            </section>
          </article>
        ) : (
          <div className="detail-empty">
            <History aria-hidden="true" size={28} />
            <h2>选择一条历史运单</h2>
          </div>
        )}
      </div>
    </section>
  );
}
