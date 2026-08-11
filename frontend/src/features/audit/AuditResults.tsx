import type { JobItem } from "../../app/contracts";

interface AuditResultsProps {
  items: JobItem[];
}

function weight(value: string | null): string {
  return value === null ? "尚未取得" : `${value} 吨`;
}

function reviewReasonLabel(reason: string | null): string | null {
  if (reason === "ticket_weight_format_suspicious") {
    return "磅单净重格式异常";
  }
  if (reason === "ocr_weight_disagreement") {
    return "两次识别的净重不一致";
  }
  return null;
}

function resultLabel(item: JobItem): string {
  const reviewLabel = reviewReasonLabel(item.reviewReason);
  if (reviewLabel !== null) {
    return reviewLabel;
  }
  if (
    item.decision === "pass" &&
    item.businessOutcome === "normal_ready" &&
    item.isTerminalOutcome
  ) {
    return "装货和卸货数字一致，影子审核已通过";
  }
  return "本条运单仍需处理";
}

export function AuditResults({ items }: AuditResultsProps) {
  if (items.length === 0) {
    return (
      <section className="audit-results" aria-labelledby="audit-results-title">
        <h2 id="audit-results-title">审核结果</h2>
        <p>本次审核没有可显示的运单结果。</p>
      </section>
    );
  }

  return (
    <section className="audit-results" aria-labelledby="audit-results-title">
      <div className="audit-results-heading">
        <div>
          <h2 id="audit-results-title">审核结果</h2>
          <p>以下结果来自本次影子审核，不会修改成丰和真实结算。</p>
        </div>
        <span className="result-count">共 {items.length} 条</span>
      </div>

      {items.map((item) => (
        <article
          className="audit-result-item"
          key={item.workItemId}
          aria-labelledby={`waybill-${item.workItemId}`}
        >
          <div className="result-summary">
            <div>
              <span>运单号</span>
              <strong id={`waybill-${item.workItemId}`}>
                {item.waybillNumber}
              </strong>
            </div>
            <div>
              <span>车辆</span>
              <strong>{item.vehicleNumber}</strong>
            </div>
          </div>

          <div className="weight-table-wrap">
            <table className="weight-table">
              <caption>平台与磅单重量核对</caption>
              <thead>
                <tr>
                  <th scope="col">业务位置</th>
                  <th scope="col">平台重量</th>
                  <th scope="col">磅单重量</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">装货</th>
                  <td>{weight(item.platformLoadingNet)}</td>
                  <td>{weight(item.ticketLoadingNet)}</td>
                </tr>
                <tr>
                  <th scope="row">卸货</th>
                  <td>{weight(item.platformUnloadingNet)}</td>
                  <td>{weight(item.ticketUnloadingNet)}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <p
            className={
              item.decision === "pass" ? "result-outcome passed" : "result-outcome"
            }
          >
            <span aria-hidden="true">{item.decision === "pass" ? "✓" : "!"}</span>
            <strong>{resultLabel(item)}</strong>
          </p>
        </article>
      ))}
    </section>
  );
}
