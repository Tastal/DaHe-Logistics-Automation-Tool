import { useEffect, useId, useMemo, useState } from "react";

import type { ServerAction } from "../../app/contracts";
import { Tooltip } from "../../components/Tooltip";

const actionOrder = [
  "view_results",
  "view_details",
  "review_items",
  "prepare_settlement",
  "pause",
  "resume",
  "cancel",
  "retry",
];

const knownActions = new Set(actionOrder);
const versionedActions = new Set(["pause", "resume", "cancel", "retry"]);

interface ActionBarProps {
  actions: Record<string, ServerAction>;
  jobName: string;
  scopeLabel: string;
  onAction: (
    actionId: string,
    expectedRecordVersion: number | null,
  ) => void;
  onContractError?: (actionId: string) => void;
  busyAction?: string | null;
}

export function ActionBar({
  actions,
  jobName,
  scopeLabel,
  onAction,
  onContractError,
  busyAction = null,
}: ActionBarProps) {
  const cancelTitleId = useId();
  const [pendingCancel, setPendingCancel] = useState<{
    label: string;
    expectedRecordVersion: number | null;
  } | null>(null);
  const invalidActions = useMemo(
    () =>
      Object.entries(actions)
        .filter(
          ([actionId, action]) =>
            !knownActions.has(actionId) ||
            (action.visible && !action.enabled && !action.reason) ||
            (action.visible &&
              versionedActions.has(actionId) &&
              action.expectedRecordVersion === null),
        )
        .map(([actionId]) => actionId),
    [actions],
  );

  useEffect(() => {
    invalidActions.forEach((actionId) => onContractError?.(actionId));
  }, [invalidActions, onContractError]);

  const entries = Object.entries(actions)
    .filter(([actionId, action]) => {
      return (
        knownActions.has(actionId) &&
        action.visible &&
        !invalidActions.includes(actionId)
      );
    })
    .sort(([left], [right]) => {
      return actionOrder.indexOf(left) - actionOrder.indexOf(right);
    });

  if (entries.length === 0) {
    return null;
  }

  return (
    <>
      <div className="action-bar" aria-label="任务操作">
        {entries.map(([actionId, action]) => (
          <div className="action-with-reason" key={actionId}>
            <Tooltip
              content={
                action.reason ??
                (busyAction !== null ? "请等待当前操作完成。" : action.label)
              }
              disabledControl={!action.enabled || busyAction !== null}
            >
              <button
                className={actionId === "cancel" ? "button secondary" : "button"}
                type="button"
                disabled={!action.enabled || busyAction !== null}
                onClick={() => {
                  if (actionId === "cancel") {
                    setPendingCancel({
                      label: action.label,
                      expectedRecordVersion: action.expectedRecordVersion,
                    });
                    return;
                  }
                  onAction(actionId, action.expectedRecordVersion);
                }}
              >
                {busyAction === actionId ? "正在提交…" : action.label}
              </button>
            </Tooltip>
          </div>
        ))}
      </div>
      {pendingCancel ? (
        <div
          className="dialog-backdrop"
          role="presentation"
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              setPendingCancel(null);
            }
          }}
        >
          <section
            aria-labelledby={cancelTitleId}
            aria-modal="true"
            className="confirmation-dialog"
            role="dialog"
          >
            <p className="dialog-eyebrow">请确认操作</p>
            <h2 id={cancelTitleId}>确认取消任务</h2>
            <p>
              您将取消“{jobName}”。
            </p>
            <dl>
              <div>
                <dt>业务范围</dt>
                <dd>{scopeLabel}</dd>
              </div>
            </dl>
            <p className="dialog-note">
              已经完成的证据和结果会保留，尚未处理的项目不会继续。
            </p>
            <div className="dialog-actions">
              <button
                autoFocus
                className="button"
                type="button"
                onClick={() => setPendingCancel(null)}
              >
                返回任务
              </button>
              <button
                className="button primary"
                type="button"
                onClick={() => {
                  const version = pendingCancel.expectedRecordVersion;
                  setPendingCancel(null);
                  onAction("cancel", version);
                }}
              >
                确认{pendingCancel.label}
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}

export type { ServerAction };
