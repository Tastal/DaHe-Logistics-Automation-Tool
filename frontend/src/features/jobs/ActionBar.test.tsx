import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ActionBar, type ServerAction } from "./ActionBar";

describe("ActionBar", () => {
  it("renders only actions that the backend marks visible", async () => {
    const user = userEvent.setup();
    const onAction = vi.fn();
    const actions: Record<string, ServerAction> = {
      pause: {
        visible: false,
        enabled: false,
        reason: null,
        label: "暂停此审核任务",
        expectedRecordVersion: 4,
      },
      cancel: {
        visible: true,
        enabled: true,
        reason: null,
        label: "取消本次审核",
        expectedRecordVersion: 4,
      },
    };

    render(
      <ActionBar
        actions={actions}
        jobName="上午运单审核"
        scopeLabel="2026-07-25 上午批次"
        onAction={onAction}
      />,
    );

    expect(screen.queryByRole("button", { name: "暂停此审核任务" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "取消本次审核" }));
    expect(onAction).not.toHaveBeenCalled();
    expect(
      screen.getByRole("dialog", { name: "确认取消任务" }),
    ).toHaveTextContent("上午运单审核");
    expect(screen.getByRole("dialog")).toHaveTextContent(
      "2026-07-25 上午批次",
    );
    expect(screen.getByRole("dialog")).toHaveTextContent(
      "已经完成的证据和结果会保留，尚未处理的项目不会继续",
    );
    await user.click(
      screen.getByRole("button", { name: "确认取消本次审核" }),
    );
    expect(onAction).toHaveBeenCalledWith("cancel", 4);
  });

  it("exposes a backend-supplied disabled reason through focus", async () => {
    render(
      <ActionBar
        actions={{
          prepare_settlement: {
            visible: true,
            enabled: false,
            reason: "还有 3 条运单等待人工处理",
            label: "准备结算清单",
            expectedRecordVersion: 8,
          },
        }}
        jobName="上午运单审核"
        scopeLabel="2026-07-25 上午批次"
        onAction={vi.fn()}
      />,
    );

    const button = screen.getByRole("button", { name: "准备结算清单" });
    expect(button).toBeDisabled();
    const anchor = button.closest<HTMLElement>(".tooltip-anchor");
    expect(anchor).not.toBeNull();
    anchor?.focus();
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "还有 3 条运单等待人工处理",
    );
  });

  it("treats a disabled action without a reason as a contract error", () => {
    const onContractError = vi.fn();

    render(
      <ActionBar
        actions={{
          pause: {
            visible: true,
            enabled: false,
            reason: null,
            label: "暂停此审核任务",
            expectedRecordVersion: 2,
          },
        }}
        jobName="上午运单审核"
        scopeLabel="2026-07-25 上午批次"
        onAction={vi.fn()}
        onContractError={onContractError}
      />,
    );

    expect(screen.queryByRole("button", { name: "暂停此审核任务" })).toBeNull();
    expect(onContractError).toHaveBeenCalledWith("pause");
  });
});
