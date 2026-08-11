import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { Tooltip } from "./Tooltip";

describe("Tooltip", () => {
  it("opens from keyboard focus and closes with Escape", async () => {
    const user = userEvent.setup();
    render(
      <Tooltip content="说明内容">
        <button type="button">操作</button>
      </Tooltip>,
    );

    await user.tab();
    expect(await screen.findByRole("tooltip")).toHaveTextContent("说明内容");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("makes a disabled control reason keyboard readable", async () => {
    const user = userEvent.setup();
    render(
      <Tooltip content="等待当前步骤完成" disabledControl>
        <button type="button" disabled>
          暂停
        </button>
      </Tooltip>,
    );

    await user.tab();
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "等待当前步骤完成",
    );
  });
});
