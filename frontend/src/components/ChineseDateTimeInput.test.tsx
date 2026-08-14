import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { ChineseDateTimeInput } from "./ChineseDateTimeInput";

function ControlledInput({ includeSeconds = false }: { includeSeconds?: boolean }) {
  const [value, setValue] = useState("");
  return (
    <ChineseDateTimeInput
      value={value}
      includeSeconds={includeSeconds}
      prefillDate="2026-08-09"
      onChange={setValue}
    />
  );
}

describe("Chinese segmented date time input", () => {
  it("keeps the date and time segments on separate rows", () => {
    render(<ControlledInput includeSeconds />);

    const group = screen.getByRole("group", { name: "年月日时分秒" });
    const dateRow = group.querySelector(".segmented-datetime-date");
    const timeRow = group.querySelector(".segmented-datetime-time");

    expect(dateRow).not.toBeNull();
    expect(timeRow).not.toBeNull();
    expect(within(dateRow as HTMLElement).getByLabelText("年")).toBeVisible();
    expect(within(dateRow as HTMLElement).getByLabelText("月")).toBeVisible();
    expect(within(dateRow as HTMLElement).getByLabelText("日")).toBeVisible();
    expect(within(dateRow as HTMLElement).queryByLabelText("时")).toBeNull();
    expect(within(timeRow as HTMLElement).getByLabelText("时")).toBeVisible();
    expect(within(timeRow as HTMLElement).getByLabelText("分")).toBeVisible();
    expect(within(timeRow as HTMLElement).getByLabelText("秒")).toBeVisible();
  });

  it("uses compact Chinese placeholders and prefills only the date", () => {
    render(<ControlledInput />);

    expect(screen.getByLabelText("年")).toHaveValue("2026");
    expect(screen.getByLabelText("月")).toHaveValue("08");
    expect(screen.getByLabelText("日")).toHaveValue("09");
    expect(screen.getByLabelText("时")).toHaveValue("");
    expect(screen.getByLabelText("分")).toHaveValue("");
    expect(screen.queryByLabelText("秒")).toBeNull();
    expect(screen.getByLabelText("时")).toHaveAttribute("placeholder", "时");
  });

  it("pads an unambiguous single digit and rejects an invalid calendar day", async () => {
    render(<ControlledInput />);
    const user = userEvent.setup();
    const month = screen.getByLabelText("月");
    await user.clear(month);
    await user.type(month, "8");
    expect(month).toHaveValue("08");
    expect(screen.getByLabelText("日")).toHaveFocus();

    const day = screen.getByLabelText("日");
    await user.clear(day);
    await user.type(day, "32");
    expect(day).toHaveValue("32");
    expect(day).toHaveAttribute("aria-invalid", "true");
  });

  it("advances after a complete field and accepts a full Chinese timestamp paste", async () => {
    render(<ControlledInput includeSeconds />);
    const user = userEvent.setup();
    const hour = screen.getByLabelText("时");
    await user.click(hour);
    await user.type(hour, "07");
    expect(screen.getByLabelText("分")).toHaveFocus();

    await user.click(screen.getByLabelText("年"));
    await user.paste("2026年08月09日07时44分35秒");
    expect(screen.getByLabelText("时")).toHaveValue("07");
    expect(screen.getByLabelText("分")).toHaveValue("44");
    expect(screen.getByLabelText("秒")).toHaveValue("35");
  });
});
