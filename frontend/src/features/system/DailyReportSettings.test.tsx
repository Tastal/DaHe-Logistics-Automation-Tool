import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AppServices, DailyReportSettings } from "../../app/contracts";
import { ToastProvider } from "../../components/Toast";
import { DailyReportSettingsPanel } from "./DailyReportSettings";

const settings: DailyReportSettings = {
  shippingMine: "Test mine",
  coalType: "Test coal",
  unloadingPlace: "Test place",
  queryPlaceKeyword: "Test keyword",
  outputDirectory: "C:/reports",
  confirmed: true,
  recordVersion: 4,
  captureStartTime: "14:00",
  captureEndMode: "system_current_time",
  captureFixedEndDayOffset: 1,
  captureFixedEndTime: "14:30",
  captureRangeCoversReportWindow: true,
};

function renderPanel(services: Partial<AppServices>) {
  render(
    <ToastProvider>
      <DailyReportSettingsPanel services={services as AppServices} />
    </ToastProvider>,
  );
}

describe("Daily report settings", () => {
  it("saves a versioned frozen capture range", async () => {
    const user = userEvent.setup();
    const saveDailyReportSettings = vi.fn().mockResolvedValue({
      ...settings,
      recordVersion: 5,
      captureStartTime: "13:45",
      captureEndMode: "fixed_time",
      captureFixedEndDayOffset: 1,
      captureFixedEndTime: "14:15",
    });
    renderPanel({
      loadDailyReportSettings: vi.fn().mockResolvedValue(settings),
      saveDailyReportSettings,
    });

    await user.clear(await screen.findByLabelText("开始时间"));
    await user.type(screen.getByLabelText("开始时间"), "13:45");
    await user.selectOptions(screen.getByLabelText("结束方式"), "fixed_time");
    await user.selectOptions(screen.getByLabelText("固定日期"), "1");
    await user.clear(screen.getByLabelText("固定时间"));
    await user.type(screen.getByLabelText("固定时间"), "14:15");
    await user.click(screen.getByRole("button", { name: "保存设置" }));

    await waitFor(() => expect(saveDailyReportSettings).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedRecordVersion: 4,
        captureStartTime: "13:45",
        captureEndMode: "fixed_time",
        captureFixedEndDayOffset: 1,
        captureFixedEndTime: "14:15",
      }),
    ));
  });

  it("warns when the configured range cannot cover the report window", async () => {
    const user = userEvent.setup();
    renderPanel({
      loadDailyReportSettings: vi.fn().mockResolvedValue(settings),
      saveDailyReportSettings: vi.fn(),
    });

    await user.clear(await screen.findByLabelText("开始时间"));
    await user.type(screen.getByLabelText("开始时间"), "14:30");

    expect(screen.getByRole("status")).toHaveTextContent(
      "当前下载范围可能未覆盖完整报表窗口",
    );
  });
});
