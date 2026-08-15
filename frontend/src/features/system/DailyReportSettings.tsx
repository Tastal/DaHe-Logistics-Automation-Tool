import { FileSpreadsheet, Save } from "lucide-react";
import { useEffect, useState } from "react";

import type { AppServices, DailyReportSettings } from "../../app/contracts";
import { Tooltip } from "../../components/Tooltip";
import { useToast } from "../../components/ToastContext";

export function DailyReportSettingsPanel({ services }: { services: AppServices }) {
  const [settings, setSettings] = useState<DailyReportSettings | null>(null);
  const [busy, setBusy] = useState(false);
  const { showToast } = useToast();

  useEffect(() => {
    if (!services.loadDailyReportSettings) return;
    let active = true;
    void services.loadDailyReportSettings().then(
      (value) => {
        if (active) setSettings(value);
      },
      () => {
        if (active) showToast("报表设置读取失败。", "error");
      },
    );
    return () => {
      active = false;
    };
  }, [services, showToast]);

  if (!services.loadDailyReportSettings || !services.saveDailyReportSettings) {
    return null;
  }

  const update = (field: keyof DailyReportSettings, value: string) => {
    setSettings((current) => (current ? { ...current, [field]: value } : current));
  };

  const save = async () => {
    if (!settings) return;
    setBusy(true);
    try {
      const next = await services.saveDailyReportSettings!({
        shippingMine: settings.shippingMine.trim(),
        coalType: settings.coalType.trim(),
        unloadingPlace: settings.unloadingPlace.trim(),
        queryPlaceKeyword: settings.queryPlaceKeyword.trim(),
        outputDirectory: settings.outputDirectory.trim(),
        confirmed: true,
        expectedRecordVersion: settings.recordVersion,
        captureStartTime: settings.captureStartTime,
        captureEndMode: settings.captureEndMode,
        captureFixedEndDayOffset: settings.captureFixedEndDayOffset,
        captureFixedEndTime: settings.captureFixedEndTime,
      });
      setSettings(next);
      showToast("报表设置已保存。", "success");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "报表设置保存失败。", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="settings-section" aria-labelledby="daily-report-settings-title">
      <div className="compact-section-heading">
        <div className="title-row">
          <FileSpreadsheet aria-hidden="true" size={20} />
          <h2 id="daily-report-settings-title">装卸车报表</h2>
        </div>
      </div>
      {settings ? (
        <form
          className="report-settings-form"
          onSubmit={(event) => {
            event.preventDefault();
            void save();
          }}
        >
          <label><span>发运煤矿</span><input value={settings.shippingMine} onChange={(event) => update("shippingMine", event.target.value)} /></label>
          <label><span>煤种</span><input value={settings.coalType} onChange={(event) => update("coalType", event.target.value)} /></label>
          <label><span>卸货地点</span><input value={settings.unloadingPlace} onChange={(event) => update("unloadingPlace", event.target.value)} /></label>
          <label><span>查询地点关键词</span><input value={settings.queryPlaceKeyword} onChange={(event) => update("queryPlaceKeyword", event.target.value)} /></label>
          <label className="report-output-field"><span>输出目录</span><input value={settings.outputDirectory} onChange={(event) => update("outputDirectory", event.target.value)} /></label>
          <fieldset className="capture-range-settings">
            <legend>平台下载范围</legend>
            <label>
              <span>开始时间</span>
              <input type="time" value={settings.captureStartTime} onChange={(event) => update("captureStartTime", event.target.value)} />
            </label>
            <label>
              <span>结束方式</span>
              <select
                value={settings.captureEndMode}
                onChange={(event) => setSettings((current) => current ? { ...current, captureEndMode: event.target.value as DailyReportSettings["captureEndMode"] } : current)}
              >
                <option value="system_current_time">系统当前时间</option>
                <option value="fixed_time">固定时间</option>
              </select>
            </label>
            {settings.captureEndMode === "fixed_time" ? (
              <>
                <label>
                  <span>固定日期</span>
                  <select
                    value={settings.captureFixedEndDayOffset}
                    onChange={(event) => setSettings((current) => current ? { ...current, captureFixedEndDayOffset: Number(event.target.value) as 0 | 1 } : current)}
                  >
                    <option value={0}>当天</option>
                    <option value={1}>次日</option>
                  </select>
                </label>
                <label>
                  <span>固定时间</span>
                  <input type="time" value={settings.captureFixedEndTime} onChange={(event) => update("captureFixedEndTime", event.target.value)} />
                </label>
              </>
            ) : null}
            {(
              settings.captureStartTime > "14:00"
              || (
                settings.captureEndMode === "fixed_time"
                && (
                  settings.captureFixedEndDayOffset !== 1
                  || settings.captureFixedEndTime < "14:00"
                )
              )
            ) ? (
              <p className="capture-range-warning" role="status">当前下载范围可能未覆盖完整报表窗口（14:00 至次日 14:00）。</p>
            ) : null}
          </fieldset>
          <div className="compact-actions">
            <Tooltip content="保存后用于生成正式装卸车报表。">
              <button
                className="button primary"
                type="submit"
                disabled={busy || !settings.shippingMine.trim() || !settings.coalType.trim() || !settings.unloadingPlace.trim() || !settings.queryPlaceKeyword.trim() || !settings.outputDirectory.trim()}
              >
                <Save aria-hidden="true" size={17} />
                {busy ? "正在保存" : "保存设置"}
              </button>
            </Tooltip>
          </div>
        </form>
      ) : null}
    </section>
  );
}
