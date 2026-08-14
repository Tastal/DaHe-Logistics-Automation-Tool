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
