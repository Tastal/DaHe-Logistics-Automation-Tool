import { Gauge, RotateCcw, Save } from "lucide-react";
import { useEffect, useState } from "react";

import type { AppServices, PerformanceSettings, PerformancePreset } from "../../app/contracts";
import { Tooltip } from "../../components/Tooltip";
import { useToast } from "../../components/ToastContext";

const defaults: Record<PerformancePreset, Omit<PerformanceSettings, "recordVersion">> = {
  responsive: { preset: "responsive", detailConcurrency: 2, imageConcurrency: 3, networkBatchSize: 50, cpuOcrThreads: 4, gpuIdleMinutes: 10, keepGpuReady: false },
  balanced: { preset: "balanced", detailConcurrency: 3, imageConcurrency: 4, networkBatchSize: 50, cpuOcrThreads: 4, gpuIdleMinutes: 30, keepGpuReady: false },
  speed: { preset: "speed", detailConcurrency: 4, imageConcurrency: 6, networkBatchSize: 50, cpuOcrThreads: 4, gpuIdleMinutes: 0, keepGpuReady: true },
};

const PRESET_HELP: Record<PerformancePreset, string> = {
  responsive: "推荐日常使用。让操作台保持流畅，采集速度稍保守。",
  balanced: "适合电脑空闲时使用。速度更快，同时保留一定操作余量。",
  speed: "只建议电脑无人操作时使用。采集最快，但会占用更多网络和系统资源。",
};

const maxCpuThreads = Math.max(
  1,
  Math.min(8, (navigator.hardwareConcurrency || 4) - 2),
);

export function PerformanceSettingsPanel({ services }: { services: AppServices }) {
  const { showToast } = useToast();
  const [settings, setSettings] = useState<PerformanceSettings | null>(null);
  useEffect(() => { void services.loadPerformanceSettings?.().then(setSettings); }, [services]);
  if (!services.loadPerformanceSettings || !services.savePerformanceSettings || !settings) return null;
  const setPreset = (preset: PerformancePreset) => setSettings({ ...defaults[preset], recordVersion: settings.recordVersion });
  const save = async () => {
    try { setSettings(await services.savePerformanceSettings!(settings)); showToast("性能设置已保存，将用于新任务。", "success"); }
    catch (error) { showToast(error instanceof Error ? error.message : "性能设置保存失败。", "error"); }
  };
  return (
    <section className="settings-section" aria-labelledby="performance-title">
      <div className="compact-section-heading"><div className="title-row"><Gauge aria-hidden="true" size={18} /><h2 id="performance-title">性能设置</h2></div></div>
      <div className="preset-row" role="group" aria-label="性能模式">
        {(["responsive", "balanced", "speed"] as PerformancePreset[]).map((preset) => <Tooltip key={preset} content={PRESET_HELP[preset]}><button className="button" aria-pressed={settings.preset === preset} type="button" onClick={() => setPreset(preset)}>{preset === "responsive" ? "响应优先" : preset === "balanced" ? "平衡模式" : "速度优先"}</button></Tooltip>)}
      </div>
      <details className="advanced-settings"><summary>高级设置</summary><div className="performance-grid">
        <Tooltip content="同时读取几条运单详情。推荐 2；调大可能更快，也更占网络和平台资源。"><label>详情并发<input type="number" min="1" max="4" value={settings.detailConcurrency} onChange={(event) => setSettings({ ...settings, detailConcurrency: Number(event.target.value) })} /></label></Tooltip>
        <Tooltip content="同时下载几张磅单。推荐 3；调大会加快下载，但更容易让电脑和网络变卡。"><label>图片并发<input type="number" min="1" max="6" value={settings.imageConcurrency} onChange={(event) => setSettings({ ...settings, imageConcurrency: Number(event.target.value) })} /></label></Tooltip>
        <Tooltip content="显卡不可用时，CPU 同时使用多少线程识别。推荐 4；调大会占用更多处理器。"><label>CPU 识别线程<input type="number" min="1" max={maxCpuThreads} value={settings.cpuOcrThreads} onChange={(event) => setSettings({ ...settings, cpuOcrThreads: Number(event.target.value) })} /></label></Tooltip>
        <Tooltip content="没有识别任务多久后释放显存。推荐 10 分钟；时间越长，下次启动越快，但显存占用越久。"><label>显卡空闲释放（分钟）<input type="number" min="1" max="60" disabled={settings.keepGpuReady} value={settings.gpuIdleMinutes || 10} onChange={(event) => setSettings({ ...settings, gpuIdleMinutes: Number(event.target.value) })} /></label></Tooltip>
        <Tooltip content="持续占用显存以缩短下次识别启动时间。只建议速度优先且电脑无人操作时开启。"><label className="checkbox-field"><input type="checkbox" checked={settings.keepGpuReady} onChange={(event) => setSettings({ ...settings, keepGpuReady: event.target.checked })} />保持显卡就绪</label></Tooltip>
      </div></details>
      <div className="compact-actions"><button className="button primary" type="button" onClick={() => void save()}><Save aria-hidden="true" size={17} />保存设置</button><button className="button" type="button" onClick={() => setPreset("responsive")}><RotateCcw aria-hidden="true" size={17} />恢复推荐设置</button></div>
    </section>
  );
}
