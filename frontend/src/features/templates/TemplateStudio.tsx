import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";

import {
  TemplateMaintenanceRequiredError,
  type AppServices,
} from "../../app/contracts";
import type {
  NormalizedBounds,
  TemplateAction,
  TemplateAnchor,
  TemplateDraft,
  TemplateFamilyIndex,
  TemplateReferenceImage,
  TemplateRegion,
  TemplateRole,
  TemplateRollbackOptions,
  TemplateVersionSnapshot,
  StagedTemplateReference,
} from "../../api/templateContracts";
import {
  clearTemplateCreationRecovery,
  readTemplateCreationRecovery,
  writeTemplateCreationRecovery,
  type TemplateCreationRecovery,
  type TemplateStudioStep,
} from "./templateRecovery";

interface TemplateStudioProps {
  services: AppServices;
  onBack: () => void;
}

type StudioStep = TemplateStudioStep;

const MIN_BOX_SIZE = 0.04;
const KEYBOARD_BOX_STEP = 0.001;
const TEMPORARY_ANCHOR_TEXT = "请替换为票面固定文字";
const DEFAULT_BOX_BOUNDS: NormalizedBounds = {
  x: 0.1,
  y: 0.1,
  width: 0.2,
  height: 0.08,
};

const supportedActions = new Set([
  "save_draft",
  "run_development_check",
  "start_shadow",
  "restore_shadow",
]);

function emptyTemplateDraft(): TemplateDraft {
  return {
    anchors: [],
    regions: [],
  };
}

function hasCompleteAnchorText(draft: TemplateDraft): boolean {
  return (
    draft.anchors.length > 0 &&
    draft.anchors.every(
      (anchor) =>
        anchor.expectedText.trim().length > 0 &&
        anchor.expectedText !== TEMPORARY_ANCHOR_TEXT,
    )
  );
}

function cloneDraft(draft: TemplateDraft): TemplateDraft {
  return {
    anchors: draft.anchors.map((anchor) => ({
      ...anchor,
      bounds: { ...anchor.bounds },
    })),
    regions: draft.regions.map((region) => ({
      ...region,
      bounds: { ...region.bounds },
    })),
  };
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

function stableNormalizedValue(value: number): number {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function nudgeBounds(
  bounds: NormalizedBounds,
  key: string,
  resize: boolean,
): NormalizedBounds {
  const next = { ...bounds };
  if (resize) {
    if (key === "ArrowLeft") {
      next.width = clamp(
        bounds.width - KEYBOARD_BOX_STEP,
        MIN_BOX_SIZE,
        1 - bounds.x,
      );
    } else if (key === "ArrowRight") {
      next.width = clamp(
        bounds.width + KEYBOARD_BOX_STEP,
        MIN_BOX_SIZE,
        1 - bounds.x,
      );
    } else if (key === "ArrowUp") {
      next.height = clamp(
        bounds.height - KEYBOARD_BOX_STEP,
        MIN_BOX_SIZE,
        1 - bounds.y,
      );
    } else if (key === "ArrowDown") {
      next.height = clamp(
        bounds.height + KEYBOARD_BOX_STEP,
        MIN_BOX_SIZE,
        1 - bounds.y,
      );
    }
    return {
      x: stableNormalizedValue(next.x),
      y: stableNormalizedValue(next.y),
      width: stableNormalizedValue(next.width),
      height: stableNormalizedValue(next.height),
    };
  }
  if (key === "ArrowLeft") {
    next.x = clamp(bounds.x - KEYBOARD_BOX_STEP, 0, 1 - bounds.width);
  } else if (key === "ArrowRight") {
    next.x = clamp(bounds.x + KEYBOARD_BOX_STEP, 0, 1 - bounds.width);
  } else if (key === "ArrowUp") {
    next.y = clamp(bounds.y - KEYBOARD_BOX_STEP, 0, 1 - bounds.height);
  } else if (key === "ArrowDown") {
    next.y = clamp(bounds.y + KEYBOARD_BOX_STEP, 0, 1 - bounds.height);
  }
  return {
    x: stableNormalizedValue(next.x),
    y: stableNormalizedValue(next.y),
    width: stableNormalizedValue(next.width),
    height: stableNormalizedValue(next.height),
  };
}

interface NormalizedPoint {
  x: number;
  y: number;
}

interface DrawGesture {
  pointerId: number;
  start: NormalizedPoint;
  current: NormalizedPoint;
}

function pointInLayer(
  event: ReactPointerEvent<HTMLDivElement>,
): NormalizedPoint | null {
  const rectangle = event.currentTarget.getBoundingClientRect();
  if (rectangle.width <= 0 || rectangle.height <= 0) {
    return null;
  }
  return {
    x: clamp((event.clientX - rectangle.left) / rectangle.width, 0, 1),
    y: clamp((event.clientY - rectangle.top) / rectangle.height, 0, 1),
  };
}

function boundsBetween(
  start: NormalizedPoint,
  end: NormalizedPoint,
): NormalizedBounds {
  return {
    x: stableNormalizedValue(Math.min(start.x, end.x)),
    y: stableNormalizedValue(Math.min(start.y, end.y)),
    width: stableNormalizedValue(Math.abs(end.x - start.x)),
    height: stableNormalizedValue(Math.abs(end.y - start.y)),
  };
}

function nextItemId(
  prefix: "anchor" | "region",
  existingIds: string[],
): string {
  const maximum = existingIds.reduce((current, itemId) => {
    const match = new RegExp(`^${prefix}-(\\d+)$`).exec(itemId);
    return match ? Math.max(current, Number(match[1])) : current;
  }, 0);
  return `${prefix}-${maximum + 1}`;
}

function boxStyle(bounds: NormalizedBounds): CSSProperties {
  return {
    left: `${bounds.x * 100}%`,
    top: `${bounds.y * 100}%`,
    width: `${bounds.width * 100}%`,
    height: `${bounds.height * 100}%`,
  };
}

function MaintenanceGate({
  index,
  busy,
  error,
  onUnlock,
}: {
  index: TemplateFamilyIndex;
  busy: boolean;
  error: string | null;
  onUnlock: (accessCode: string) => void;
}) {
  const [accessCode, setAccessCode] = useState("");

  return (
    <section className="template-gate" aria-labelledby="template-gate-title">
      <div>
        <h2 id="template-gate-title">模板只能由已授权的维护人员修改。</h2>
        <p>
          财务人员可以查看模板状态；框选、检查和影子版本切换需要维护验证。
        </p>
      </div>
      <div className="template-gate-form">
        <label htmlFor="template-access-code">维护验证码</label>
        <input
          id="template-access-code"
          role="textbox"
          type="password"
          autoComplete="off"
          value={accessCode}
          onChange={(event) => setAccessCode(event.currentTarget.value)}
        />
        <button
          className="button primary"
          type="button"
          disabled={busy}
          onClick={() => onUnlock(accessCode)}
        >
          {busy ? "正在验证…" : "进入维护模式"}
        </button>
        {error ? (
          <p className="template-error" role="alert">
            {error}
          </p>
        ) : null}
      </div>
      <p className="template-access-status">{index.maintenance.statusLabel}</p>
    </section>
  );
}

function TemplateSteps({
  step,
  onChange,
}: {
  step: StudioStep;
  onChange: (step: StudioStep) => void;
}) {
  return (
    <nav className="template-steps" aria-label="模板制作步骤">
      <button
        type="button"
        aria-label="1 标出固定内容"
        aria-current={step === "anchors" ? "step" : undefined}
        onClick={() => onChange("anchors")}
      >
        <span>1</span>
        标出固定内容
      </button>
      <button
        type="button"
        aria-label="2 标出要读取的内容"
        aria-current={step === "regions" ? "step" : undefined}
        onClick={() => onChange("regions")}
      >
        <span>2</span>
        标出要读取的内容
      </button>
    </nav>
  );
}

function AnchorProperties({
  anchor,
  onChange,
}: {
  anchor: TemplateAnchor;
  onChange: (anchor: TemplateAnchor) => void;
}) {
  return (
    <div className="template-property-fields">
      <label>
        票面固定文字
        <input
          aria-describedby={
            anchor.expectedText === TEMPORARY_ANCHOR_TEXT
              ? "temporary-anchor-text-warning"
              : undefined
          }
          value={anchor.expectedText}
          onChange={(event) =>
            onChange({
              ...anchor,
              label: event.currentTarget.value,
              expectedText: event.currentTarget.value,
            })
          }
        />
      </label>
      {anchor.expectedText === TEMPORARY_ANCHOR_TEXT ? (
        <p
          className="template-field-warning"
          id="temporary-anchor-text-warning"
          role="status"
        >
          这是临时文字，保存前请替换为票面上的实际固定内容。
        </p>
      ) : null}
      <p className="template-keyboard-hint">
        方向键移动框，Shift 加方向键调整大小，按 Delete 删除。
      </p>
    </div>
  );
}

function RegionProperties({
  region,
  anchors,
  onChange,
}: {
  region: TemplateRegion;
  anchors: TemplateAnchor[];
  onChange: (region: TemplateRegion) => void;
}) {
  const changeField = (field: TemplateRegion["field"]) => {
    const businessDefaults: Record<
      TemplateRegion["field"],
      Pick<TemplateRegion, "label" | "valueType" | "unit">
    > = {
      ordinary_net_weight: {
        label: "普通净重",
        valueType: "weight",
        unit: "ton",
      },
      factory_net_weight: {
        label: "工厂净重",
        valueType: "weight",
        unit: "ton",
      },
      gross_weight: {
        label: "毛重",
        valueType: "weight",
        unit: "ton",
      },
      tare_weight: {
        label: "皮重",
        valueType: "weight",
        unit: "ton",
      },
      loading_weigh_time: {
        label: "装货过磅时间",
        valueType: "time",
        unit: "printed",
      },
      unloading_tare_time: {
        label: "卸货皮重时间",
        valueType: "time",
        unit: "printed",
      },
      print_time: {
        label: "打印时间",
        valueType: "time",
        unit: "printed",
      },
    };
    onChange({ ...region, field, ...businessDefaults[field] });
  };

  return (
    <div className="template-property-fields">
      <label>
        业务字段
        <select
          value={region.field}
          onChange={(event) =>
            changeField(event.currentTarget.value as TemplateRegion["field"])
          }
        >
          <option value="ordinary_net_weight">普通净重</option>
          <option value="factory_net_weight">工厂净重</option>
          <option value="gross_weight">毛重</option>
          <option value="tare_weight">皮重</option>
          <option value="loading_weigh_time">装货过磅时间</option>
          <option value="unloading_tare_time">卸货皮重时间</option>
          <option value="print_time">打印时间</option>
        </select>
      </label>
      <label>
        单位
        <select
          value={region.unit}
          disabled={region.valueType === "time"}
          onChange={(event) =>
            onChange({
              ...region,
              unit: event.currentTarget.value as TemplateRegion["unit"],
            })
          }
        >
          {region.valueType === "time" ? (
            <option value="printed">按票面时间读取</option>
          ) : (
            <>
              <option value="ton">吨</option>
              <option value="kilogram">千克</option>
            </>
          )}
        </select>
      </label>
      <label>
        参照的固定内容
        <select
          value={region.anchorId}
          onChange={(event) =>
            onChange({ ...region, anchorId: event.currentTarget.value })
          }
        >
          {anchors.map((anchor) => (
            <option key={anchor.anchorId} value={anchor.anchorId}>
              {anchor.label}
            </option>
          ))}
        </select>
      </label>
      <p className="template-keyboard-hint">
        每项内容单独保存。方向键移动框，Shift 加方向键调整大小，按
        Delete 删除。
      </p>
    </div>
  );
}

function ShadowConfirmation({
  accessCode,
  busy,
  error,
  onAccessCodeChange,
  onCancel,
  onConfirm,
}: {
  accessCode: string;
  busy: boolean;
  error: string | null;
  onAccessCodeChange: (accessCode: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  return (
    <section
      className="template-shadow-confirmation"
      aria-labelledby="template-shadow-confirmation-title"
      aria-live="polite"
    >
      <div>
        <h2
          id="template-shadow-confirmation-title"
          ref={headingRef}
          tabIndex={-1}
        >
          确认开始影子测试
        </h2>
        <p>
          <strong>只读影子，不影响成丰和真实结算。</strong>
          这一步只切换本地模板的影子测试版本。
        </p>
      </div>
      <label htmlFor="template-shadow-access-code">
        再次输入维护验证码
        <input
          id="template-shadow-access-code"
          type="password"
          autoComplete="off"
          value={accessCode}
          onChange={(event) =>
            onAccessCodeChange(event.currentTarget.value)
          }
        />
      </label>
      <div className="template-shadow-confirmation-actions">
        <button
          className="button primary"
          type="button"
          disabled={busy}
          onClick={onConfirm}
        >
          {busy ? "正在验证并切换…" : "确认开始影子测试"}
        </button>
        <button
          className="button"
          type="button"
          disabled={busy}
          onClick={onCancel}
        >
          取消
        </button>
      </div>
      {error ? (
        <p className="template-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}

function RollbackConfirmation({
  options,
  targetVersionId,
  reason,
  accessCode,
  busy,
  error,
  onTargetChange,
  onReasonChange,
  onAccessCodeChange,
  onCancel,
  onConfirm,
}: {
  options: TemplateRollbackOptions;
  targetVersionId: string;
  reason: string;
  accessCode: string;
  busy: boolean;
  error: string | null;
  onTargetChange: (versionId: string) => void;
  onReasonChange: (reason: string) => void;
  onAccessCodeChange: (accessCode: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const rollbackTargets = options.versions.filter(
    (version) => version.canRollback,
  );

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  return (
    <section
      className="template-shadow-confirmation"
      aria-labelledby="template-rollback-confirmation-title"
      aria-live="polite"
    >
      <div>
        <h2
          id="template-rollback-confirmation-title"
          ref={headingRef}
          tabIndex={-1}
        >
          确认恢复影子版本
        </h2>
        <p>
          <strong>只切换本地影子模板，不修改成丰数据。</strong>
          请选择已经通过检查的较早版本，并记录恢复原因。
        </p>
      </div>
      <label htmlFor="template-rollback-target">
        恢复到
        <select
          id="template-rollback-target"
          value={targetVersionId}
          disabled={busy}
          onChange={(event) => onTargetChange(event.currentTarget.value)}
        >
          <option value="">请选择影子版本</option>
          {rollbackTargets.map((version) => (
            <option key={version.versionId} value={version.versionId}>
              {version.label}
            </option>
          ))}
        </select>
      </label>
      <label htmlFor="template-rollback-reason">
        恢复原因
        <input
          id="template-rollback-reason"
          value={reason}
          disabled={busy}
          onChange={(event) => onReasonChange(event.currentTarget.value)}
        />
      </label>
      <label htmlFor="template-rollback-access-code">
        再次输入维护验证码
        <input
          id="template-rollback-access-code"
          type="password"
          autoComplete="off"
          value={accessCode}
          disabled={busy}
          onChange={(event) =>
            onAccessCodeChange(event.currentTarget.value)
          }
        />
      </label>
      <div className="template-shadow-confirmation-actions">
        <button
          className="button primary"
          type="button"
          disabled={busy}
          onClick={onConfirm}
        >
          {busy ? "正在验证并恢复…" : "确认恢复影子版本"}
        </button>
        <button
          className="button"
          type="button"
          disabled={busy}
          onClick={onCancel}
        >
          取消
        </button>
      </div>
      {error ? (
        <p className="template-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}

function QualityReport({
  report,
}: {
  report: TemplateVersionSnapshot["checkReport"];
}) {
  if (report === null) {
    return null;
  }
  return (
    <section
      className="template-quality-report"
      aria-labelledby="template-quality-title"
    >
      <div className="template-report-heading">
        <h2 id="template-quality-title">开发样本检查</h2>
        <p>{report.summaryLabel}</p>
      </div>
      <div className="template-report-context">
        <p>{report.scopeLabel}</p>
        <p className="template-report-warning">{report.warning}</p>
      </div>
      <dl>
        {report.metrics.map((metric) => (
          <div key={metric.metricId}>
            <dt>{metric.label}</dt>
            <dd>{metric.valueLabel}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function ReferenceEditor({
  referenceImage,
  draft,
  step,
  selectedAnchorId,
  selectedRegionId,
  onSelectAnchor,
  onSelectRegion,
  onDraftChange,
}: {
  referenceImage: TemplateReferenceImage;
  draft: TemplateDraft;
  step: StudioStep;
  selectedAnchorId: string | null;
  selectedRegionId: string | null;
  onSelectAnchor: (anchorId: string | null) => void;
  onSelectRegion: (regionId: string | null) => void;
  onDraftChange: (draft: TemplateDraft) => void;
}) {
  const selectedAnchor =
    draft.anchors.find((item) => item.anchorId === selectedAnchorId) ?? null;
  const selectedRegion =
    draft.regions.find((item) => item.regionId === selectedRegionId) ?? null;
  const drawGesture = useRef<DrawGesture | null>(null);
  const [drawPreview, setDrawPreview] = useState<NormalizedBounds | null>(null);
  const [drawNotice, setDrawNotice] = useState<{
    step: StudioStep;
    message: string;
  } | null>(null);

  const updateAnchor = useCallback(
    (nextAnchor: TemplateAnchor) => {
      onDraftChange({
        ...draft,
        anchors: draft.anchors.map((item) =>
          item.anchorId === nextAnchor.anchorId ? nextAnchor : item,
        ),
      });
    },
    [draft, onDraftChange],
  );

  const updateRegion = useCallback(
    (nextRegion: TemplateRegion) => {
      onDraftChange({
        ...draft,
        regions: draft.regions.map((item) =>
          item.regionId === nextRegion.regionId ? nextRegion : item,
        ),
      });
    },
    [draft, onDraftChange],
  );

  const addAnchor = (bounds: NormalizedBounds = DEFAULT_BOX_BOUNDS) => {
    const next: TemplateAnchor = {
      anchorId: nextItemId(
        "anchor",
        draft.anchors.map((anchor) => anchor.anchorId),
      ),
      label: "新的固定内容",
      expectedText: TEMPORARY_ANCHOR_TEXT,
      matchMode: "exact",
      required: false,
      roleEvidence: "position_only",
      importance: "supporting",
      bounds: { ...bounds },
    };
    onDraftChange({
      ...draft,
      anchors: [...draft.anchors, next],
    });
    onSelectAnchor(next.anchorId);
    setDrawNotice(null);
  };

  const addRegion = (bounds: NormalizedBounds = DEFAULT_BOX_BOUNDS) => {
    const anchorId =
      (selectedAnchorId &&
      draft.anchors.some((anchor) => anchor.anchorId === selectedAnchorId)
        ? selectedAnchorId
        : draft.anchors[0]?.anchorId) ?? null;
    if (anchorId === null) {
      setDrawNotice({
        step: "regions",
        message: "请先在第 1 步标出至少一处固定内容，才能添加读取内容。",
      });
      return;
    }
    const next: TemplateRegion = {
      regionId: nextItemId(
        "region",
        draft.regions.map((region) => region.regionId),
      ),
      label: "普通净重",
      field: "ordinary_net_weight",
      valueType: "weight",
      unit: "ton",
      required: false,
      anchorId,
      bounds: { ...bounds },
    };
    onDraftChange({
      ...draft,
      regions: [...draft.regions, next],
    });
    onSelectRegion(next.regionId);
    setDrawNotice(null);
  };

  const handleBoxKey = (
    event: KeyboardEvent<HTMLButtonElement>,
    kind: StudioStep,
    itemId: string,
  ) => {
    if (event.key === "Delete") {
      event.preventDefault();
      if (kind === "anchors") {
        const dependentRegions = draft.regions.filter(
          (region) => region.anchorId === itemId,
        );
        if (dependentRegions.length > 0) {
          setDrawNotice({
            step: "anchors",
            message:
              `不能删除这处固定内容，还有 ${dependentRegions.length} 个读取区域以它为参照。` +
              "请先删除这些读取区域，或把它们改为参照其他固定内容。",
          });
          return;
        }
        const remainingAnchors = draft.anchors.filter(
          (item) => item.anchorId !== itemId,
        );
        onDraftChange({
          ...draft,
          anchors: remainingAnchors,
        });
        onSelectAnchor(null);
      } else {
        onDraftChange({
          ...draft,
          regions: draft.regions.filter((item) => item.regionId !== itemId),
        });
        onSelectRegion(null);
      }
      return;
    }
    if (!event.key.startsWith("Arrow")) {
      return;
    }
    event.preventDefault();
    if (kind === "anchors") {
      const item = draft.anchors.find((anchor) => anchor.anchorId === itemId);
      if (item) {
        updateAnchor({
          ...item,
          bounds: nudgeBounds(item.bounds, event.key, event.shiftKey),
        });
      }
    } else {
      const item = draft.regions.find((region) => region.regionId === itemId);
      if (item) {
        updateRegion({
          ...item,
          bounds: nudgeBounds(item.bounds, event.key, event.shiftKey),
        });
      }
    }
  };

  const beginDrawing = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (
      event.target !== event.currentTarget ||
      event.button !== 0 ||
      event.isPrimary === false
    ) {
      return;
    }
    if (step === "regions" && draft.anchors.length === 0) {
      setDrawNotice({
        step,
        message: "请先在第 1 步标出至少一处固定内容，才能添加读取内容。",
      });
      return;
    }
    const point = pointInLayer(event);
    if (point === null) {
      return;
    }
    event.preventDefault();
    drawGesture.current = {
      pointerId: event.pointerId,
      start: point,
      current: point,
    };
    setDrawPreview(null);
    setDrawNotice(null);
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };

  const continueDrawing = (event: ReactPointerEvent<HTMLDivElement>) => {
    const gesture = drawGesture.current;
    if (gesture === null || gesture.pointerId !== event.pointerId) {
      return;
    }
    const point = pointInLayer(event);
    if (point === null) {
      return;
    }
    event.preventDefault();
    const nextGesture = { ...gesture, current: point };
    drawGesture.current = nextGesture;
    setDrawPreview(boundsBetween(nextGesture.start, nextGesture.current));
  };

  const finishDrawing = (event: ReactPointerEvent<HTMLDivElement>) => {
    const gesture = drawGesture.current;
    if (gesture === null || gesture.pointerId !== event.pointerId) {
      return;
    }
    event.preventDefault();
    const end = pointInLayer(event) ?? gesture.current;
    const bounds = boundsBetween(gesture.start, end);
    drawGesture.current = null;
    setDrawPreview(null);
    if (event.currentTarget.hasPointerCapture?.(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    if (bounds.width < MIN_BOX_SIZE || bounds.height < MIN_BOX_SIZE) {
      setDrawNotice({
        step,
        message: "框选范围太小，请拖出更大的范围。",
      });
      return;
    }
    if (step === "anchors") {
      addAnchor(bounds);
    } else {
      addRegion(bounds);
    }
  };

  const cancelDrawing = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (drawGesture.current?.pointerId !== event.pointerId) {
      return;
    }
    drawGesture.current = null;
    setDrawPreview(null);
  };

  return (
    <div className="template-editor-grid">
      <section
        className="template-image-region"
        aria-labelledby="template-image-title"
      >
        <div className="template-region-heading">
          <div>
            <h2 id="template-image-title">参考图片</h2>
            <p>{referenceImage.alt}</p>
            <span className="template-image-size">
              {referenceImage.width} × {referenceImage.height} 像素
            </span>
          </div>
          {step === "anchors" && draft.anchors.length > 0 ? (
            <button
              className="button"
              type="button"
              onClick={() => addAnchor()}
            >
              添加固定内容
            </button>
          ) : null}
          {step === "regions" && draft.regions.length > 0 ? (
            <button
              className="button"
              type="button"
              disabled={draft.anchors.length === 0}
              onClick={() => addRegion()}
            >
              添加读取内容
            </button>
          ) : null}
        </div>
        <p className="template-draw-instruction" id="template-draw-instruction">
          {step === "anchors"
            ? "在图片空白处按住并拖动，框住一处长期不变的文字或标记。"
            : "在图片空白处按住并拖动，框住一项需要读取的内容。"}
        </p>
        <div
          className="template-image-stage"
          style={{
            aspectRatio: `${referenceImage.width} / ${referenceImage.height}`,
          }}
        >
          <img
            src={referenceImage.contentUrl}
            alt={referenceImage.alt}
            draggable={false}
          />
          <div
            className="template-box-layer"
            role="group"
            aria-label={
              step === "anchors"
                ? "固定内容框选区域"
                : "读取内容框选区域"
            }
            aria-describedby="template-draw-instruction"
            onPointerDown={beginDrawing}
            onPointerMove={continueDrawing}
            onPointerUp={finishDrawing}
            onPointerCancel={cancelDrawing}
            onLostPointerCapture={cancelDrawing}
          >
            {drawPreview ? (
              <span
                aria-hidden="true"
                className={`template-draw-preview ${
                  step === "regions" ? "region-preview" : ""
                }`}
                style={boxStyle(drawPreview)}
              />
            ) : null}
            {step === "anchors"
              ? draft.anchors.map((item) => (
                  <button
                    key={item.anchorId}
                    className="template-box anchor-box"
                    style={boxStyle(item.bounds)}
                    type="button"
                    tabIndex={0}
                    aria-pressed={item.anchorId === selectedAnchorId}
                    aria-label={`固定内容：${item.label}`}
                    onClick={() => onSelectAnchor(item.anchorId)}
                    onKeyDown={(event) =>
                      handleBoxKey(event, "anchors", item.anchorId)
                    }
                  />
                ))
              : draft.regions.map((item) => (
                  <button
                    key={item.regionId}
                    className="template-box region-box"
                    style={boxStyle(item.bounds)}
                    type="button"
                    tabIndex={0}
                    aria-pressed={item.regionId === selectedRegionId}
                    aria-label={`读取区域：${item.label}`}
                    onClick={() => onSelectRegion(item.regionId)}
                    onKeyDown={(event) =>
                      handleBoxKey(event, "regions", item.regionId)
                    }
                  />
                ))}
          </div>
        </div>
        {drawNotice?.step === step ? (
          <p
            className="template-draw-message"
            role={drawNotice.message.startsWith("不能删除") ? "alert" : "status"}
          >
            {drawNotice.message}
          </p>
        ) : null}
      </section>

      <section
        className="template-properties-region"
        aria-labelledby="template-properties-title"
      >
        <h2 id="template-properties-title">
          {step === "anchors" ? "固定内容设置" : "读取内容设置"}
        </h2>
        {step === "anchors" ? (
          selectedAnchor ? (
            <AnchorProperties anchor={selectedAnchor} onChange={updateAnchor} />
          ) : (
            <div className="template-property-empty">
              <p>尚未标出固定内容</p>
              <button
                className="button"
                type="button"
                onClick={() => addAnchor()}
              >
                添加固定内容
              </button>
            </div>
          )
        ) : selectedRegion ? (
          <RegionProperties
            region={selectedRegion}
            anchors={draft.anchors}
            onChange={updateRegion}
          />
        ) : (
          <div className="template-property-empty">
            <p>
              {draft.regions.length === 0
                ? "尚未标出读取内容"
                : "请选择图片中需要读取的内容。"}
            </p>
            {draft.regions.length === 0 ? (
              <button
                className="button"
                type="button"
                disabled={draft.anchors.length === 0}
                onClick={() => addRegion()}
              >
                添加读取内容
              </button>
            ) : null}
            {draft.anchors.length === 0 ? (
              <p className="template-disabled-explanation">
                请先在第 1 步标出至少一处固定内容，才能添加读取内容。
              </p>
            ) : null}
          </div>
        )}
      </section>
    </div>
  );
}

export function TemplateStudio({ services, onBack }: TemplateStudioProps) {
  const [initialRecovery] = useState(() => readTemplateCreationRecovery());
  const [index, setIndex] = useState<TemplateFamilyIndex | null>(null);
  const [version, setVersion] = useState<TemplateVersionSnapshot | null>(null);
  const [draft, setDraft] = useState<TemplateDraft | null>(null);
  const [selectedFamilyId, setSelectedFamilyId] = useState<string | null>(null);
  const [step, setStep] = useState<StudioStep>(
    initialRecovery?.step ?? "anchors",
  );
  const [selectedAnchorId, setSelectedAnchorId] = useState<string | null>(
    initialRecovery?.selectedAnchorId ?? null,
  );
  const [selectedRegionId, setSelectedRegionId] = useState<string | null>(
    initialRecovery?.selectedRegionId ?? null,
  );
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [shadowConfirmationOpen, setShadowConfirmationOpen] = useState(false);
  const [shadowAccessCode, setShadowAccessCode] = useState("");
  const [shadowError, setShadowError] = useState<string | null>(null);
  const [rollbackConfirmationOpen, setRollbackConfirmationOpen] =
    useState(false);
  const [rollbackOptions, setRollbackOptions] =
    useState<TemplateRollbackOptions | null>(null);
  const [rollbackTargetVersionId, setRollbackTargetVersionId] = useState("");
  const [rollbackReason, setRollbackReason] = useState("");
  const [rollbackAccessCode, setRollbackAccessCode] = useState("");
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  const [creationOpen, setCreationOpen] = useState(
    initialRecovery?.creationOpen ?? false,
  );
  const [creationName, setCreationName] = useState(
    initialRecovery?.creationName ?? "",
  );
  const [creationRole, setCreationRole] = useState<TemplateRole | "">(
    initialRecovery?.creationRole ?? "",
  );
  const [referenceFile, setReferenceFile] = useState<File | null>(null);
  const [stagedReference, setStagedReference] =
    useState<StagedTemplateReference | null>(
      initialRecovery?.stagedReference ?? null,
    );
  const [creationDraft, setCreationDraft] =
    useState<TemplateDraft>(
      initialRecovery?.creationDraft ?? emptyTemplateDraft,
    );
  const [creationError, setCreationError] = useState<string | null>(null);
  const uploadInFlight = useRef(false);
  const createInFlight = useRef(false);

  const applyVersion = useCallback((next: TemplateVersionSnapshot) => {
    setVersion(next);
    setSelectedFamilyId(next.familyId);
    setDraft(cloneDraft(next.draft));
    setSelectedAnchorId(next.draft.anchors[0]?.anchorId ?? null);
    setSelectedRegionId(next.draft.regions[0]?.regionId ?? null);
    setShadowConfirmationOpen(false);
    setShadowAccessCode("");
    setShadowError(null);
    setRollbackConfirmationOpen(false);
    setRollbackOptions(null);
    setRollbackTargetVersionId("");
    setRollbackReason("");
    setRollbackAccessCode("");
    setRollbackError(null);
    setNotice(null);
  }, []);

  useEffect(() => {
    const hasRecoverableCreation =
      creationOpen ||
      creationName.length > 0 ||
      creationRole !== "" ||
      stagedReference !== null ||
      creationDraft.anchors.length > 0 ||
      creationDraft.regions.length > 0;
    if (!hasRecoverableCreation) {
      clearTemplateCreationRecovery();
      return;
    }
    const recovery: TemplateCreationRecovery = {
      schemaVersion: 1,
      creationOpen,
      creationName,
      creationRole,
      stagedReference,
      creationDraft: cloneDraft(creationDraft),
      step,
      selectedAnchorId,
      selectedRegionId,
    };
    writeTemplateCreationRecovery(recovery);
  }, [
    creationDraft,
    creationName,
    creationOpen,
    creationRole,
    selectedAnchorId,
    selectedRegionId,
    stagedReference,
    step,
  ]);

  const loadAuthorizedVersion = useCallback(
    async (
      nextIndex: TemplateFamilyIndex,
      preferredFamilyId?: string | null,
    ): Promise<TemplateVersionSnapshot | null> => {
      const nextFamilyId =
        nextIndex.maintenance.authorized === true
          ? (
              nextIndex.families.find(
                (family) => family.familyId === preferredFamilyId,
              )?.familyId ??
              nextIndex.families[0]?.familyId ??
              null
            )
          : null;
      if (nextFamilyId === null || !services.loadTemplateFamily) {
        return null;
      }
      return services.loadTemplateFamily(nextFamilyId);
    },
    [services],
  );

  const returnToMaintenanceGate = useCallback(
    async (message: string) => {
      setVersion(null);
      setDraft(null);
      setSelectedFamilyId(null);
      setShadowConfirmationOpen(false);
      setRollbackConfirmationOpen(false);
      setError(message);
      if (!services.loadTemplateFamilies) {
        return;
      }
      try {
        setIndex(await services.loadTemplateFamilies());
      } catch {
        // The explicit local draft remains recoverable even if status reload fails.
      }
    },
    [services],
  );

  const handleTemplateFailure = useCallback(
    (failure: unknown, fallback: string) => {
      if (failure instanceof TemplateMaintenanceRequiredError) {
        void returnToMaintenanceGate(
          "维护模式已退出，未提交的模板草稿仍然保留。请重新验证后继续。",
        );
        return;
      }
      setError(fallback);
    },
    [returnToMaintenanceGate],
  );

  useEffect(() => {
    let disposed = false;
    if (!services.loadTemplateFamilies) {
      return;
    }
    void services
      .loadTemplateFamilies()
      .then(async (next) => ({
        index: next,
        version: await loadAuthorizedVersion(next),
      }))
      .then((next) => {
        if (!disposed) {
          setIndex(next.index);
          if (next.version) {
            applyVersion(next.version);
          }
        }
      })
      .catch(() => {
        if (!disposed) {
          setError("模板状态暂时无法加载，已有模板不会改变。");
        }
      });
    return () => {
      disposed = true;
    };
  }, [applyVersion, loadAuthorizedVersion, services]);

  const unlock = (accessCode: string) => {
    if (!services.unlockTemplateMaintenance) {
      setError("当前版本不能进入模板维护模式。");
      return;
    }
    if (!accessCode.trim()) {
      setError("请输入维护验证码。");
      return;
    }
    setBusy("unlock");
    setError(null);
    void services
      .unlockTemplateMaintenance(accessCode)
      .then(async (next) => ({
        index: next,
        version: await loadAuthorizedVersion(next),
      }))
      .then((next) => {
        setIndex(next.index);
        if (next.version) {
          applyVersion(next.version);
        }
      })
      .catch(() => {
        setError("维护验证没有通过，请核对验证码后再试。");
      })
      .finally(() => setBusy(null));
  };

  const selectFamily = (familyId: string) => {
    if (
      busy !== null ||
      familyId === selectedFamilyId ||
      !services.loadTemplateFamily
    ) {
      return;
    }
    setBusy("load_family");
    setError(null);
    void services
      .loadTemplateFamily(familyId)
      .then(applyVersion)
      .catch((failure: unknown) => {
        handleTemplateFailure(
          failure,
          "该票据模板暂时无法加载，当前模板没有改变。",
        );
      })
      .finally(() => setBusy(null));
  };

  const openCreation = () => {
    const action = index?.actions.create_template;
    if (!action?.visible || !action.enabled || busy !== null) {
      return;
    }
    setCreationOpen(true);
    setCreationError(null);
    setError(null);
  };

  const resetCreation = useCallback(() => {
    setCreationOpen(false);
    setCreationName("");
    setCreationRole("");
    setReferenceFile(null);
    setStagedReference(null);
    setCreationDraft(emptyTemplateDraft());
    setSelectedAnchorId(version?.draft.anchors[0]?.anchorId ?? null);
    setSelectedRegionId(version?.draft.regions[0]?.regionId ?? null);
    setStep("anchors");
    setCreationError(null);
    clearTemplateCreationRecovery();
  }, [version]);

  const selectReferenceFile = (file: File | null) => {
    if (stagedReference !== null) {
      setCreationError(
        "当前参考图片已经上传。请先放弃本次模板，再选择另一张图片。",
      );
      return;
    }
    setReferenceFile(file);
    setCreationDraft(emptyTemplateDraft());
    setSelectedAnchorId(null);
    setSelectedRegionId(null);
    setStep("anchors");
    setCreationError(null);
  };

  const abandonCreation = () => {
    if (busy !== null) {
      return;
    }
    if (!stagedReference) {
      resetCreation();
      return;
    }
    if (!services.abandonTemplateReference) {
      setCreationError("当前版本不能安全放弃已上传的参考图片。");
      return;
    }
    setBusy("abandon_reference");
    setCreationError(null);
    void services
      .abandonTemplateReference(
        stagedReference.stagedReferenceId,
        stagedReference.recordVersion,
      )
      .then(resetCreation)
      .catch((failure: unknown) => {
        if (failure instanceof TemplateMaintenanceRequiredError) {
          void returnToMaintenanceGate(
            "维护模式已退出，本次模板草稿仍然保留。请重新验证后再放弃。",
          );
          return;
        }
        setCreationError("本次模板尚未放弃，已填写和框选的内容仍然保留。");
      })
      .finally(() => setBusy(null));
  };

  const uploadReference = () => {
    const action = index?.actions.create_template;
    if (
      uploadInFlight.current ||
      busy !== null ||
      stagedReference !== null ||
      !action?.visible ||
      !action.enabled
    ) {
      return;
    }
    if (!referenceFile) {
      setCreationError("请先选择一张 PNG 或 JPEG 参考图片。");
      return;
    }
    if (
      referenceFile.type !== "image/png" &&
      referenceFile.type !== "image/jpeg"
    ) {
      setCreationError("参考图片只支持 PNG 或 JPEG 格式。");
      return;
    }
    if (!services.uploadTemplateReference) {
      setCreationError("当前版本尚不能上传模板参考图片。");
      return;
    }
    uploadInFlight.current = true;
    setBusy("upload_reference");
    setCreationError(null);
    void services
      .uploadTemplateReference(referenceFile)
      .then((next) => {
        setStagedReference(next);
        setCreationDraft(emptyTemplateDraft());
        setSelectedAnchorId(null);
        setSelectedRegionId(null);
        setStep("anchors");
      })
      .catch((failure: unknown) => {
        if (failure instanceof TemplateMaintenanceRequiredError) {
          void returnToMaintenanceGate(
            "维护模式已退出，已填写的模板信息仍然保留。请重新验证后继续。",
          );
          return;
        }
        setCreationError("参考图片上传失败，已填写内容会保留，请重试。");
      })
      .finally(() => {
        uploadInFlight.current = false;
        setBusy(null);
      });
  };

  const createFirstTemplate = () => {
    const action = index?.actions.create_template;
    if (
      createInFlight.current ||
      busy !== null ||
      !action?.visible ||
      !action.enabled
    ) {
      return;
    }
    if (
      !stagedReference ||
      !creationName.trim() ||
      !creationRole ||
      !hasCompleteAnchorText(creationDraft)
    ) {
      setCreationError("请先完成模板名称、票据类型和固定内容。");
      return;
    }
    if (!services.createTemplateFromStagedReference) {
      setCreationError("当前版本尚不能创建票据模板。");
      return;
    }
    createInFlight.current = true;
    setBusy("create_template");
    setCreationError(null);
    void services
      .createTemplateFromStagedReference(
        stagedReference.stagedReferenceId,
        stagedReference.recordVersion,
        creationName.trim(),
        creationRole,
        creationDraft,
      )
      .then((result) => {
        resetCreation();
        applyVersion(result.template);
        if (services.loadTemplateFamilies) {
          void services.loadTemplateFamilies().then(setIndex);
        }
      })
      .catch((failure: unknown) => {
        if (failure instanceof TemplateMaintenanceRequiredError) {
          void returnToMaintenanceGate(
            "维护模式已退出，未提交的模板草稿仍然保留。请重新验证后继续。",
          );
          return;
        }
        setCreationError(
          "模板草稿没有创建，已填写和框选的内容仍然保留。",
        );
      })
      .finally(() => {
        createInFlight.current = false;
        setBusy(null);
      });
  };

  const save = () => {
    if (!version || !draft || !services.saveTemplateDraft) {
      return;
    }
    setBusy("save_draft");
    setError(null);
    void services
      .saveTemplateDraft(version.versionId, version.recordVersion, draft)
      .then(applyVersion)
      .catch((failure: unknown) => {
        handleTemplateFailure(
          failure,
          "草稿尚未保存，当前页面中的框选内容仍然保留。",
        );
      })
      .finally(() => setBusy(null));
  };

  const runAction = (actionId: string, action: TemplateAction) => {
    if (!version || action.expectedRecordVersion === null) {
      return;
    }
    if (
      actionId === "run_development_check" &&
      !action.evaluationId?.trim()
    ) {
      setError("开发样本检查记录缺失，请重新生成检查结果后再试。");
      return;
    }
    const expectedRecordVersion = action.expectedRecordVersion;
    setBusy(actionId);
    setError(null);
    if (
      actionId === "run_development_check" &&
      services.runTemplateDevelopmentCheck
    ) {
      void services
        .runTemplateDevelopmentCheck(
          version.versionId,
          expectedRecordVersion,
          action.evaluationId ?? undefined,
        )
        .then(applyVersion)
        .catch((failure: unknown) => {
          handleTemplateFailure(
            failure,
            "开发样本检查没有完成，草稿和已有结果没有改变。",
          );
        })
        .finally(() => setBusy(null));
      return;
    }
    setBusy(null);
  };

  const openRollbackConfirmation = () => {
    if (
      !version ||
      busy !== null ||
      !services.loadTemplateFamilyVersions
    ) {
      setError("当前版本尚不能读取可恢复的影子版本。");
      return;
    }
    setBusy("load_rollback");
    setError(null);
    setNotice(null);
    setRollbackError(null);
    void services
      .loadTemplateFamilyVersions(version.familyId)
      .then((options) => {
        const firstTarget = options.versions.find(
          (candidate) => candidate.canRollback,
        );
        if (
          !firstTarget ||
          options.currentShadowRecordVersion === null
        ) {
          setError("当前模板没有可恢复的较早影子版本。");
          return;
        }
        setRollbackOptions(options);
        setRollbackTargetVersionId(firstTarget.versionId);
        setRollbackReason("");
        setRollbackAccessCode("");
        setRollbackConfirmationOpen(true);
      })
      .catch((failure: unknown) => {
        handleTemplateFailure(
          failure,
          "可恢复的影子版本暂时无法加载，当前模板没有改变。",
        );
      })
      .finally(() => setBusy(null));
  };

  const closeRollbackConfirmation = () => {
    if (busy === "restore_shadow") {
      return;
    }
    setRollbackConfirmationOpen(false);
    setRollbackOptions(null);
    setRollbackTargetVersionId("");
    setRollbackReason("");
    setRollbackAccessCode("");
    setRollbackError(null);
  };

  const confirmShadowRollback = () => {
    if (
      !version ||
      !rollbackOptions ||
      rollbackOptions.currentShadowRecordVersion === null
    ) {
      setRollbackError("影子版本状态已经变化，请重新打开恢复操作。");
      return;
    }
    const target = rollbackOptions.versions.find(
      (candidate) =>
        candidate.versionId === rollbackTargetVersionId &&
        candidate.canRollback,
    );
    if (!target) {
      setRollbackError("请选择一个可恢复的较早影子版本。");
      return;
    }
    if (!rollbackReason.trim()) {
      setRollbackError("请填写恢复原因。");
      return;
    }
    if (!rollbackAccessCode.trim()) {
      setRollbackError("请再次输入维护验证码。");
      return;
    }
    if (
      !services.revalidateTemplateRollbackAction ||
      !services.rollbackTemplateShadow
    ) {
      setRollbackError("当前版本尚不能安全恢复影子版本。");
      return;
    }
    const familyId = version.familyId;
    const expectedRecordVersion =
      rollbackOptions.currentShadowRecordVersion;
    const reason = rollbackReason.trim();
    const accessCode = rollbackAccessCode;
    setBusy("restore_shadow");
    setRollbackError(null);
    setRollbackAccessCode("");
    void (async () => {
      let developerAuthorization: string;
      try {
        developerAuthorization =
          await services.revalidateTemplateRollbackAction!(
            accessCode,
            familyId,
          );
      } catch (failure) {
        if (failure instanceof TemplateMaintenanceRequiredError) {
          await returnToMaintenanceGate(
            "维护模式已退出，影子版本没有改变。请重新验证后再恢复。",
          );
          return;
        }
        setRollbackError("维护验证没有通过，影子版本没有改变。");
        return;
      }
      try {
        await services.rollbackTemplateShadow!(
          familyId,
          target.versionId,
          expectedRecordVersion,
          reason,
          developerAuthorization,
        );
      } catch (failure) {
        if (failure instanceof TemplateMaintenanceRequiredError) {
          await returnToMaintenanceGate(
            "维护模式已退出，影子版本没有改变。请重新验证后再恢复。",
          );
          return;
        }
        setRollbackError(
          "无法确认恢复结果，请重新打开模板状态核对后再决定是否操作。",
        );
        return;
      }
      try {
        const [nextIndex, nextVersion] = await Promise.all([
          services.loadTemplateFamilies?.(),
          services.loadTemplateFamily?.(familyId),
        ]);
        if (nextIndex) {
          setIndex(nextIndex);
        }
        if (nextVersion) {
          applyVersion(nextVersion);
        } else {
          setRollbackConfirmationOpen(false);
          setRollbackOptions(null);
          setRollbackTargetVersionId("");
          setRollbackReason("");
          setRollbackAccessCode("");
          setRollbackError(null);
        }
        setNotice(`影子模板已恢复到${target.label}。`);
      } catch {
        setRollbackConfirmationOpen(false);
        setRollbackOptions(null);
        setRollbackTargetVersionId("");
        setRollbackReason("");
        setRollbackAccessCode("");
        setNotice(
          `影子模板已恢复到${target.label}，但页面状态暂时没有刷新。请重新进入模板维护核对当前版本。`,
        );
      }
    })().finally(() => setBusy(null));
  };

  const openShadowConfirmation = () => {
    setError(null);
    setShadowError(null);
    setShadowAccessCode("");
    setShadowConfirmationOpen(true);
  };

  const closeShadowConfirmation = () => {
    if (busy === "start_shadow") {
      return;
    }
    setShadowConfirmationOpen(false);
    setShadowAccessCode("");
    setShadowError(null);
  };

  const confirmShadowPublication = () => {
    const action = version?.actions.start_shadow;
    if (!version || !action || action.expectedRecordVersion === null) {
      setShadowError("影子测试状态已经变化，请刷新模板后再试。");
      return;
    }
    if (!shadowAccessCode.trim()) {
      setShadowError("请再次输入维护验证码。");
      return;
    }
    if (!action.evaluationId?.trim()) {
      setShadowError("影子测试缺少已通过的开发样本检查记录。");
      return;
    }
    if (
      !services.revalidateTemplateShadowAction ||
      !services.runTemplateVersionAction
    ) {
      setShadowError("当前版本尚不能安全开始影子测试。");
      return;
    }
    const accessCode = shadowAccessCode;
    const evaluationId = action.evaluationId;
    const expectedRecordVersion = action.expectedRecordVersion;
    setBusy("start_shadow");
    setShadowError(null);
    setShadowAccessCode("");
    void (async () => {
      let developerAuthorization: string;
      try {
        developerAuthorization =
          await services.revalidateTemplateShadowAction!(
            accessCode,
            version.versionId,
          );
      } catch (failure) {
        if (failure instanceof TemplateMaintenanceRequiredError) {
          await returnToMaintenanceGate(
            "维护模式已退出，影子测试没有开始。请重新验证后再试。",
          );
          return;
        }
        setShadowError("维护验证没有通过，当前模板没有改变。");
        return;
      }
      try {
        const next = await services.runTemplateVersionAction!(
          version.versionId,
          "start_shadow",
          expectedRecordVersion,
          {
            evaluationId,
            developerAuthorization,
          },
        );
        applyVersion(next);
      } catch (failure) {
        if (failure instanceof TemplateMaintenanceRequiredError) {
          await returnToMaintenanceGate(
            "维护模式已退出，影子测试没有开始。请重新验证后再试。",
          );
          return;
        }
        setShadowError("影子测试没有开始，当前模板没有改变。");
      }
    })().finally(() => setBusy(null));
  };

  const visibleActions = useMemo(
    () =>
      version
        ? Object.entries(version.actions).filter(
            ([actionId, action]) =>
              supportedActions.has(actionId) && action.visible,
          )
        : [],
    [version],
  );
  const createAction = index?.actions.create_template ?? null;
  const creationIncompleteReason = !stagedReference
    ? "请先上传参考图片。"
    : !creationName.trim()
      ? "请填写模板名称。"
      : !creationRole
        ? "请选择装货磅单或卸货磅单。"
        : creationDraft.anchors.length === 0
          ? "请先标出至少一处固定内容。"
          : !hasCompleteAnchorText(creationDraft)
            ? "请把固定内容的预计文字替换为票面实际文字。"
            : null;
  const unavailableError = services.loadTemplateFamilies
    ? null
    : "票据模板功能尚未连接到本地服务。";
  const displayedError = error ?? unavailableError;
  const isLoadingVersion =
    index?.maintenance.authorized === true &&
    index.families.length > 0 &&
    version === null &&
    Boolean(services.loadTemplateFamily) &&
    displayedError === null;

  return (
    <section className="plain-section template-studio" aria-labelledby="template-title">
      <div className="template-breadcrumbs">
        <button type="button" onClick={onBack}>
          开发与维护
        </button>
        <span aria-hidden="true">/</span>
        <span>票据模板</span>
      </div>
      <div className="section-heading">
        <div>
          <h1 id="template-title">票据模板</h1>
          <p>用清晰磅单标出固定内容和需要读取的字段。</p>
        </div>
        {index?.maintenance.authorized ? (
          <div className="template-maintenance-status">
            <strong>{index.maintenance.statusLabel}</strong>
            {index.maintenance.expiresAtLabel ? (
              <span>{index.maintenance.expiresAtLabel}</span>
            ) : null}
          </div>
        ) : null}
      </div>

      {index ? (
        <div className="template-acceptance-status">
          <span>{index.acceptanceSet.statusLabel}</span>
          <strong>
            {index.acceptanceSet.waybillCount}/
            {index.acceptanceSet.targetWaybillCount} 条运单
          </strong>
        </div>
      ) : null}

      {index &&
      !index.maintenance.authorized &&
      index.families.length > 0 ? (
        <section
          className="template-family-status"
          aria-labelledby="template-family-status-title"
        >
          <h2 id="template-family-status-title">现有模板</h2>
          <ul className="template-family-list">
            {index.families.map((family) => (
              <li key={family.familyId}>
                <div>
                  <div>
                    <strong>{family.name}</strong>
                    <span>{family.purposeLabel}</span>
                  </div>
                  <span>
                    {family.currentVersionLabel}，{family.lifecycleLabel}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {index && !index.maintenance.authorized ? (
        <MaintenanceGate
          index={index}
          busy={busy === "unlock"}
          error={displayedError}
          onUnlock={unlock}
        />
      ) : null}

      {index?.maintenance.authorized ? (
        <section
          className="template-first-workspace"
          aria-labelledby="template-first-title"
        >
          <div className="template-first-heading">
            <div>
              <h2 id="template-first-title">
                {index.families.length === 0 ? "还没有票据模板" : "现有模板"}
              </h2>
              <p>
                {index.families.length === 0
                  ? "从一张清晰、方向正确的磅单图片开始制作第一个模板。"
                  : "选择一个模板查看和维护，也可以继续添加新的票据模板。"}
              </p>
            </div>
            {!creationOpen && createAction?.visible ? (
              <button
                className="button primary"
                type="button"
                disabled={!createAction.enabled || busy !== null}
                onClick={openCreation}
              >
                {createAction.label}
              </button>
            ) : null}
          </div>
          {!creationOpen &&
          createAction?.visible &&
          !createAction.enabled &&
          createAction.reason ? (
            <p className="template-disabled-explanation">
              {createAction.reason}
            </p>
          ) : null}

          {index.families.length > 0 ? (
            <ul className="template-family-list template-family-selector">
              {index.families.map((family) => (
                <li key={family.familyId}>
                  <button
                    type="button"
                    aria-pressed={family.familyId === selectedFamilyId}
                    disabled={busy !== null || creationOpen}
                    onClick={() => selectFamily(family.familyId)}
                  >
                    <span>
                      <strong>{family.name}</strong>
                      <small>{family.purposeLabel}</small>
                    </span>
                    <span>
                      {family.currentVersionLabel}，{family.lifecycleLabel}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          ) : null}

          {creationOpen ? (
            <div className="template-creation-panel">
              <div>
                <h3>添加票据模板</h3>
                <p>先填写用途并上传参考图片，再在图片上标出固定内容。</p>
              </div>
              <div className="template-creation-fields">
                <label htmlFor="template-family-name">模板名称</label>
                <input
                  id="template-family-name"
                  disabled={busy !== null}
                  value={creationName}
                  onChange={(event) => {
                    setCreationName(event.currentTarget.value);
                    setCreationError(null);
                  }}
                />
                <label htmlFor="template-family-role">票据类型</label>
                <select
                  id="template-family-role"
                  disabled={busy !== null}
                  value={creationRole}
                  onChange={(event) => {
                    setCreationRole(
                      event.currentTarget.value as TemplateRole | "",
                    );
                    setCreationError(null);
                  }}
                >
                  <option value="">请选择票据类型</option>
                  <option value="loading">装货磅单</option>
                  <option value="unloading">卸货磅单</option>
                </select>
                <label htmlFor="template-reference-file">参考图片</label>
                <input
                  id="template-reference-file"
                  type="file"
                  accept="image/png,image/jpeg"
                  aria-describedby="template-reference-help"
                  disabled={busy !== null || stagedReference !== null}
                  onChange={(event) =>
                    selectReferenceFile(event.currentTarget.files?.[0] ?? null)
                  }
                />
                <p
                  className="template-file-help"
                  id="template-reference-help"
                >
                  只支持 PNG 或 JPEG。图片只保存到本机数据目录。
                </p>
                <button
                  className="button"
                  type="button"
                  disabled={
                    !createAction?.enabled ||
                    busy !== null ||
                    stagedReference !== null
                  }
                  onClick={uploadReference}
                >
                  {busy === "upload_reference"
                    ? "正在上传…"
                    : "上传参考图片"}
                </button>
                <button
                  className="button"
                  type="button"
                  disabled={busy !== null}
                  onClick={abandonCreation}
                >
                  {busy === "abandon_reference"
                    ? "正在放弃…"
                    : "放弃本次模板"}
                </button>
              </div>

              {creationError ? (
                <p className="template-error" role="alert">
                  {creationError}
                </p>
              ) : null}

              {stagedReference ? (
                <div className="template-staged-editor">
                  <p className="template-upload-status" role="status">
                    参考图片已准备，可以开始框选。
                  </p>
                  <TemplateSteps step={step} onChange={setStep} />
                  <p className="template-step-copy">
                    {step === "anchors"
                      ? "框选长期不变的文字或标记，例如厂名、“净重”和“打印时间”。"
                      : "普通净重、工厂净重、毛重、皮重和时间需要分别框选。"}
                  </p>
                  <ReferenceEditor
                    referenceImage={stagedReference}
                    draft={creationDraft}
                    step={step}
                    selectedAnchorId={selectedAnchorId}
                    selectedRegionId={selectedRegionId}
                    onSelectAnchor={setSelectedAnchorId}
                    onSelectRegion={setSelectedRegionId}
                    onDraftChange={setCreationDraft}
                  />
                  <div className="template-actions">
                    <div>
                      <button
                        className="button primary"
                        type="button"
                        disabled={
                          !createAction?.enabled ||
                          busy !== null ||
                          creationIncompleteReason !== null
                        }
                        onClick={createFirstTemplate}
                      >
                        {busy === "create_template"
                          ? "正在创建…"
                          : "创建草稿"}
                      </button>
                      {createAction &&
                      !createAction.enabled &&
                      createAction.reason ? (
                        <p>{createAction.reason}</p>
                      ) : creationIncompleteReason ? (
                        <p>{creationIncompleteReason}</p>
                      ) : null}
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}
        </section>
      ) : null}

      {index?.maintenance.authorized &&
      !creationOpen &&
      version &&
      draft ? (
        <>
          <div className="template-version-heading">
            <div>
              <span>{version.purposeLabel}</span>
              <h2>{version.familyName}</h2>
            </div>
            <strong>{version.lifecycleLabel}</strong>
          </div>

          <TemplateSteps step={step} onChange={setStep} />
          <p className="template-step-copy">
            {step === "anchors"
              ? "框选长期不变的文字或标记，例如厂名、“净重”和“打印时间”。"
              : "普通净重、工厂净重、毛重、皮重和时间需要分别框选。"}
          </p>

          <ReferenceEditor
            referenceImage={version.referenceImage}
            draft={draft}
            step={step}
            selectedAnchorId={selectedAnchorId}
            selectedRegionId={selectedRegionId}
            onSelectAnchor={setSelectedAnchorId}
            onSelectRegion={setSelectedRegionId}
            onDraftChange={setDraft}
          />

          <div className="template-actions" aria-label="模板操作">
            {visibleActions.map(([actionId, action]) => (
              <div key={actionId}>
                <button
                  className={
                    actionId === "start_shadow" ? "button primary" : "button"
                  }
                  type="button"
                  disabled={
                    !action.enabled ||
                    busy !== null ||
                    (actionId === "start_shadow" && shadowConfirmationOpen) ||
                    (actionId === "restore_shadow" &&
                      rollbackConfirmationOpen)
                  }
                  onClick={() => {
                    if (actionId === "save_draft") {
                      save();
                    } else if (actionId === "start_shadow") {
                      openShadowConfirmation();
                    } else if (actionId === "restore_shadow") {
                      openRollbackConfirmation();
                    } else {
                      runAction(actionId, action);
                    }
                  }}
                >
                  {busy === actionId ? "正在处理…" : action.label}
                </button>
                {!action.enabled && action.reason ? (
                  <p>{action.reason}</p>
                ) : null}
              </div>
            ))}
          </div>

          {shadowConfirmationOpen ? (
            <ShadowConfirmation
              accessCode={shadowAccessCode}
              busy={busy === "start_shadow"}
              error={shadowError}
              onAccessCodeChange={(accessCode) => {
                setShadowAccessCode(accessCode);
                setShadowError(null);
              }}
              onCancel={closeShadowConfirmation}
              onConfirm={confirmShadowPublication}
            />
          ) : null}

          {rollbackConfirmationOpen && rollbackOptions ? (
            <RollbackConfirmation
              options={rollbackOptions}
              targetVersionId={rollbackTargetVersionId}
              reason={rollbackReason}
              accessCode={rollbackAccessCode}
              busy={busy === "restore_shadow"}
              error={rollbackError}
              onTargetChange={(versionId) => {
                setRollbackTargetVersionId(versionId);
                setRollbackError(null);
              }}
              onReasonChange={(reason) => {
                setRollbackReason(reason);
                setRollbackError(null);
              }}
              onAccessCodeChange={(accessCode) => {
                setRollbackAccessCode(accessCode);
                setRollbackError(null);
              }}
              onCancel={closeRollbackConfirmation}
              onConfirm={confirmShadowRollback}
            />
          ) : null}

          {notice ? <p role="status">{notice}</p> : null}
          {error ? (
            <p className="template-error" role="alert">
              {error}
            </p>
          ) : null}
          <QualityReport report={version.checkReport} />
        </>
      ) : null}

      {index?.maintenance.authorized && isLoadingVersion ? (
        <p role="status">正在加载模板内容…</p>
      ) : null}
      {!index && !displayedError ? (
        <p role="status">正在加载模板状态…</p>
      ) : null}
      {!index && displayedError ? (
        <p className="template-error" role="alert">
          {displayedError}
        </p>
      ) : null}
    </section>
  );
}
