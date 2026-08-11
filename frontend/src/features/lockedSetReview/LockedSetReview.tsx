import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import type { AppServices } from "../../app/contracts";
import type {
  LockedSetPairCondition,
  LockedSetQualityCondition,
  LockedSetReviewDecision,
  LockedSetReviewImage,
  LockedSetReviewIndex,
  LockedSetReviewItem,
  LockedSetTicketRole,
  SaveLockedSetReviewInput,
} from "../../api/lockedSetReviewContracts";
import {
  clearReviewDraft,
  draftFingerprint,
  emptyDraft,
  readReviewDraft,
  writeReviewDraft,
  type ImageDraft,
  type ReviewDraft,
} from "./lockedSetReviewDraft";

const orientationOptions: Array<{
  value: LockedSetQualityCondition;
  label: string;
}> = [
  { value: "rotation_0", label: "正向 0°" },
  { value: "rotation_90", label: "右转 90°" },
  { value: "rotation_180", label: "倒置 180°" },
  { value: "rotation_270", label: "左转 90°" },
];

const qualityOptions: Array<{
  value: LockedSetQualityCondition;
  label: string;
}> = [
  { value: "blur", label: "模糊／清晰度不足" },
  { value: "glare", label: "有反光" },
  { value: "crop", label: "有裁边或内容缺失" },
  { value: "screen", label: "屏幕拍摄" },
  { value: "printed", label: "打印票" },
  { value: "unknown_layout", label: "未知版式" },
  { value: "non_ticket", label: "非磅单或上传错误" },
];

const pairOptions: Array<{
  value: LockedSetPairCondition;
  label: string;
}> = [
  { value: "normal_pair", label: "正常一装一卸" },
  { value: "swapped_pair", label: "疑似两张票放反" },
  { value: "same_role_pair", label: "两张票是同一角色" },
  { value: "pair_unknown", label: "无法判断两张图片的组合" },
];

const REVIEW_NOTES_MAX_LENGTH = 1000;

export interface LockedSetReviewNavigationState {
  dirty: boolean;
  saving: boolean;
}

function formatSample(position: number): string {
  return `样本 ${String(position).padStart(2, "0")}`;
}

function clueLabel(clue: string): string {
  const labels: Record<string, string> = {
    legacy_review_hint: "旧结构化记录曾标为需要复核",
    rotation_0_hint: "旧记录存在正向线索",
    rotation_90_hint: "旧记录存在 90° 方向线索",
    rotation_180_hint: "旧记录存在 180° 方向线索",
    rotation_270_hint: "旧记录存在 270° 方向线索",
  };
  return labels[clue] ?? "存在待人工核对的抽样线索";
}

export function ReviewImageViewer({
  image,
  slotLabel,
}: {
  image: { imageUrl: string };
  slotLabel: string;
}) {
  const [rotation, setRotation] = useState(0);
  const [scale, setScale] = useState(1);

  return (
    <div className="locked-review-viewer">
      <div className="locked-review-image-toolbar" aria-label={`${slotLabel}查看工具`}>
        <button
          type="button"
          aria-label="逆时针旋转图片"
          onClick={() => setRotation((current) => current - 90)}
        >
          左转
        </button>
        <button
          type="button"
          aria-label="顺时针旋转图片"
          onClick={() => setRotation((current) => current + 90)}
        >
          右转
        </button>
        <button
          type="button"
          aria-label="缩小图片"
          disabled={scale <= 0.5}
          onClick={() =>
            setScale((current) => Math.max(0.5, current - 0.25))
          }
        >
          缩小
        </button>
        <button
          type="button"
          aria-label="放大图片"
          disabled={scale >= 3}
          onClick={() =>
            setScale((current) => Math.min(3, current + 0.25))
          }
        >
          放大
        </button>
        <button
          type="button"
          aria-label="复位图片"
          onClick={() => {
            setRotation(0);
            setScale(1);
          }}
        >
          复位
        </button>
      </div>
      <div className="locked-review-image-stage">
        <img
          src={image.imageUrl}
          alt={`${slotLabel}原图`}
          draggable={false}
          style={{ transform: `rotate(${rotation}deg) scale(${scale})` }}
        />
      </div>
    </div>
  );
}

function ImageReviewPane({
  image,
  draft,
  onChange,
}: {
  image: LockedSetReviewImage;
  draft: ImageDraft;
  onChange: (next: ImageDraft) => void;
}) {
  const slotLabel =
    image.submittedSlot === "loading" ? "装货位置图片" : "卸货位置图片";
  const orientation =
    draft.qualityConditions.find((condition) =>
      condition.startsWith("rotation_"),
    ) ?? "";

  const setOrientation = (condition: LockedSetQualityCondition) => {
    onChange({
      ...draft,
      qualityConditions: [
        ...draft.qualityConditions.filter(
          (current) => !current.startsWith("rotation_"),
        ),
        condition,
      ],
    });
  };

  const toggleQuality = (condition: LockedSetQualityCondition) => {
    const selecting = !draft.qualityConditions.includes(condition);
    const requiresUnknownRole =
      condition === "non_ticket" || condition === "unknown_layout";
    onChange({
      ...draft,
      role:
        requiresUnknownRole && selecting ? "unknown" : draft.role,
      ordinaryNet:
        requiresUnknownRole && selecting
          ? ""
          : draft.ordinaryNet,
      qualityConditions: draft.qualityConditions.includes(condition)
        ? draft.qualityConditions.filter((current) => current !== condition)
        : [...draft.qualityConditions, condition],
    });
  };

  return (
    <section
      className="locked-review-image-pane"
      aria-labelledby={`${image.submittedSlot}-review-title`}
    >
      <div className="locked-review-pane-heading">
        <div>
          <h3 id={`${image.submittedSlot}-review-title`}>{slotLabel}</h3>
          <p>这里只表示司机上传的位置，不代表票据真实角色。</p>
        </div>
      </div>
      <ReviewImageViewer
        key={image.imageUrl}
        image={image}
        slotLabel={slotLabel}
      />
      <fieldset className="locked-review-fieldset">
        <legend>这张图片实际是什么？</legend>
        <div className="locked-review-radio-row">
          {(
            [
              ["loading", "装货票"],
              ["unloading", "卸货票"],
              ["unknown", "票据类型无法判断（净重留空）"],
            ] as const
          ).map(([value, label]) => (
            <label key={value}>
              <input
                type="radio"
                name={`${image.submittedSlot}-role`}
                value={value}
                checked={draft.role === value}
                onChange={() =>
                  onChange({
                    ...draft,
                    role: value,
                    ordinaryNet:
                      value === "unknown" ? "" : draft.ordinaryNet,
                    qualityConditions:
                      value === "unknown"
                        ? draft.qualityConditions
                        : draft.qualityConditions.filter(
                            (condition) =>
                              condition !== "non_ticket" &&
                              condition !== "unknown_layout",
                          ),
                  })
                }
              />
              {label}
            </label>
          ))}
        </div>
      </fieldset>
      <label className="locked-review-text-field">
        普通净重（吨）
        <input
          type="text"
          inputMode="decimal"
          placeholder={
            draft.role === "unknown" ? "无法判断时留空" : "例如 30.50"
          }
          value={draft.ordinaryNet}
          disabled={draft.role === "unknown"}
          onChange={(event) =>
            onChange({ ...draft, ordinaryNet: event.target.value })
          }
        />
      </label>
      <fieldset className="locked-review-fieldset">
        <legend>票面方向</legend>
        <div className="locked-review-option-grid">
          {orientationOptions.map((option) => (
            <label key={option.value}>
              <input
                type="radio"
                name={`${image.submittedSlot}-orientation`}
                checked={orientation === option.value}
                onChange={() => setOrientation(option.value)}
              />
              {option.label}
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset className="locked-review-fieldset">
        <legend>图片情况（可多选）</legend>
        <div className="locked-review-option-grid">
          {qualityOptions.map((option) => (
            <label key={option.value}>
              <input
                type="checkbox"
                checked={draft.qualityConditions.includes(option.value)}
                onChange={() => toggleQuality(option.value)}
              />
              {option.label}
            </label>
          ))}
        </div>
      </fieldset>
      <label className="locked-review-text-field">
        这张图片的备注（选填）
        <textarea
          maxLength={REVIEW_NOTES_MAX_LENGTH}
          rows={2}
          value={draft.notes}
          onChange={(event) =>
            onChange({ ...draft, notes: event.target.value })
          }
        />
      </label>
    </section>
  );
}

type ReviewFilter = "all" | "pending" | "completed";

export function LockedSetReview({
  services,
  onBack,
  onNavigationStateChange,
}: {
  services: AppServices;
  onBack: () => void;
  onNavigationStateChange?: (
    state: LockedSetReviewNavigationState,
  ) => void;
}) {
  const reviewServiceAvailable =
    services.loadLockedSetReview !== undefined &&
    services.loadLockedSetReviewItem !== undefined &&
    services.saveLockedSetReviewItem !== undefined;
  const [reviewIndex, setReviewIndex] =
    useState<LockedSetReviewIndex | null>(null);
  const [selectedSampleId, setSelectedSampleId] = useState<string | null>(
    null,
  );
  const [item, setItem] = useState<LockedSetReviewItem | null>(null);
  const [draft, setDraft] = useState<ReviewDraft | null>(null);
  const [baseline, setBaseline] = useState("");
  const [filter, setFilter] = useState<ReviewFilter>("all");
  const [loading, setLoading] = useState(reviewServiceAvailable);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(() =>
    reviewServiceAvailable ? null : "锁定集复核工具当前不可用。",
  );
  const [errorNearActions, setErrorNearActions] = useState(false);
  const [draftRecovered, setDraftRecovered] = useState(false);
  const detailRequest = useRef(0);
  const itemHeading = useRef<HTMLHeadingElement | null>(null);
  const actionError = useRef<HTMLParagraphElement | null>(null);
  const reviewPackageId = reviewIndex?.packageId ?? null;

  const dirty = useMemo(
    () => draft !== null && draftFingerprint(draft) !== baseline,
    [baseline, draft],
  );

  useEffect(() => {
    onNavigationStateChange?.({ dirty, saving });
  }, [dirty, onNavigationStateChange, saving]);

  useEffect(
    () => () => {
      onNavigationStateChange?.({ dirty: false, saving: false });
    },
    [onNavigationStateChange],
  );

  useEffect(() => {
    if (!services.loadLockedSetReview) {
      return;
    }
    let disposed = false;
    void services
      .loadLockedSetReview()
      .then((next) => {
        if (disposed) {
          return;
        }
        setReviewIndex(next);
        setSelectedSampleId(next.items[0]?.sampleId ?? null);
        setLoading(next.items.length > 0);
      })
      .catch(() => {
        if (!disposed) {
          setError("锁定集复核资料暂时无法读取，尚未修改任何标注。");
          setLoading(false);
        }
      });
    return () => {
      disposed = true;
    };
  }, [services]);

  useEffect(() => {
    if (!selectedSampleId || !services.loadLockedSetReviewItem) {
      return;
    }
    const requestId = detailRequest.current + 1;
    detailRequest.current = requestId;
    void services
      .loadLockedSetReviewItem(selectedSampleId)
      .then((next) => {
        if (requestId !== detailRequest.current) {
          return;
        }
        const serverDraft = emptyDraft(next);
        const storedDraft = reviewPackageId
          ? readReviewDraft(reviewPackageId, next)
          : null;
        const nextDraft = storedDraft ?? serverDraft;
        setItem(next);
        setDraft(nextDraft);
        setBaseline(
          draftFingerprint(storedDraft ? serverDraft : nextDraft),
        );
        setDraftRecovered(storedDraft !== null);
        setLoading(false);
        requestAnimationFrame(() => itemHeading.current?.focus());
      })
      .catch(() => {
        if (requestId === detailRequest.current) {
          setErrorNearActions(false);
          setError("这条样本暂时无法读取，现有人工标注没有改变。");
          setLoading(false);
        }
      });
  }, [reviewPackageId, selectedSampleId, services]);

  useEffect(() => {
    if (!reviewPackageId || !item || !draft) {
      return;
    }
    if (!dirty) {
      clearReviewDraft(reviewPackageId, item.sampleId);
      return;
    }
    writeReviewDraft(reviewPackageId, item, draft);
  }, [dirty, draft, item, reviewPackageId]);

  useEffect(() => {
    if (errorNearActions && error) {
      actionError.current?.focus();
    }
  }, [error, errorNearActions]);

  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => {
      if (!dirty) {
        return;
      }
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  const filteredItems = useMemo(() => {
    if (!reviewIndex) {
      return [];
    }
    return reviewIndex.items.filter((summary) => {
      if (filter === "all") {
        return true;
      }
      if (filter === "completed") {
        return summary.reviewStatus !== "pending";
      }
      return summary.reviewStatus === "pending";
    });
  }, [filter, reviewIndex]);

  const orderedItems = useMemo(
    () =>
      reviewIndex
        ? [...reviewIndex.items].sort(
            (left, right) => left.position - right.position,
          )
        : [],
    [reviewIndex],
  );
  const currentIndex = orderedItems.findIndex(
    (summary) => summary.sampleId === selectedSampleId,
  );
  const previousId =
    currentIndex > 0 ? orderedItems[currentIndex - 1]?.sampleId : undefined;
  const nextId =
    currentIndex >= 0
      ? orderedItems[currentIndex + 1]?.sampleId
      : undefined;

  const leaveCurrent = useCallback(
    (action: () => void) => {
      if (saving) {
        setMessage("当前人工标注正在保存，请等待保存完成后再切换。");
        return;
      }
      if (
        dirty &&
        !window.confirm(
          "当前填写尚未提交，切换后仍会保留在本机草稿中。是否继续？",
        )
      ) {
        setMessage("当前填写尚未提交，已留在本条样本。");
        return;
      }
      setMessage(null);
      action();
    },
    [dirty, saving],
  );

  const chooseSample = (sampleId: string) => {
    if (sampleId === selectedSampleId) {
      return;
    }
    leaveCurrent(() => {
      setLoading(true);
      setDraftRecovered(false);
      setError(null);
      setErrorNearActions(false);
      setSelectedSampleId(sampleId);
    });
  };

  const updateImage = (
    submittedSlot: "loading" | "unloading",
    next: ImageDraft,
  ) => {
    setDraft((current) =>
      current
        ? {
            ...current,
            images: current.images.map((image) =>
              image.submittedSlot === submittedSlot ? next : image,
            ),
          }
        : current,
    );
  };

  const validate = useCallback((): string | null => {
    if (!draft || !item) {
      return "当前样本尚未加载完成。";
    }
    if (!draft.decision) {
      return "请选择保存方式。";
    }
    if (
      draft.decision === "replace_candidate" &&
      !draft.replaceReason.trim()
    ) {
      return "申请更换样本时，请填写更换原因。";
    }
    if (
      draft.decision === "replace_candidate" &&
      draft.replaceReason.trim().length > REVIEW_NOTES_MAX_LENGTH
    ) {
      return `更换原因不能超过 ${REVIEW_NOTES_MAX_LENGTH} 个字符。`;
    }
    if (draft.decision === "replace_candidate") {
      return null;
    }
    if (draft.images.length !== 2) {
      return "当前样本必须包含装货位置和卸货位置两张图片。";
    }
    for (const image of draft.images) {
      const label =
        image.submittedSlot === "loading" ? "装货位置图片" : "卸货位置图片";
      if (!image.role) {
        return `请选择${label}的真实角色。`;
      }
      if (
        image.role !== "unknown" &&
        (!/^(?:0|[1-9]\d*)\.\d{2}$/.test(
          image.ordinaryNet.trim(),
        ) ||
          Number(image.ordinaryNet) <= 0)
      ) {
        return `请填写${label}的普通净重，单位为吨。`;
      }
      if (
        image.role !== "unknown" &&
        (image.qualityConditions.includes("unknown_layout") ||
          image.qualityConditions.includes("non_ticket"))
      ) {
        return `${label}标为未知版式或非磅单时，真实角色应选择“无法判断”。`;
      }
      if (image.notes.trim().length > REVIEW_NOTES_MAX_LENGTH) {
        return `${label}的备注不能超过 ${REVIEW_NOTES_MAX_LENGTH} 个字符。`;
      }
      if (
        !image.qualityConditions.some((condition) =>
          condition.startsWith("rotation_"),
        )
      ) {
        return `请选择${label}的票面方向。`;
      }
    }
    const pairClassifications = draft.pairConditions.filter(
      (condition) => condition !== "duplicate_upload",
    );
    if (pairClassifications.length !== 1) {
      return "请选择两张图片放在一起时的结论。";
    }
    const roles = Object.fromEntries(
      draft.images.map((image) => [image.submittedSlot, image.role]),
    );
    if (
      pairClassifications[0] === "normal_pair" &&
      (roles.loading !== "loading" || roles.unloading !== "unloading")
    ) {
      return "选择“正常一装一卸”时，装货位置应为装货票，卸货位置应为卸货票。";
    }
    if (
      pairClassifications[0] === "swapped_pair" &&
      (roles.loading !== "unloading" || roles.unloading !== "loading")
    ) {
      return "选择“疑似两张票放反”时，两张票的真实角色应与上传位置相反。";
    }
    if (
      pairClassifications[0] === "same_role_pair" &&
      !(
        roles.loading === roles.unloading &&
        (roles.loading === "loading" || roles.loading === "unloading")
      )
    ) {
      return "选择“两张票是同一角色”时，两张票应同时为装货票或同时为卸货票。";
    }
    if (
      pairClassifications[0] === "pair_unknown" &&
      roles.loading !== "unknown" &&
      roles.unloading !== "unknown"
    ) {
      return "选择“无法判断两张图片的组合”时，至少一张图片的真实角色也应为“票据类型无法判断”。";
    }
    if (draft.pairNotes.trim().length > REVIEW_NOTES_MAX_LENGTH) {
      return `整条样本备注不能超过 ${REVIEW_NOTES_MAX_LENGTH} 个字符。`;
    }
    return null;
  }, [draft, item]);

  const save = useCallback(
    async (advance: boolean) => {
      const validation = validate();
      if (validation) {
        setError(validation);
        setErrorNearActions(true);
        return;
      }
      if (!draft || !item || !services.saveLockedSetReviewItem) {
        setError("锁定集复核保存接口当前不可用。");
        setErrorNearActions(true);
        return;
      }
      const input: SaveLockedSetReviewInput = {
        expectedRecordVersion: item.recordVersion,
        decision: draft.decision as LockedSetReviewDecision,
        images:
          draft.decision === "replace_candidate"
            ? []
            : draft.images.map((image) => ({
                submittedSlot: image.submittedSlot,
                role: (image.role || "unknown") as LockedSetTicketRole,
                ordinaryNet:
                  image.role === "unknown"
                    ? null
                    : image.ordinaryNet.trim(),
                qualityConditions: image.qualityConditions,
                notes: image.notes.trim() || null,
              })),
        pairConditions:
          draft.decision === "replace_candidate"
            ? []
            : draft.pairConditions,
        pairNotes:
          draft.decision === "replace_candidate"
            ? null
            : draft.pairNotes.trim() || null,
        replaceReason:
          draft.decision === "confirmed"
            ? null
            : draft.replaceReason.trim() || null,
      };
      setSaving(true);
      setError(null);
      setErrorNearActions(false);
      setMessage(null);
      try {
        const result = await services.saveLockedSetReviewItem(
          item.sampleId,
          input,
        );
        const savedDraft = emptyDraft(result.item);
        setItem(result.item);
        setDraft(savedDraft);
        setBaseline(draftFingerprint(savedDraft));
        if (reviewPackageId) {
          clearReviewDraft(reviewPackageId, item.sampleId);
        }
        setDraftRecovered(false);
        setReviewIndex((current) =>
          current
            ? {
                ...current,
                progress: result.progress,
                items: current.items.map((summary) =>
                  summary.sampleId === result.item.sampleId
                    ? {
                        ...summary,
                        reviewStatus: result.item.reviewStatus,
                        recordVersion: result.item.recordVersion,
                        decision: result.item.decision,
                      }
                    : summary,
                ),
              }
            : current,
        );
        setMessage(`${formatSample(item.position)}的人工标注已保存。`);
        if (advance && nextId) {
          setLoading(true);
          setSelectedSampleId(nextId);
        }
      } catch {
        setError(
          "这次保存尚未确认完成。请保持页面打开，重新读取本条后再核对，避免覆盖较新的人工标注。",
        );
        setErrorNearActions(true);
      } finally {
        setSaving(false);
      }
    },
    [draft, item, nextId, reviewPackageId, services, validate],
  );

  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if (
        (event.ctrlKey || event.metaKey) &&
        event.key.toLowerCase() === "s"
      ) {
        event.preventDefault();
        if (!saving) {
          void save(false);
        }
      }
    };
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, [save, saving]);

  return (
    <section
      className="plain-section locked-review-page"
      aria-labelledby="locked-review-title"
    >
      <div className="template-breadcrumbs">
        <button
          type="button"
          disabled={saving}
          onClick={() => leaveCurrent(onBack)}
        >
          开发与维护
        </button>
        <span aria-hidden="true">/</span>
        <span>锁定集人工复核</span>
      </div>
      <div className="locked-review-page-heading">
        <div>
          <h1 id="locked-review-title">锁定集人工复核</h1>
          <p>
            请只根据两张原图填写。抽样线索不是答案，也不会自动写入人工标注。
          </p>
        </div>
        {reviewIndex ? (
          <div className="locked-review-progress" aria-label="复核进度">
            <strong>
              {reviewIndex.progress.completed} / {reviewIndex.progress.total} 已完成
            </strong>
            <span>{reviewIndex.progress.remaining} 条待复核</span>
          </div>
        ) : null}
      </div>
      {message ? (
        <p className="locked-review-message" role="alert">
          {message}
        </p>
      ) : null}
      {error && !errorNearActions ? (
        <p className="locked-review-error" role="alert">
          {error}
        </p>
      ) : null}
      {reviewIndex ? (
        <div className="locked-review-layout">
          <aside
            className="locked-review-list-panel"
            aria-labelledby="locked-review-list-title"
          >
            <h2 id="locked-review-list-title">50 条样本</h2>
            <div
              className="locked-review-filters"
              role="group"
              aria-label="样本筛选"
            >
              {(
                [
                  ["all", "全部"],
                  ["pending", "待复核"],
                  ["completed", "已完成"],
                ] as const
              ).map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  disabled={saving}
                  aria-pressed={filter === value}
                  onClick={() => setFilter(value)}
                >
                  {label}
                </button>
              ))}
            </div>
            {filteredItems.length === 0 ? (
              <p className="locked-review-filter-empty">当前筛选下没有样本。</p>
            ) : (
              <ol className="locked-review-sample-list">
                {filteredItems.map((summary) => (
                  <li key={summary.sampleId}>
                    <button
                      type="button"
                      disabled={saving}
                      aria-current={
                        summary.sampleId === selectedSampleId
                          ? "true"
                          : undefined
                      }
                      onClick={() => chooseSample(summary.sampleId)}
                    >
                      <span>{formatSample(summary.position)}</span>
                      <small>
                        {summary.reviewStatus === "pending"
                          ? "待复核"
                          : summary.reviewStatus === "replace_candidate"
                            ? "申请更换"
                            : "已完成"}
                      </small>
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </aside>
          <div className="locked-review-workspace">
            {loading ? (
              <p role="status">正在读取样本原图…</p>
            ) : item && draft ? (
              <>
                <div className="locked-review-item-heading">
                  <div>
                    <h2 ref={itemHeading} tabIndex={-1}>
                      {formatSample(item.position)}
                    </h2>
                    <p>先看原图，再填写票据真实角色、净重和图片情况。</p>
                  </div>
                </div>
                {draftRecovered ? (
                  <p className="locked-review-recovery-note" role="status">
                    已恢复本条尚未提交的填写内容。
                  </p>
                ) : null}
                <div className="locked-review-images">
                  {item.images.map((image) => {
                    const imageDraft = draft.images.find(
                      (current) =>
                        current.submittedSlot === image.submittedSlot,
                    );
                    return imageDraft ? (
                      <ImageReviewPane
                        key={image.submittedSlot}
                        image={image}
                        draft={imageDraft}
                        onChange={(next) =>
                          updateImage(image.submittedSlot, next)
                        }
                      />
                    ) : null;
                  })}
                </div>
                <section
                  className="locked-review-pair"
                  aria-labelledby="locked-review-pair-title"
                >
                  <h3 id="locked-review-pair-title">两张图片放在一起看</h3>
                  <fieldset className="locked-review-fieldset">
                    <legend>这条样本属于哪种情况？</legend>
                    <div className="locked-review-pair-options">
                      {pairOptions.map((option) => (
                        <label key={option.value}>
                          <input
                            type="radio"
                            name="pair-condition"
                            checked={draft.pairConditions.includes(
                              option.value,
                            )}
                            onChange={() =>
                              setDraft({
                                ...draft,
                                pairConditions: [
                                  option.value,
                                  ...(draft.pairConditions.includes(
                                    "duplicate_upload",
                                  )
                                    ? ([
                                        "duplicate_upload",
                                      ] as LockedSetPairCondition[])
                                    : []),
                                ],
                              })
                            }
                          />
                          {option.label}
                        </label>
                      ))}
                      <label>
                        <input
                          type="checkbox"
                          checked={draft.pairConditions.includes(
                            "duplicate_upload",
                          )}
                          onChange={() =>
                            setDraft({
                              ...draft,
                              pairConditions: draft.pairConditions.includes(
                                "duplicate_upload",
                              )
                                ? draft.pairConditions.filter(
                                    (condition) =>
                                      condition !== "duplicate_upload",
                                  )
                                : [
                                    ...draft.pairConditions,
                                    "duplicate_upload",
                                  ],
                            })
                          }
                        />
                        疑似重复上传（可与上面的结论同时选择）
                      </label>
                    </div>
                  </fieldset>
                  <label className="locked-review-text-field">
                    整条样本备注（选填）
                    <textarea
                      maxLength={REVIEW_NOTES_MAX_LENGTH}
                      rows={2}
                      value={draft.pairNotes}
                      onChange={(event) =>
                        setDraft({
                          ...draft,
                          pairNotes: event.target.value,
                        })
                      }
                    />
                  </label>
                </section>
                <section
                  className="locked-review-decision"
                  aria-labelledby="locked-review-decision-title"
                >
                  <h3 id="locked-review-decision-title">保存方式</h3>
                  <div className="locked-review-decision-options">
                    <label>
                      <input
                        type="radio"
                        name="review-decision"
                        checked={draft.decision === "confirmed"}
                        onChange={() =>
                          setDraft({
                            ...draft,
                            decision: "confirmed",
                            replaceReason: "",
                          })
                        }
                      />
                      确认并保存人工标注
                    </label>
                    <label>
                      <input
                        type="radio"
                        name="review-decision"
                        checked={draft.decision === "replace_candidate"}
                        onChange={() =>
                          setDraft({
                            ...draft,
                            decision: "replace_candidate",
                            pairConditions: [],
                            pairNotes: "",
                          })
                        }
                      />
                      这条不适合作为锁定集样本，申请更换
                    </label>
                  </div>
                  {draft.decision === "replace_candidate" ? (
                    <label className="locked-review-text-field">
                      更换原因
                      <textarea
                        maxLength={REVIEW_NOTES_MAX_LENGTH}
                        rows={2}
                        value={draft.replaceReason}
                        onChange={(event) =>
                          setDraft({
                            ...draft,
                            replaceReason: event.target.value,
                          })
                        }
                      />
                    </label>
                  ) : null}
                </section>
                <details className="locked-review-clues">
                  <summary>抽样线索（不是答案）</summary>
                  <p>
                    这些内容只解释为什么系统把本条列入候选，不能替代人工看图。
                  </p>
                  <ul>
                    {[
                      ...item.selectionClues,
                      ...item.images.flatMap((image) => image.selectionClues),
                    ].map((clue, index) => (
                      <li key={`${clue}-${index}`}>{clueLabel(clue)}</li>
                    ))}
                  </ul>
                </details>
                <div className="locked-review-action-dock">
                  {errorNearActions && error ? (
                    <p
                      ref={actionError}
                      className="locked-review-error"
                      role="alert"
                      tabIndex={-1}
                    >
                      {error}
                    </p>
                  ) : null}
                  <div className="locked-review-actions">
                    <div>
                      <button
                        className="button button-secondary"
                        type="button"
                        disabled={!previousId || saving}
                        onClick={() =>
                          previousId && chooseSample(previousId)
                        }
                      >
                        上一条
                      </button>
                      <button
                        className="button button-secondary"
                        type="button"
                        disabled={!nextId || saving}
                        onClick={() => nextId && chooseSample(nextId)}
                      >
                        下一条
                      </button>
                    </div>
                    <div>
                      <span>
                        {dirty
                          ? "尚未提交，刷新后会恢复"
                          : "可按 Ctrl+S 保存当前条"}
                      </span>
                      <button
                        className="button button-secondary"
                        type="button"
                        disabled={saving}
                        onClick={() => void save(false)}
                      >
                        {saving ? "正在保存…" : "保存"}
                      </button>
                      <button
                        className="button primary"
                        type="button"
                        disabled={saving || !nextId}
                        onClick={() => void save(true)}
                      >
                        {saving ? "正在保存…" : "保存并下一条"}
                      </button>
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <p>当前复核包中没有可显示的样本。</p>
            )}
          </div>
        </div>
      ) : loading ? (
        <p role="status">正在读取锁定集复核资料…</p>
      ) : null}
    </section>
  );
}
