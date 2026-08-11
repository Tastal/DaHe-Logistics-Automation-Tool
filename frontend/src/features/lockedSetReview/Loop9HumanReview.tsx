import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import type { AppServices } from "../../app/contracts";
import type {
  Loop9PairCondition,
  Loop9QualityCondition,
  Loop9ReviewImage,
  Loop9ReviewIndex,
  Loop9ReviewItem,
  Loop9ReviewTruth,
  Loop9TicketRole,
  Loop9TruthImage,
} from "../../api/loop9ReviewContracts";
import {
  ReviewImageViewer,
  type LockedSetReviewNavigationState,
} from "./LockedSetReview";

const orientationOptions: Array<{
  value: Loop9QualityCondition;
  label: string;
}> = [
  { value: "rotation_0", label: "正向 0°" },
  { value: "rotation_90", label: "右转 90°" },
  { value: "rotation_180", label: "倒置 180°" },
  { value: "rotation_270", label: "左转 90°" },
];

const qualityOptions: Array<{
  value: Loop9QualityCondition;
  label: string;
}> = [
  { value: "blur", label: "模糊／清晰度不足" },
  { value: "glare", label: "有反光" },
  { value: "crop", label: "有裁边或内容缺失" },
  { value: "screen", label: "屏幕拍摄" },
  { value: "printed", label: "打印票" },
  { value: "unknown_layout", label: "未知版式或非磅单" },
];

const pairOptions: Array<{
  value: Loop9PairCondition;
  label: string;
}> = [
  { value: "normal_pair", label: "正常一装一卸" },
  { value: "suspected_swapped", label: "疑似两张票放反" },
  { value: "both_loading", label: "两张都是装货票" },
  { value: "both_unloading", label: "两张都是卸货票" },
  { value: "unknown_or_non_ticket", label: "至少一张无法判断或不是磅单" },
];

const roleOptions: Array<{
  value: Loop9TicketRole;
  label: string;
}> = [
  { value: "loading", label: "装货票" },
  { value: "unloading", label: "卸货票" },
  { value: "unknown", label: "无法判断" },
];

function formatSample(position: number): string {
  return `样本 ${String(position).padStart(2, "0")}`;
}

function fingerprint(value: Loop9ReviewTruth): string {
  return JSON.stringify(value);
}

function inferPairCondition(
  images: Loop9TruthImage[],
): Loop9PairCondition {
  const roles = Object.fromEntries(
    images.map((image) => [image.slot, image.role]),
  );
  if (roles.loading === "loading" && roles.unloading === "unloading") {
    return "normal_pair";
  }
  if (roles.loading === "unloading" && roles.unloading === "loading") {
    return "suspected_swapped";
  }
  if (roles.loading === "loading" && roles.unloading === "loading") {
    return "both_loading";
  }
  if (roles.loading === "unloading" && roles.unloading === "unloading") {
    return "both_unloading";
  }
  return "unknown_or_non_ticket";
}

function truthFromItem(item: Loop9ReviewItem): Loop9ReviewTruth {
  if (item.truth) {
    return item.truth;
  }
  if (item.advisory.kind === "machine_result") {
    const machineBySlot = new Map(
      item.advisory.images.map((image) => [image.slot, image]),
    );
    const images = item.images.map((image): Loop9TruthImage => {
      const machine = machineBySlot.get(image.slot);
      return {
        slot: image.slot,
        imageSha256: image.imageSha256,
        role: machine?.predictedRole ?? "unknown",
        ordinaryNet:
          machine?.predictedRole === "unknown"
            ? null
            : (machine?.ordinaryNet ?? null),
        qualityConditions: [],
      };
    });
    return {
      images,
      pairCondition: inferPairCondition(images),
    };
  }
  return {
    images: item.images.map((image) => ({
      slot: image.slot,
      imageSha256: image.imageSha256,
      role: "unknown",
      ordinaryNet: null,
      qualityConditions: [],
    })),
    pairCondition: "unknown_or_non_ticket",
  };
}

function normalizeInputTruth(truth: Loop9ReviewTruth): Loop9ReviewTruth {
  return {
    images: truth.images.map((image) => ({
      ...image,
      ordinaryNet:
        image.role === "unknown"
          ? null
          : image.ordinaryNet?.trim() || null,
      qualityConditions: [...image.qualityConditions].sort(),
    })),
    pairCondition: truth.pairCondition,
  };
}

function validateTruth(truth: Loop9ReviewTruth | null): string | null {
  if (!truth || truth.images.length !== 2) {
    return "当前项目必须包含装货位置和卸货位置两张图片。";
  }
  for (const image of truth.images) {
    const label =
      image.slot === "loading" ? "装货位置原图" : "卸货位置原图";
    const orientationCount = image.qualityConditions.filter((condition) =>
      condition.startsWith("rotation_"),
    ).length;
    if (orientationCount !== 1) {
      return `请选择${label}的票面方向。`;
    }
    if (image.role === "unknown") {
      if (image.ordinaryNet !== null && image.ordinaryNet !== "") {
        return `${label}无法判断时，普通净重必须留空。`;
      }
    } else if (
      image.ordinaryNet === null ||
      !/^(?:0|[1-9]\d{0,2})(?:\.\d{1,2})?$/.test(
        image.ordinaryNet.trim(),
      ) ||
      Number(image.ordinaryNet) <= 0
    ) {
      return `请填写${label}的普通净重，单位为吨，最多两位小数。`;
    }
    if (
      image.qualityConditions.includes("unknown_layout") &&
      image.role !== "unknown"
    ) {
      return `${label}标为未知版式或非磅单时，角色必须选择“无法判断”。`;
    }
  }
  if (
    truth.pairCondition !== inferPairCondition(truth.images)
  ) {
    return "两张图片的组合结论与各自角色不一致。";
  }
  return null;
}

function MachineAdvisory({ item }: { item: Loop9ReviewItem }) {
  if (item.advisory.kind !== "machine_result") {
    return null;
  }
  const outcomeLabels: Record<string, string> = {
    normal_ready: "机器判断：正常",
    awaiting_review: "机器判断：需要人工核对",
    technical_failed: "机器处理失败，仍需逐图确认",
  };
  return (
    <div className="loop9-machine-advisory">
      <strong>
        {outcomeLabels[item.advisory.automaticOutcome] ??
          "机器结果待人工确认"}
      </strong>
      {item.advisory.images.map((image) => (
        <span key={image.slot}>
          {image.slot === "loading" ? "装货位置" : "卸货位置"}：
          {roleOptions.find((option) => option.value === image.predictedRole)
            ?.label ?? "无法判断"}
          {image.ordinaryNet ? `，${image.ordinaryNet} t` : ""}
        </span>
      ))}
      {item.advisory.diagnosticCode ? (
        <span>诊断编号：{item.advisory.diagnosticCode}</span>
      ) : null}
    </div>
  );
}

function ImageReviewPane({
  image,
  truth,
  platformWeight,
  checked,
  disabled,
  onChecked,
  onChange,
}: {
  image: Loop9ReviewImage;
  truth: Loop9TruthImage;
  platformWeight: string;
  checked: boolean;
  disabled: boolean;
  onChecked: (value: boolean) => void;
  onChange: (value: Loop9TruthImage) => void;
}) {
  const slotLabel =
    image.slot === "loading" ? "装货位置原图" : "卸货位置原图";
  const orientation =
    truth.qualityConditions.find((condition) =>
      condition.startsWith("rotation_"),
    ) ?? "";

  const setRole = (role: Loop9TicketRole) => {
    const unknown = role === "unknown";
    onChange({
      ...truth,
      role,
      ordinaryNet: unknown ? null : truth.ordinaryNet,
      qualityConditions: unknown
        ? truth.qualityConditions
        : truth.qualityConditions.filter(
            (condition) => condition !== "unknown_layout",
          ),
    });
  };

  const setOrientation = (condition: Loop9QualityCondition) => {
    onChange({
      ...truth,
      qualityConditions: [
        ...truth.qualityConditions.filter(
          (current) => !current.startsWith("rotation_"),
        ),
        condition,
      ],
    });
  };

  const toggleQuality = (condition: Loop9QualityCondition) => {
    const selecting = !truth.qualityConditions.includes(condition);
    onChange({
      ...truth,
      role:
        condition === "unknown_layout" && selecting
          ? "unknown"
          : truth.role,
      ordinaryNet:
        condition === "unknown_layout" && selecting
          ? null
          : truth.ordinaryNet,
      qualityConditions: selecting
        ? [...truth.qualityConditions, condition]
        : truth.qualityConditions.filter((current) => current !== condition),
    });
  };

  return (
    <section className="locked-review-image-pane">
      <div className="locked-review-pane-heading">
        <h3>{slotLabel}</h3>
        <p>平台净重：{platformWeight} t</p>
      </div>
      <ReviewImageViewer
        key={image.imageUrl}
        image={image}
        slotLabel={image.slot === "loading" ? "装货位置" : "卸货位置"}
      />
      <fieldset className="locked-review-fieldset" disabled={disabled}>
        <legend>这张图片实际是什么？</legend>
        <div className="locked-review-radio-row">
          {roleOptions.map((option) => (
            <label key={option.value}>
              <input
                type="radio"
                name={`${image.slot}-loop9-role`}
                checked={truth.role === option.value}
                onChange={() => setRole(option.value)}
              />
              <span>{option.label}</span>
            </label>
          ))}
        </div>
      </fieldset>
      <label className="locked-review-text-field">
        <span>普通净重（吨）</span>
        <input
          type="text"
          inputMode="decimal"
          value={truth.ordinaryNet ?? ""}
          disabled={disabled || truth.role === "unknown"}
          placeholder={truth.role === "unknown" ? "无法判断时留空" : "例如 30.25"}
          onChange={(event) =>
            onChange({
              ...truth,
              ordinaryNet: event.target.value,
            })
          }
        />
      </label>
      <fieldset className="locked-review-fieldset" disabled={disabled}>
        <legend>票面方向</legend>
        <div className="locked-review-option-grid">
          {orientationOptions.map((option) => (
            <label key={option.value}>
              <input
                type="radio"
                name={`${image.slot}-loop9-orientation`}
                checked={orientation === option.value}
                onChange={() => setOrientation(option.value)}
              />
              <span>{option.label}</span>
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset className="locked-review-fieldset" disabled={disabled}>
        <legend>图片情况（可多选）</legend>
        <div className="locked-review-option-grid">
          {qualityOptions.map((option) => (
            <label key={option.value}>
              <input
                type="checkbox"
                checked={truth.qualityConditions.includes(option.value)}
                onChange={() => toggleQuality(option.value)}
              />
              <span>{option.label}</span>
            </label>
          ))}
        </div>
      </fieldset>
      <label className="loop9-original-check">
        <input
          type="checkbox"
          checked={checked}
          disabled={disabled}
          onChange={(event) => onChecked(event.target.checked)}
        />
        <span>已核对{image.slot === "loading" ? "装货" : "卸货"}位置原图</span>
      </label>
    </section>
  );
}

export function Loop9HumanReview({
  services,
  onBack,
  onNavigationStateChange,
}: {
  services: AppServices;
  onBack?: () => void;
  onNavigationStateChange?: (
    state: LockedSetReviewNavigationState,
  ) => void;
}) {
  const available =
    services.loadLoop9Review !== undefined &&
    services.loadLoop9ReviewItem !== undefined &&
    services.saveLoop9ReviewDraft !== undefined &&
    services.confirmLoop9ReviewItem !== undefined &&
    services.exportLoop9Review !== undefined;
  const [reviewIndex, setReviewIndex] =
    useState<Loop9ReviewIndex | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [item, setItem] = useState<Loop9ReviewItem | null>(null);
  const [truth, setTruth] = useState<Loop9ReviewTruth | null>(null);
  const [baseline, setBaseline] = useState("");
  const [checked, setChecked] = useState({
    loading: false,
    unloading: false,
  });
  const [loading, setLoading] = useState(available);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(
    available ? null : "Loop 9 人工复核工具当前不可用。",
  );
  const detailRequest = useRef(0);

  const dirty = useMemo(
    () => truth !== null && fingerprint(truth) !== baseline,
    [baseline, truth],
  );

  useEffect(() => {
    onNavigationStateChange?.({ dirty, saving });
  }, [dirty, onNavigationStateChange, saving]);

  useEffect(
    () => () =>
      onNavigationStateChange?.({ dirty: false, saving: false }),
    [onNavigationStateChange],
  );

  useEffect(() => {
    if (!services.loadLoop9Review) {
      return;
    }
    let disposed = false;
    void services
      .loadLoop9Review()
      .then((next) => {
        if (disposed) {
          return;
        }
        setReviewIndex(next);
        setSelectedId(
          next.items.find((summary) => summary.reviewStatus !== "confirmed")
            ?.itemIdentitySha256 ??
            next.items[0]?.itemIdentitySha256 ??
            null,
        );
        setLoading(next.items.length > 0);
      })
      .catch(() => {
        if (!disposed) {
          setError("人工复核资料暂时无法读取，尚未修改任何内容。");
          setLoading(false);
        }
      });
    return () => {
      disposed = true;
    };
  }, [services]);

  useEffect(() => {
    if (!selectedId || !services.loadLoop9ReviewItem) {
      return;
    }
    const requestId = detailRequest.current + 1;
    detailRequest.current = requestId;
    void services
      .loadLoop9ReviewItem(selectedId)
      .then((next) => {
        if (requestId !== detailRequest.current) {
          return;
        }
        const nextTruth = truthFromItem(next);
        setItem(next);
        setTruth(nextTruth);
        setBaseline(fingerprint(nextTruth));
        setChecked({ loading: false, unloading: false });
        setError(null);
        setLoading(false);
      })
      .catch(() => {
        if (requestId === detailRequest.current) {
          setError("这条项目暂时无法读取，现有人工复核内容没有改变。");
          setLoading(false);
        }
      });
  }, [selectedId, services]);

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

  const orderedItems = useMemo(
    () =>
      reviewIndex
        ? [...reviewIndex.items].sort(
            (left, right) => left.position - right.position,
          )
        : [],
    [reviewIndex],
  );

  const updateTruthImage = (
    slot: "loading" | "unloading",
    next: Loop9TruthImage,
  ) => {
    setTruth((current) => {
      if (!current) {
        return current;
      }
      const images = current.images.map((image) =>
        image.slot === slot ? next : image,
      );
      return {
        images,
        pairCondition: inferPairCondition(images),
      };
    });
    setChecked((current) => ({ ...current, [slot]: false }));
  };

  const updateIndex = useCallback(
    (
      savedItem: Loop9ReviewItem,
      progress: Loop9ReviewIndex["progress"],
      revision: string,
    ) => {
      setReviewIndex((current) =>
        current
          ? {
              ...current,
              progress,
              reviewRevisionSha256: revision,
              items: current.items.map((summary) =>
                summary.itemIdentitySha256 ===
                savedItem.itemIdentitySha256
                  ? {
                      ...summary,
                      reviewStatus: savedItem.reviewStatus,
                      recordVersion: savedItem.recordVersion,
                    }
                  : summary,
              ),
            }
          : current,
      );
    },
    [],
  );

  const save = useCallback(
    async (confirm: boolean) => {
      const validation = validateTruth(truth);
      if (validation) {
        setError(validation);
        return;
      }
      if (
        !truth ||
        !item ||
        !services.saveLoop9ReviewDraft ||
        !services.confirmLoop9ReviewItem
      ) {
        setError("人工复核保存接口当前不可用。");
        return;
      }
      if (confirm && (!checked.loading || !checked.unloading)) {
        setError("请分别核对两张原图后再确认本条。");
        return;
      }
      const normalized = normalizeInputTruth(truth);
      setSaving(true);
      setError(null);
      setMessage(null);
      try {
        const result = await (confirm
          ? services.confirmLoop9ReviewItem(
              item.itemIdentitySha256,
              {
                expectedRecordVersion: item.recordVersion,
                truth: normalized,
                verifiedImageSha256s: item.images.map(
                  (image) => image.imageSha256,
                ) as [string, string],
              },
            )
          : services.saveLoop9ReviewDraft(
              item.itemIdentitySha256,
              {
                expectedRecordVersion: item.recordVersion,
                truth: normalized,
              },
            ));
        setItem(result.item);
        const savedTruth = result.item.truth ?? normalized;
        setTruth(savedTruth);
        setBaseline(fingerprint(savedTruth));
        updateIndex(
          result.item,
          result.progress,
          result.reviewRevisionSha256,
        );
        setMessage(
          confirm
            ? `${formatSample(item.position)}已确认。`
            : `${formatSample(item.position)}草稿已保存。`,
        );
        if (confirm) {
          const currentIndex = orderedItems.findIndex(
            (summary) =>
              summary.itemIdentitySha256 === item.itemIdentitySha256,
          );
          const next = [
            ...orderedItems.slice(currentIndex + 1),
            ...orderedItems.slice(0, currentIndex),
          ].find(
            (summary) =>
              summary.itemIdentitySha256 !== item.itemIdentitySha256 &&
              summary.reviewStatus !== "confirmed",
          );
          if (next) {
            setLoading(true);
            setSelectedId(next.itemIdentitySha256);
          }
        }
      } catch {
        setError(
          "这次保存尚未确认完成。页面不会猜测结果，请重新读取本条后再核对。",
        );
      } finally {
        setSaving(false);
      }
    },
    [
      checked.loading,
      checked.unloading,
      item,
      orderedItems,
      services,
      truth,
      updateIndex,
    ],
  );

  const exportAnswers = useCallback(async () => {
    if (
      !reviewIndex ||
      reviewIndex.progress.remaining !== 0 ||
      !services.exportLoop9Review
    ) {
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const result = await services.exportLoop9Review(
        reviewIndex.reviewRevisionSha256,
      );
      setMessage(`人工复核答案已封存：${result.fileName}`);
    } catch {
      setError("封存失败。请刷新并确认全部项目仍已完成。");
    } finally {
      setSaving(false);
    }
  }, [reviewIndex, services]);

  const selectItem = (identity: string) => {
    if (identity === selectedId || saving) {
      return;
    }
    if (
      dirty &&
      !window.confirm("当前填写尚未保存。是否放弃本地修改并切换？")
    ) {
      return;
    }
    setLoading(true);
    setSelectedId(identity);
    setMessage(null);
    setError(null);
  };

  const suggestionUnchanged =
    item?.advisory.kind === "draft_suggestion" &&
    truth !== null &&
    fingerprint(normalizeInputTruth(truth)) ===
      fingerprint({
        images: item.advisory.images,
        pairCondition: item.advisory.pairCondition,
      });
  const confirmLabel =
    item?.reviewKind === "current_locked_50"
      ? suggestionUnchanged
        ? "建议正确，确认并下一条"
        : "保存修改并下一条"
      : "确认本条并下一条";

  const leaveReview = () => {
    if (!onBack) {
      return;
    }
    if (saving) {
      setMessage("当前复核正在保存，请等待保存完成后再离开。");
      return;
    }
    if (
      dirty &&
      !window.confirm("当前填写尚未保存。是否放弃本地修改并离开？")
    ) {
      return;
    }
    onBack();
  };

  return (
    <section
      className="plain-section locked-review-page"
      aria-labelledby="loop9-review-title"
    >
      {onBack ? (
        <div className="template-breadcrumbs">
          <button type="button" disabled={saving} onClick={leaveReview}>
            开发与维护
          </button>
          <span aria-hidden="true">/</span>
          <span>Loop 9 人工复核</span>
        </div>
      ) : null}
      <div className="locked-review-page-heading">
        <div>
          <h1 id="loop9-review-title">
            {reviewIndex?.reviewKind === "real_shadow_30"
              ? "真实影子结果人工核对"
              : "当前构建锁定集人工复核"}
          </h1>
        </div>
        {reviewIndex ? (
          <div className="locked-review-progress" aria-label="复核进度">
            <strong>
              {reviewIndex.progress.confirmed} / {reviewIndex.progress.total} 已确认
            </strong>
            <span>
              {reviewIndex.progress.draft} 条草稿，
              {reviewIndex.progress.remaining} 条未完成
            </span>
          </div>
        ) : null}
      </div>
      {reviewIndex ? (
        <p className="locked-review-message" role="status">
          {reviewIndex.advisoryMessage}
        </p>
      ) : null}
      {message ? (
        <p className="locked-review-message" role="status">
          {message}
        </p>
      ) : null}
      {error ? (
        <p className="locked-review-error" role="alert">
          {error}
        </p>
      ) : null}
      {reviewIndex ? (
        <div className="locked-review-layout">
          <aside className="locked-review-list-panel">
            <h2>全部项目</h2>
            <ol className="locked-review-sample-list">
              {orderedItems.map((summary) => (
                <li key={summary.itemIdentitySha256}>
                  <button
                    type="button"
                    aria-current={
                      summary.itemIdentitySha256 === selectedId
                        ? "true"
                        : undefined
                    }
                    disabled={saving}
                    onClick={() =>
                      selectItem(summary.itemIdentitySha256)
                    }
                  >
                    <span>{formatSample(summary.position)}</span>
                    <small>
                      {summary.reviewStatus === "confirmed"
                        ? "已确认"
                        : summary.reviewStatus === "draft"
                          ? "有草稿"
                          : "未复核"}
                    </small>
                  </button>
                </li>
              ))}
            </ol>
          </aside>
          <div className="locked-review-workspace">
            {loading || !item || !truth ? (
              <p aria-busy="true">正在读取复核项目…</p>
            ) : (
              <>
                <div className="locked-review-item-heading">
                  <div>
                    <h2>{formatSample(item.position)}</h2>
                    <p>
                      {item.reviewStatus === "confirmed"
                        ? "本条已确认；证据变化后仍会按规则失效。"
                        : item.reviewStatus === "draft"
                          ? "已恢复服务端草稿。"
                          : "请逐张查看原图后确认。"}
                    </p>
                  </div>
                </div>
                <MachineAdvisory item={item} />
                <div className="locked-review-images">
                  {item.images.map((image) => {
                    const imageTruth = truth.images.find(
                      (candidate) => candidate.slot === image.slot,
                    );
                    if (!imageTruth) {
                      return null;
                    }
                    return (
                      <ImageReviewPane
                        key={image.slot}
                        image={image}
                        truth={imageTruth}
                        platformWeight={item.platformWeights[image.slot]}
                        checked={checked[image.slot]}
                        disabled={saving}
                        onChecked={(value) =>
                          setChecked((current) => ({
                            ...current,
                            [image.slot]: value,
                          }))
                        }
                        onChange={(next) =>
                          updateTruthImage(image.slot, next)
                        }
                      />
                    );
                  })}
                </div>
                <section className="locked-review-pair">
                  <h3>两张图片的组合结论</h3>
                  <div className="locked-review-pair-options">
                    {pairOptions.map((option) => (
                      <label key={option.value}>
                        <input
                          type="radio"
                          name="loop9-pair-condition"
                          value={option.value}
                          checked={truth.pairCondition === option.value}
                          disabled={saving}
                          onChange={() =>
                            setTruth((current) =>
                              current
                                ? {
                                    ...current,
                                    pairCondition: option.value,
                                  }
                                : current,
                            )
                          }
                        />
                        <span>{option.label}</span>
                      </label>
                    ))}
                  </div>
                </section>
                <div className="locked-review-action-dock">
                  <div className="locked-review-actions">
                    <div>
                      <button
                        className="button"
                        type="button"
                        disabled={saving}
                        onClick={() => void save(false)}
                      >
                        {saving ? "正在保存" : "保存草稿"}
                      </button>
                      <button
                        className="button primary"
                        type="button"
                        disabled={
                          saving ||
                          !checked.loading ||
                          !checked.unloading
                        }
                        onClick={() => void save(true)}
                      >
                        {confirmLabel}
                      </button>
                    </div>
                    <button
                      className="button"
                      type="button"
                      disabled={
                        saving || reviewIndex.progress.remaining !== 0
                      }
                      onClick={() => void exportAnswers()}
                    >
                      封存全部答案
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      ) : loading ? (
        <p aria-busy="true">正在读取人工复核资料…</p>
      ) : null}
    </section>
  );
}
