export type TemplateLifecycle = "draft" | "development_tested" | "shadow";
export type TemplateRole = "loading" | "unloading";

export interface TemplateAction {
  visible: boolean;
  enabled: boolean;
  reason: string | null;
  label: string;
  expectedRecordVersion: number | null;
  evaluationId: string | null;
}

export interface NormalizedBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface TemplateAnchor {
  anchorId: string;
  label: string;
  expectedText: string;
  matchMode: "exact" | "contains" | "pattern";
  required: boolean;
  roleEvidence: "loading" | "unloading" | "position_only";
  importance: "primary" | "supporting";
  bounds: NormalizedBounds;
}

export interface TemplateRegion {
  regionId: string;
  label: string;
  field:
    | "ordinary_net_weight"
    | "factory_net_weight"
    | "gross_weight"
    | "tare_weight"
    | "loading_weigh_time"
    | "unloading_tare_time"
    | "print_time";
  valueType: "weight" | "time" | "text";
  unit: "ton" | "kilogram" | "printed";
  required: boolean;
  anchorId: string;
  bounds: NormalizedBounds;
}

export interface TemplateDraft {
  anchors: TemplateAnchor[];
  regions: TemplateRegion[];
}

export interface TemplateMetric {
  metricId: string;
  label: string;
  valueLabel: string;
}

export interface TemplateReferenceImage {
  imageId: string;
  contentUrl: string;
  alt: string;
  width: number;
  height: number;
  rotation: 0 | 90 | 180 | 270;
}

export interface StagedTemplateReference extends TemplateReferenceImage {
  stagedReferenceId: string;
  recordVersion: number;
  rotation: 0;
}

export interface TemplateVersionSnapshot {
  versionId: string;
  recordVersion: number;
  familyId: string;
  familyName: string;
  purpose: TemplateRole;
  purposeLabel: string;
  lifecycle: TemplateLifecycle;
  lifecycleLabel: string;
  referenceImage: TemplateReferenceImage;
  draft: TemplateDraft;
  actions: Record<string, TemplateAction>;
  checkReport: {
    summaryLabel: string;
    scopeLabel: string;
    warning: string;
    metrics: TemplateMetric[];
  } | null;
}

export interface TemplateFamilySummary {
  familyId: string;
  name: string;
  purposeLabel: string;
  currentVersionLabel: string;
  lifecycleLabel: string;
}

export interface TemplateFamilyIndex {
  maintenance: {
    authorized: boolean;
    statusLabel: string;
    expiresAtLabel: string | null;
  };
  families: TemplateFamilySummary[];
  actions: Record<string, TemplateAction>;
  acceptanceSet: {
    waybillCount: number;
    targetWaybillCount: number;
    statusLabel: string;
  };
}

export interface TemplateFamilyVersionOption {
  versionId: string;
  versionNumber: number;
  lifecycleLabel: string;
  isCurrentShadow: boolean;
  canRollback: boolean;
  label: string;
}

export interface TemplateRollbackOptions {
  familyId: string;
  currentShadowVersionId: string | null;
  currentShadowRecordVersion: number | null;
  versions: TemplateFamilyVersionOption[];
}

export interface TemplateRollbackResult {
  applied: boolean;
  familyId: string;
  versionId: string;
  recordVersion: number;
}

interface WireTemplateAction {
  visible: boolean;
  enabled: boolean;
  reason: string | null;
  label: string;
  expected_record_version?: number | null;
  evaluation_id?: string | null;
}

interface WireBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface WireTemplateAnchor {
  anchor_id: string;
  label: string;
  expected_text: string;
  match_mode: TemplateAnchor["matchMode"];
  required: boolean;
  role_evidence: TemplateAnchor["roleEvidence"];
  importance: TemplateAnchor["importance"];
  bounds: WireBounds;
}

interface WireTemplateRegion {
  region_id: string;
  label: string;
  field: TemplateRegion["field"];
  value_type: TemplateRegion["valueType"];
  unit: TemplateRegion["unit"];
  required: boolean;
  anchor_id: string;
  bounds: WireBounds;
}

type WireTemplateAnchorInput = Omit<WireTemplateAnchor, "label">;

type WireTemplateRegionInput = Omit<WireTemplateRegion, "label">;

export interface WireTemplateFamilyIndex {
  maintenance: {
    authorized: boolean;
    status_label: string;
    expires_at_label: string | null;
  };
  families: Array<{
    family_id: string;
    name: string;
    purpose_label: string;
    current_version_label: string;
    lifecycle_label: string;
  }>;
  actions: Record<string, WireTemplateAction>;
  acceptance_set: {
    waybill_count: number;
    target_waybill_count: number;
    status_label: string;
  };
}

export interface WireTemplateVersionSnapshot {
  version_id: string;
  record_version: number;
  family_id: string;
  family_name: string;
  purpose: TemplateRole;
  purpose_label: string;
  lifecycle: TemplateLifecycle;
  lifecycle_label: string;
  reference_image: {
    image_id: string;
    content_url: string;
    alt: string;
    width: number;
    height: number;
    rotation: 0 | 90 | 180 | 270;
  };
  draft: {
    anchors: WireTemplateAnchor[];
    regions: WireTemplateRegion[];
  };
  actions: Record<string, WireTemplateAction>;
  check_report: {
    summary_label: string;
    scope_label: string;
    warning: string;
    metrics: Array<{
      metric_id: string;
      label: string;
      value_label: string;
    }>;
  } | null;
}

export interface WireStagedTemplateReference {
  staged_reference_id: string;
  image_id: string;
  content_url: string;
  alt: string;
  width: number;
  height: number;
  record_version: number;
}

export interface WireTemplateRollbackOptions {
  family_id: string;
  current_shadow: {
    version_id: string;
    record_version: number;
  } | null;
  versions: Array<{
    version_id: string;
    version_number: number;
    lifecycle_label: string;
    is_current_shadow: boolean;
    can_rollback: boolean;
    label: string;
  }>;
}

function mapBounds(bounds: WireBounds): NormalizedBounds {
  return {
    x: bounds.x,
    y: bounds.y,
    width: bounds.width,
    height: bounds.height,
  };
}

function mapAction(action: WireTemplateAction): TemplateAction {
  return {
    visible: action.visible,
    enabled: action.enabled,
    reason: action.reason,
    label: action.label,
    expectedRecordVersion: action.expected_record_version ?? null,
    evaluationId: action.evaluation_id ?? null,
  };
}

export function mapTemplateFamilyIndex(
  wire: WireTemplateFamilyIndex,
): TemplateFamilyIndex {
  return {
    maintenance: {
      authorized: wire.maintenance.authorized,
      statusLabel: wire.maintenance.status_label,
      expiresAtLabel: wire.maintenance.expires_at_label,
    },
    families: wire.families.map((family) => ({
      familyId: family.family_id,
      name: family.name,
      purposeLabel: family.purpose_label,
      currentVersionLabel: family.current_version_label,
      lifecycleLabel: family.lifecycle_label,
    })),
    actions: Object.fromEntries(
      Object.entries(wire.actions).map(([actionId, action]) => [
        actionId,
        mapAction(action),
      ]),
    ),
    acceptanceSet: {
      waybillCount: wire.acceptance_set.waybill_count,
      targetWaybillCount: wire.acceptance_set.target_waybill_count,
      statusLabel: wire.acceptance_set.status_label,
    },
  };
}

export function mapTemplateVersion(
  wire: WireTemplateVersionSnapshot,
): TemplateVersionSnapshot {
  return {
    versionId: wire.version_id,
    recordVersion: wire.record_version,
    familyId: wire.family_id,
    familyName: wire.family_name,
    purpose: wire.purpose,
    purposeLabel: wire.purpose_label,
    lifecycle: wire.lifecycle,
    lifecycleLabel: wire.lifecycle_label,
    referenceImage: {
      imageId: wire.reference_image.image_id,
      contentUrl: wire.reference_image.content_url,
      alt: wire.reference_image.alt,
      width: wire.reference_image.width,
      height: wire.reference_image.height,
      rotation: wire.reference_image.rotation,
    },
    draft: {
      anchors: wire.draft.anchors.map((anchor) => ({
        anchorId: anchor.anchor_id,
        label: anchor.label,
        expectedText: anchor.expected_text,
        matchMode: anchor.match_mode,
        required: anchor.required,
        roleEvidence: anchor.role_evidence,
        importance: anchor.importance,
        bounds: mapBounds(anchor.bounds),
      })),
      regions: wire.draft.regions.map((region) => ({
        regionId: region.region_id,
        label: region.label,
        field: region.field,
        valueType: region.value_type,
        unit: region.unit,
        required: region.required,
        anchorId: region.anchor_id,
        bounds: mapBounds(region.bounds),
      })),
    },
    actions: Object.fromEntries(
      Object.entries(wire.actions).map(([actionId, action]) => [
        actionId,
        mapAction(action),
      ]),
    ),
    checkReport:
      wire.check_report === null
          ? null
          : {
            summaryLabel: wire.check_report.summary_label,
            scopeLabel: wire.check_report.scope_label,
            warning: wire.check_report.warning,
            metrics: wire.check_report.metrics.map((metric) => ({
              metricId: metric.metric_id,
              label: metric.label,
              valueLabel: metric.value_label,
            })),
          },
  };
}

export function mapStagedTemplateReference(
  wire: WireStagedTemplateReference,
): StagedTemplateReference {
  return {
    stagedReferenceId: wire.staged_reference_id,
    imageId: wire.image_id,
    contentUrl: wire.content_url,
    alt: wire.alt,
    width: wire.width,
    height: wire.height,
    rotation: 0,
    recordVersion: wire.record_version,
  };
}

export function mapTemplateRollbackOptions(
  wire: WireTemplateRollbackOptions,
): TemplateRollbackOptions {
  return {
    familyId: wire.family_id,
    currentShadowVersionId: wire.current_shadow?.version_id ?? null,
    currentShadowRecordVersion: wire.current_shadow?.record_version ?? null,
    versions: wire.versions.map((version) => ({
      versionId: version.version_id,
      versionNumber: version.version_number,
      lifecycleLabel: version.lifecycle_label,
      isCurrentShadow: version.is_current_shadow,
      canRollback: version.can_rollback,
      label: version.label,
    })),
  };
}

export function serializeTemplateDraft(draft: TemplateDraft): {
  anchors: WireTemplateAnchorInput[];
  regions: WireTemplateRegionInput[];
} {
  return {
    anchors: draft.anchors.map((anchor) => ({
      anchor_id: anchor.anchorId,
      expected_text: anchor.expectedText,
      match_mode: anchor.matchMode,
      required: anchor.required,
      role_evidence: anchor.roleEvidence,
      importance: anchor.importance,
      bounds: { ...anchor.bounds },
    })),
    regions: draft.regions.map((region) => ({
      region_id: region.regionId,
      field: region.field,
      value_type: region.valueType,
      unit: region.unit,
      required: region.required,
      anchor_id: region.anchorId,
      bounds: { ...region.bounds },
    })),
  };
}
