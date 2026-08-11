import type {
  StagedTemplateReference,
  TemplateDraft,
  TemplateRole,
} from "../../api/templateContracts";

export type TemplateStudioStep = "anchors" | "regions";

export interface TemplateCreationRecovery {
  schemaVersion: 1;
  creationOpen: boolean;
  creationName: string;
  creationRole: TemplateRole | "";
  stagedReference: StagedTemplateReference | null;
  creationDraft: TemplateDraft;
  step: TemplateStudioStep;
  selectedAnchorId: string | null;
  selectedRegionId: string | null;
}

const CREATION_RECOVERY_KEY = "dahe.template-studio.creation-draft.v1";

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

export function readTemplateCreationRecovery(): TemplateCreationRecovery | null {
  try {
    const raw = sessionStorage.getItem(CREATION_RECOVERY_KEY);
    if (raw === null) {
      return null;
    }
    const value = JSON.parse(raw) as Partial<TemplateCreationRecovery>;
    if (
      value.schemaVersion !== 1 ||
      typeof value.creationOpen !== "boolean" ||
      typeof value.creationName !== "string" ||
      (value.creationRole !== "" &&
        value.creationRole !== "loading" &&
        value.creationRole !== "unloading") ||
      !value.creationDraft ||
      !Array.isArray(value.creationDraft.anchors) ||
      !Array.isArray(value.creationDraft.regions) ||
      (value.step !== "anchors" && value.step !== "regions")
    ) {
      sessionStorage.removeItem(CREATION_RECOVERY_KEY);
      return null;
    }
    return {
      schemaVersion: 1,
      creationOpen: value.creationOpen,
      creationName: value.creationName,
      creationRole: value.creationRole,
      stagedReference: value.stagedReference ?? null,
      creationDraft: cloneDraft(value.creationDraft),
      step: value.step,
      selectedAnchorId: value.selectedAnchorId ?? null,
      selectedRegionId: value.selectedRegionId ?? null,
    };
  } catch {
    sessionStorage.removeItem(CREATION_RECOVERY_KEY);
    return null;
  }
}

export function hasRecoverableTemplateCreation(): boolean {
  return readTemplateCreationRecovery() !== null;
}

export function writeTemplateCreationRecovery(
  recovery: TemplateCreationRecovery,
): void {
  sessionStorage.setItem(CREATION_RECOVERY_KEY, JSON.stringify(recovery));
}

export function clearTemplateCreationRecovery(): void {
  sessionStorage.removeItem(CREATION_RECOVERY_KEY);
}
