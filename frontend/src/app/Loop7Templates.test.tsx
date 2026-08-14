import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import {
  App,
  type AppServices,
  type ConsoleSnapshot,
  type ServerAction,
} from "./App";
import { TemplateMaintenanceRequiredError } from "./contracts";

type TemplateLifecycle = "draft" | "development_tested" | "shadow";
type TemplateRole = "loading" | "unloading";

class TestPointerEvent extends MouseEvent {
  readonly pointerId: number;
  readonly isPrimary: boolean;

  constructor(type: string, init: PointerEventInit = {}) {
    super(type, init);
    this.pointerId = init.pointerId ?? 0;
    this.isPrimary = init.isPrimary ?? true;
  }
}

beforeAll(() => {
  vi.stubGlobal("PointerEvent", TestPointerEvent);
});

afterAll(() => {
  vi.unstubAllGlobals();
});

interface NormalizedBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface TemplateAnchor {
  anchorId: string;
  label: string;
  expectedText: string;
  matchMode: "exact" | "contains" | "pattern";
  required: boolean;
  roleEvidence: "loading" | "unloading" | "position_only";
  importance: "primary" | "supporting";
  bounds: NormalizedBounds;
}

interface TemplateRegion {
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

interface TemplateDraft {
  anchors: TemplateAnchor[];
  regions: TemplateRegion[];
}

interface TemplateMetric {
  metricId: string;
  label: string;
  valueLabel: string;
}

interface TemplateServerAction extends ServerAction {
  evaluationId: string | null;
}

interface TemplateVersionSnapshot {
  versionId: string;
  recordVersion: number;
  familyId: string;
  familyName: string;
  purpose: TemplateRole;
  purposeLabel: string;
  lifecycle: TemplateLifecycle;
  lifecycleLabel: string;
  referenceImage: {
    imageId: string;
    contentUrl: string;
    alt: string;
    width: number;
    height: number;
    rotation: 0 | 90 | 180 | 270;
  };
  draft: TemplateDraft;
  actions: Record<string, TemplateServerAction>;
  checkReport: {
    summaryLabel: string;
    scopeLabel: string;
    warning: string;
    metrics: TemplateMetric[];
  } | null;
}

interface StagedTemplateReference {
  stagedReferenceId: string;
  imageId: string;
  contentUrl: string;
  alt: string;
  width: number;
  height: number;
  rotation: 0;
  recordVersion: number;
}

interface TemplateFamilySummary {
  familyId: string;
  name: string;
  purposeLabel: string;
  currentVersionLabel: string;
  lifecycleLabel: string;
}

interface TemplateFamilyIndex {
  maintenance: {
    authorized: boolean;
    statusLabel: string;
    expiresAtLabel: string | null;
  };
  families: TemplateFamilySummary[];
  actions: Record<string, TemplateServerAction>;
  acceptanceSet: {
    waybillCount: number;
    targetWaybillCount: number;
    statusLabel: string;
  };
}

interface TemplateRollbackOptions {
  familyId: string;
  currentShadowVersionId: string | null;
  currentShadowRecordVersion: number | null;
  versions: Array<{
    versionId: string;
    versionNumber: number;
    lifecycleLabel: string;
    isCurrentShadow: boolean;
    canRollback: boolean;
    label: string;
  }>;
}

interface Loop7AppServices extends AppServices {
  loadTemplateFamilies(): Promise<TemplateFamilyIndex>;
  loadTemplateFamily(familyId: string): Promise<TemplateVersionSnapshot>;
  unlockTemplateMaintenance(accessCode: string): Promise<TemplateFamilyIndex>;
  uploadTemplateReference(file: File): Promise<StagedTemplateReference>;
  abandonTemplateReference(
    stagedReferenceId: string,
    expectedRecordVersion: number,
  ): Promise<void>;
  createTemplateFromStagedReference(
    stagedReferenceId: string,
    expectedRecordVersion: number,
    familyName: string,
    role: TemplateRole,
    draft: TemplateDraft,
  ): Promise<{ created: boolean; template: TemplateVersionSnapshot }>;
  saveTemplateDraft(
    versionId: string,
    expectedRecordVersion: number,
    draft: TemplateDraft,
  ): Promise<TemplateVersionSnapshot>;
  runTemplateDevelopmentCheck(
    versionId: string,
    expectedRecordVersion: number,
    evaluationId?: string,
  ): Promise<TemplateVersionSnapshot>;
  revalidateTemplateShadowAction(
    accessCode: string,
    versionId: string,
  ): Promise<string>;
  loadTemplateFamilyVersions(
    familyId: string,
  ): Promise<TemplateRollbackOptions>;
  revalidateTemplateRollbackAction(
    accessCode: string,
    familyId: string,
  ): Promise<string>;
  rollbackTemplateShadow(
    familyId: string,
    targetVersionId: string,
    expectedRecordVersion: number,
    reason: string,
    developerAuthorization: string,
  ): Promise<{
    applied: boolean;
    familyId: string;
    versionId: string;
    recordVersion: number;
  }>;
  runTemplateVersionAction(
    versionId: string,
    actionId: "start_shadow" | "restore_shadow",
    expectedRecordVersion: number,
  ): Promise<TemplateVersionSnapshot>;
}

const emptyConsoleSnapshot: ConsoleSnapshot = {
  eventCursor: 0,
  jobs: [],
  resources: [],
  startActions: {},
};

function action(
  label: string,
  expectedRecordVersion: number | null,
  overrides: Partial<TemplateServerAction> = {},
): TemplateServerAction {
  return {
    visible: true,
    enabled: true,
    reason: null,
    label,
    expectedRecordVersion,
    evaluationId: null,
    ...overrides,
  };
}

const anchor: TemplateAnchor = {
  anchorId: "anchor-net-label",
  label: "净重标签",
  expectedText: "净重",
  matchMode: "exact",
  required: true,
  roleEvidence: "loading",
  importance: "primary",
  bounds: {
    x: 0.1,
    y: 0.18,
    width: 0.16,
    height: 0.08,
  },
};

const region: TemplateRegion = {
  regionId: "region-ordinary-net",
  label: "普通净重",
  field: "ordinary_net_weight",
  valueType: "weight",
  unit: "ton",
  required: true,
  anchorId: anchor.anchorId,
  bounds: {
    x: 0.31,
    y: 0.18,
    width: 0.22,
    height: 0.08,
  },
};

const lockedIndex: TemplateFamilyIndex = {
  maintenance: {
    authorized: false,
    statusLabel: "未进入维护模式",
    expiresAtLabel: null,
  },
  families: [
    {
      familyId: "family-loading-a",
      name: "一号矿装货磅单",
      purposeLabel: "装货磅单",
      currentVersionLabel: "草稿 1",
      lifecycleLabel: "草稿",
    },
  ],
  actions: {
    create_template: action("添加第一个模板", null, {
      enabled: false,
      reason: "请先进入维护模式",
    }),
  },
  acceptanceSet: {
    waybillCount: 0,
    targetWaybillCount: 50,
    statusLabel: "独立验收样本尚未建立",
  },
};

const unlockedIndex: TemplateFamilyIndex = {
  ...lockedIndex,
  maintenance: {
    authorized: true,
    statusLabel: "维护模式已开启",
    expiresAtLabel: "15 分钟后自动退出",
  },
  actions: {
    create_template: action("添加第一个模板", null),
  },
};

const unlockedEmptyIndex: TemplateFamilyIndex = {
  ...unlockedIndex,
  families: [],
};

const stagedReference: StagedTemplateReference = {
  stagedReferenceId: "staged-reference-1",
  imageId: "reference-image-new",
  contentUrl:
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='1200' height='1800'/%3E",
  alt: "新模板参考图",
  width: 1200,
  height: 1800,
  rotation: 0,
  recordVersion: 3,
};

function versionSnapshot(
  overrides: Partial<TemplateVersionSnapshot> = {},
): TemplateVersionSnapshot {
  return {
    versionId: "template-version-1",
    recordVersion: 7,
    familyId: "family-loading-a",
    familyName: "一号矿装货磅单",
    purpose: "loading",
    purposeLabel: "装货磅单",
    lifecycle: "draft",
    lifecycleLabel: "草稿",
    referenceImage: {
      imageId: "reference-image-1",
      contentUrl:
        "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='800' height='500'/%3E",
      alt: "一号矿装货磅单参考图",
      width: 800,
      height: 500,
      rotation: 0,
    },
    draft: {
      anchors: [anchor],
      regions: [region],
    },
    actions: {
      save_draft: action("保存草稿", 7),
      run_development_check: action("确认开发样本检查", 7, {
        evaluationId: "development-evaluation-001",
      }),
    },
    checkReport: null,
    ...overrides,
  };
}

function services(
  overrides: Partial<Loop7AppServices> = {},
): Loop7AppServices {
  return {
    bootstrap: vi.fn().mockResolvedValue({
      applicationVersion: "1.0.0",
      csrfToken: "csrf-loop7",
      lockedSetReviewEnabled: false,
    }),
    loadSnapshot: vi.fn().mockResolvedValue(emptyConsoleSnapshot),
    loadResources: vi.fn().mockResolvedValue([]),
    loadJobItems: vi.fn().mockResolvedValue([]),
    createAuditJob: vi.fn().mockRejectedValue(new Error("Not used in Loop 7 tests.")),
    createFixtureJob: vi
      .fn()
      .mockRejectedValue(new Error("Not used in Loop 7 tests.")),
    subscribe: vi.fn().mockReturnValue(() => undefined),
    runJobAction: vi.fn().mockResolvedValue(undefined),
    loadTemplateFamilies: vi.fn().mockResolvedValue(lockedIndex),
    loadTemplateFamily: vi.fn().mockResolvedValue(versionSnapshot()),
    unlockTemplateMaintenance: vi.fn().mockResolvedValue(unlockedIndex),
    uploadTemplateReference: vi.fn().mockResolvedValue(stagedReference),
    abandonTemplateReference: vi.fn().mockResolvedValue(undefined),
    createTemplateFromStagedReference: vi.fn().mockResolvedValue({
      created: true,
      template: versionSnapshot(),
    }),
    saveTemplateDraft: vi.fn().mockImplementation(
      (
        _versionId: string,
        expectedRecordVersion: number,
        draft: TemplateDraft,
      ) =>
        Promise.resolve(
          versionSnapshot({
            recordVersion: expectedRecordVersion + 1,
            draft,
          }),
        ),
    ),
    runTemplateDevelopmentCheck: vi.fn().mockResolvedValue(versionSnapshot()),
    revalidateTemplateShadowAction: vi
      .fn()
      .mockResolvedValue("shadow-action-token"),
    loadTemplateFamilyVersions: vi.fn().mockResolvedValue({
      familyId: "family-loading-a",
      currentShadowVersionId: null,
      currentShadowRecordVersion: null,
      versions: [],
    }),
    revalidateTemplateRollbackAction: vi
      .fn()
      .mockResolvedValue("rollback-action-token"),
    rollbackTemplateShadow: vi.fn().mockResolvedValue({
      applied: true,
      familyId: "family-loading-a",
      versionId: "template-version-1",
      recordVersion: 2,
    }),
    runTemplateVersionAction: vi.fn().mockResolvedValue(
      versionSnapshot({
        lifecycle: "shadow",
        lifecycleLabel: "影子测试中",
      }),
    ),
    ...overrides,
  };
}

async function openTemplateWorkbench(
  user: ReturnType<typeof userEvent.setup>,
): Promise<void> {
  await user.click(await screen.findByRole("button", { name: "系统设置" }));
  await user.click(await screen.findByRole("button", { name: "识别模板" }));
}

const originalInnerWidth = window.innerWidth;

afterEach(() => {
  Object.defineProperty(window, "innerWidth", {
    configurable: true,
    value: originalInnerWidth,
  });
});

describe("Loop 7 template maintenance workspace", () => {
  it("places the template entry under System maintenance and keeps editing locked", async () => {
    const user = userEvent.setup();
    const appServices = services();
    render(<App services={appServices} />);

    await openTemplateWorkbench(user);

    expect(
      await screen.findByRole("heading", { name: "票据模板" }),
    ).toBeVisible();
    expect(
      screen.getByText("模板只能由已授权的维护人员修改。"),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "进入维护模式" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("textbox", { name: "维护验证码" }),
    ).toBeVisible();
    expect(
      screen.getByText("独立验收样本尚未建立"),
    ).toBeVisible();
    expect(screen.getByText("0/50 条运单")).toBeVisible();
    const statusList = screen.getByRole("region", { name: "现有模板" });
    expect(within(statusList).getByText("一号矿装货磅单")).toBeVisible();
    expect(within(statusList).getByText("草稿 1，草稿")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "保存草稿" }),
    ).toBeNull();
    expect(appServices.loadTemplateFamilies).toHaveBeenCalledTimes(1);
  });

  it("announces a failed maintenance verification as an alert", async () => {
    const user = userEvent.setup();
    render(
      <App
        services={services({
          unlockTemplateMaintenance: vi
            .fn()
            .mockRejectedValue(new Error("wrong code")),
        })}
      />,
    );
    await openTemplateWorkbench(user);

    await user.type(
      screen.getByRole("textbox", { name: "维护验证码" }),
      "wrong-code",
    );
    await user.click(
      screen.getByRole("button", { name: "进入维护模式" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "维护验证没有通过",
    );
  });

  it("unlocks editing only after the protected maintenance action succeeds", async () => {
    const user = userEvent.setup();
    const loadTemplateFamilies = vi
      .fn<Loop7AppServices["loadTemplateFamilies"]>()
      .mockResolvedValue(lockedIndex);
    const unlockTemplateMaintenance = vi
      .fn<Loop7AppServices["unlockTemplateMaintenance"]>()
      .mockResolvedValue(unlockedIndex);
    const appServices = services({
      loadTemplateFamilies,
      unlockTemplateMaintenance,
    });
    render(<App services={appServices} />);
    await openTemplateWorkbench(user);

    await user.type(
      screen.getByRole("textbox", { name: "维护验证码" }),
      "loop7-access",
    );
    await user.click(
      screen.getByRole("button", { name: "进入维护模式" }),
    );

    expect(unlockTemplateMaintenance).toHaveBeenCalledWith("loop7-access");
    expect(await screen.findByText("维护模式已开启")).toBeVisible();
    expect(screen.getByText("15 分钟后自动退出")).toBeVisible();
    expect(
      await screen.findByRole("button", { name: "保存草稿" }),
    ).toBeEnabled();
    expect(appServices.loadTemplateFamily).toHaveBeenCalledWith(
      "family-loading-a",
    );
  });

  it("shows an actionable first-template state for an authorized empty database", async () => {
    const user = userEvent.setup();
    const loadTemplateFamily = vi
      .fn<Loop7AppServices["loadTemplateFamily"]>()
      .mockResolvedValue(versionSnapshot());
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedEmptyIndex),
          loadTemplateFamily,
        })}
      />,
    );

    await openTemplateWorkbench(user);

    expect(
      await screen.findByRole("heading", { name: "还没有票据模板" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "添加第一个模板" }),
    ).toBeEnabled();
    expect(screen.queryByText("正在加载模板内容…")).toBeNull();
    expect(loadTemplateFamily).not.toHaveBeenCalled();
  });

  it("lists every family, switches the editor, and keeps add-template available", async () => {
    const user = userEvent.setup();
    const secondFamily = {
      familyId: "family-unloading-b",
      name: "二号矿卸货磅单",
      purposeLabel: "卸货磅单",
      currentVersionLabel: "草稿 2",
      lifecycleLabel: "草稿",
    };
    const twoFamilyIndex: TemplateFamilyIndex = {
      ...unlockedIndex,
      families: [...unlockedIndex.families, secondFamily],
    };
    const loadTemplateFamily = vi
      .fn<Loop7AppServices["loadTemplateFamily"]>()
      .mockImplementation((familyId) =>
        Promise.resolve(
          familyId === secondFamily.familyId
            ? versionSnapshot({
                familyId: secondFamily.familyId,
                familyName: secondFamily.name,
                purpose: "unloading",
                purposeLabel: "卸货磅单",
              })
            : versionSnapshot(),
        ),
      );
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(twoFamilyIndex),
          loadTemplateFamily,
        })}
      />,
    );
    await openTemplateWorkbench(user);

    expect(
      screen.getByRole("button", { name: "添加第一个模板" }),
    ).toBeEnabled();
    await user.click(
      screen.getByRole("button", {
        name: /二号矿卸货磅单卸货磅单草稿 2/,
      }),
    );

    expect(
      await screen.findByRole("heading", { name: "二号矿卸货磅单" }),
    ).toBeVisible();
    expect(loadTemplateFamily).toHaveBeenLastCalledWith(
      "family-unloading-b",
    );
  });

  it("keeps the backend create action authoritative in the empty state", async () => {
    const user = userEvent.setup();
    const reason = "当前维护会话不能创建模板";
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue({
            ...unlockedEmptyIndex,
            actions: {
              create_template: action("添加第一个模板", null, {
                enabled: false,
                reason,
              }),
            },
          }),
        })}
      />,
    );

    await openTemplateWorkbench(user);

    expect(
      screen.getByRole("button", { name: "添加第一个模板" }),
    ).toBeDisabled();
    expect(screen.getByText(reason)).toBeVisible();
  });

  it("asks for a PNG or JPEG before uploading the first reference image", async () => {
    const user = userEvent.setup();
    const uploadTemplateReference = vi
      .fn<Loop7AppServices["uploadTemplateReference"]>()
      .mockResolvedValue(stagedReference);
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedEmptyIndex),
          uploadTemplateReference,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      screen.getByRole("button", { name: "添加第一个模板" }),
    );

    await user.click(
      screen.getByRole("button", { name: "上传参考图片" }),
    );

    expect(
      screen.getByRole("alert", {
        name: "",
      }),
    ).toHaveTextContent("请先选择一张 PNG 或 JPEG 参考图片。");
    expect(uploadTemplateReference).not.toHaveBeenCalled();
  });

  it("preserves first-template input when reference upload fails", async () => {
    const user = userEvent.setup();
    const uploadTemplateReference = vi
      .fn<Loop7AppServices["uploadTemplateReference"]>()
      .mockRejectedValue(new Error("upload failed"));
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedEmptyIndex),
          uploadTemplateReference,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      screen.getByRole("button", { name: "添加第一个模板" }),
    );
    await user.type(screen.getByLabelText("模板名称"), "二号矿卸货磅单");
    await user.selectOptions(screen.getByLabelText("票据类型"), "unloading");
    const file = new File(["reference"], "二号矿参考图.png", {
      type: "image/png",
    });
    const input = screen.getByLabelText("参考图片") as HTMLInputElement;
    await user.upload(input, file);

    await user.click(
      screen.getByRole("button", { name: "上传参考图片" }),
    );

    expect(
      await screen.findByText(
        "参考图片上传失败，已填写内容会保留，请重试。",
      ),
    ).toBeVisible();
    expect(screen.getByLabelText("模板名称")).toHaveValue("二号矿卸货磅单");
    expect(screen.getByLabelText("票据类型")).toHaveValue("unloading");
    expect(input.files?.[0]).toBe(file);
  });

  it("restores an unsubmitted first-template draft after refresh and revalidation", async () => {
    const user = userEvent.setup();
    const firstRender = render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedEmptyIndex),
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      screen.getByRole("button", { name: "添加第一个模板" }),
    );
    await user.type(screen.getByLabelText("模板名称"), "待恢复卸货模板");
    await user.selectOptions(screen.getByLabelText("票据类型"), "unloading");
    await user.upload(
      screen.getByLabelText("参考图片"),
      new File(["reference"], "待恢复.png", { type: "image/png" }),
    );
    await user.click(
      screen.getByRole("button", { name: "上传参考图片" }),
    );
    await user.click(
      await screen.findByRole("button", { name: "添加固定内容" }),
    );
    const fixedText = screen.getByLabelText("票面固定文字");
    await user.clear(fixedText);
    await user.type(fixedText, "卸货磅单");
    firstRender.unmount();

    const lockedEmptyIndex: TemplateFamilyIndex = {
      ...lockedIndex,
      families: [],
    };
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(lockedEmptyIndex),
          unlockTemplateMaintenance: vi
            .fn()
            .mockResolvedValue(unlockedEmptyIndex),
        })}
      />,
    );
    const refreshedUser = userEvent.setup();
    expect(
      await screen.findByText("模板只能由已授权的维护人员修改。"),
    ).toBeVisible();
    await refreshedUser.type(
      screen.getByRole("textbox", { name: "维护验证码" }),
      "loop7-access",
    );
    await refreshedUser.click(
      screen.getByRole("button", { name: "进入维护模式" }),
    );

    expect(await screen.findByLabelText("模板名称")).toHaveValue(
      "待恢复卸货模板",
    );
    expect(screen.getByLabelText("票据类型")).toHaveValue("unloading");
    expect(screen.getByLabelText("票面固定文字")).toHaveValue("卸货磅单");
    expect(
      screen.getByRole("img", { name: "新模板参考图" }),
    ).toBeVisible();
  });

  it("abandons the staged reference and clears local draft recovery", async () => {
    const user = userEvent.setup();
    const abandonTemplateReference = vi
      .fn<Loop7AppServices["abandonTemplateReference"]>()
      .mockResolvedValue(undefined);
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedEmptyIndex),
          abandonTemplateReference,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      screen.getByRole("button", { name: "添加第一个模板" }),
    );
    await user.type(screen.getByLabelText("模板名称"), "临时模板");
    await user.upload(
      screen.getByLabelText("参考图片"),
      new File(["reference"], "临时.png", { type: "image/png" }),
    );
    await user.click(
      screen.getByRole("button", { name: "上传参考图片" }),
    );
    await user.click(
      await screen.findByRole("button", { name: "放弃本次模板" }),
    );

    await waitFor(() =>
      expect(abandonTemplateReference).toHaveBeenCalledWith(
        "staged-reference-1",
        3,
      ),
    );
    expect(
      screen.getByRole("button", { name: "添加第一个模板" }),
    ).toBeVisible();
    expect(
      sessionStorage.getItem("dahe.template-studio.creation-draft.v1"),
    ).toBeNull();
  });

  it("does not create a draft before a real fixed-content anchor exists", async () => {
    const user = userEvent.setup();
    const createTemplateFromStagedReference = vi
      .fn<Loop7AppServices["createTemplateFromStagedReference"]>()
      .mockResolvedValue({ created: true, template: versionSnapshot() });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedEmptyIndex),
          createTemplateFromStagedReference,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      screen.getByRole("button", { name: "添加第一个模板" }),
    );
    await user.type(screen.getByLabelText("模板名称"), "空锚点测试模板");
    await user.selectOptions(screen.getByLabelText("票据类型"), "loading");
    const file = new File(["reference"], "reference.jpg", {
      type: "image/jpeg",
    });
    await user.upload(screen.getByLabelText("参考图片"), file);
    await user.click(
      screen.getByRole("button", { name: "上传参考图片" }),
    );

    expect(await screen.findByRole("img", { name: "新模板参考图" })).toBeVisible();
    expect(screen.getByRole("button", { name: "创建草稿" })).toBeDisabled();
    expect(screen.getByText("请先标出至少一处固定内容。")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "添加固定内容" }));
    expect(screen.getByRole("button", { name: "创建草稿" })).toBeDisabled();
    expect(createTemplateFromStagedReference).not.toHaveBeenCalled();
  });

  it("creates the first draft from the staged reference and opens the existing editor", async () => {
    const user = userEvent.setup();
    const uploadTemplateReference = vi
      .fn<Loop7AppServices["uploadTemplateReference"]>()
      .mockResolvedValue(stagedReference);
    const createdTemplate = versionSnapshot({
      familyId: "family-unloading-b",
      familyName: "二号矿卸货磅单",
      purpose: "unloading",
      purposeLabel: "卸货磅单",
      referenceImage: {
        imageId: stagedReference.imageId,
        contentUrl: stagedReference.contentUrl,
        alt: "二号矿卸货磅单参考图",
        width: stagedReference.width,
        height: stagedReference.height,
        rotation: 0,
      },
      draft: {
        anchors: [
          {
            ...anchor,
            anchorId: "anchor-1",
            expectedText: "卸货磅单",
          },
        ],
        regions: [],
      },
    });
    const createTemplateFromStagedReference = vi
      .fn<Loop7AppServices["createTemplateFromStagedReference"]>()
      .mockResolvedValue({ created: true, template: createdTemplate });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedEmptyIndex),
          uploadTemplateReference,
          createTemplateFromStagedReference,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      screen.getByRole("button", { name: "添加第一个模板" }),
    );
    await user.type(screen.getByLabelText("模板名称"), "二号矿卸货磅单");
    await user.selectOptions(screen.getByLabelText("票据类型"), "unloading");
    const file = new File(["reference"], "二号矿参考图.jpg", {
      type: "image/jpeg",
    });
    await user.upload(screen.getByLabelText("参考图片"), file);
    await user.click(
      screen.getByRole("button", { name: "上传参考图片" }),
    );
    await user.click(
      await screen.findByRole("button", { name: "添加固定内容" }),
    );
    const completedUploadButton = screen.getByRole("button", {
      name: "上传参考图片",
    });
    expect(completedUploadButton).toBeDisabled();
    fireEvent.click(completedUploadButton);
    expect(uploadTemplateReference).toHaveBeenCalledTimes(1);
    const expectedText = screen.getByLabelText("票面固定文字");
    await user.clear(expectedText);
    await user.type(expectedText, "卸货磅单");

    const createButton = screen.getByRole("button", { name: "创建草稿" });
    expect(createButton).toBeEnabled();
    fireEvent.click(createButton);
    fireEvent.click(createButton);

    await waitFor(() =>
      expect(createTemplateFromStagedReference).toHaveBeenCalledTimes(1),
    );
    expect(uploadTemplateReference).toHaveBeenCalledWith(file);
    expect(createTemplateFromStagedReference).toHaveBeenCalledWith(
      "staged-reference-1",
      3,
      "二号矿卸货磅单",
      "unloading",
      expect.objectContaining({
        anchors: [
          expect.objectContaining({
            expectedText: "卸货磅单",
          }),
        ],
      }),
    );
    expect(
      await screen.findByRole("heading", { name: "二号矿卸货磅单" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "保存草稿" }),
    ).toBeEnabled();
    expect(
      sessionStorage.getItem("dahe.template-studio.creation-draft.v1"),
    ).toBeNull();
  });

  it("prevents duplicate reference uploads while the first request is pending", async () => {
    const user = userEvent.setup();
    const uploadTemplateReference = vi
      .fn<Loop7AppServices["uploadTemplateReference"]>()
      .mockReturnValue(new Promise<StagedTemplateReference>(() => undefined));
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedEmptyIndex),
          uploadTemplateReference,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      screen.getByRole("button", { name: "添加第一个模板" }),
    );
    await user.upload(
      screen.getByLabelText("参考图片"),
      new File(["reference"], "reference.png", { type: "image/png" }),
    );
    const uploadButton = screen.getByRole("button", {
      name: "上传参考图片",
    });

    fireEvent.click(uploadButton);
    fireEvent.click(uploadButton);

    expect(uploadTemplateReference).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("button", { name: "正在上传…" }),
    ).toBeDisabled();
  });

  it("reloads the empty-state service contract after a page remount", async () => {
    const user = userEvent.setup();
    const loadTemplateFamilies = vi
      .fn<Loop7AppServices["loadTemplateFamilies"]>()
      .mockResolvedValue(unlockedEmptyIndex);
    const appServices = services({ loadTemplateFamilies });
    const first = render(<App services={appServices} />);
    await openTemplateWorkbench(user);
    expect(
      await screen.findByRole("heading", { name: "还没有票据模板" }),
    ).toBeVisible();
    first.unmount();

    render(<App services={appServices} />);
    await openTemplateWorkbench(user);

    expect(
      await screen.findByRole("heading", { name: "还没有票据模板" }),
    ).toBeVisible();
    expect(loadTemplateFamilies).toHaveBeenCalledTimes(2);
  });

  it("supports the two business-language marking steps and keyboard box adjustment", async () => {
    const user = userEvent.setup();
    const saveTemplateDraft = vi
      .fn<Loop7AppServices["saveTemplateDraft"]>()
      .mockImplementation(
        (
          _versionId: string,
          expectedRecordVersion: number,
          draft: TemplateDraft,
        ) =>
          Promise.resolve(
            versionSnapshot({
              recordVersion: expectedRecordVersion + 1,
              draft,
            }),
          ),
      );
    const appServices = services({
      loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
      saveTemplateDraft,
    });
    render(<App services={appServices} />);
    await openTemplateWorkbench(user);

    const steps = screen.getByRole("navigation", {
      name: "模板制作步骤",
    });
    expect(
      within(steps).getByRole("button", { name: "1 标出固定内容" }),
    ).toHaveAttribute("aria-current", "step");
    expect(
      screen.getByText(
        "框选长期不变的文字或标记，例如厂名、“净重”和“打印时间”。",
      ),
    ).toBeVisible();

    const anchorBox = screen.getByRole("button", {
      name: "固定内容：净重标签",
    });
    anchorBox.focus();
    await user.keyboard("{ArrowRight}{ArrowDown}{Shift>}{ArrowRight}{ArrowDown}{/Shift}");
    await user.click(screen.getByRole("button", { name: "保存草稿" }));

    await waitFor(() => expect(saveTemplateDraft).toHaveBeenCalledTimes(1));
    const firstSave = saveTemplateDraft.mock.calls[0];
    expect(firstSave?.[0]).toBe("template-version-1");
    expect(firstSave?.[1]).toBe(7);
    expect(firstSave?.[2].anchors[0]?.bounds.x).toBeGreaterThan(
      anchor.bounds.x,
    );
    expect(firstSave?.[2].anchors[0]?.bounds.y).toBeGreaterThan(
      anchor.bounds.y,
    );
    expect(firstSave?.[2].anchors[0]?.bounds.width).toBeGreaterThan(
      anchor.bounds.width,
    );
    expect(firstSave?.[2].anchors[0]?.bounds.height).toBeGreaterThan(
      anchor.bounds.height,
    );

    await user.click(
      within(steps).getByRole("button", {
        name: "2 标出要读取的内容",
      }),
    );
    expect(
      screen.getByText(
        "普通净重、工厂净重、毛重、皮重和时间需要分别框选。",
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "读取区域：普通净重" }),
    ).toBeVisible();
    expect(
      within(steps).getByRole("button", {
        name: "2 标出要读取的内容",
      }),
    ).toHaveAttribute("aria-current", "step");
  });

  it("draws new fixed and reading boxes with normalized safe defaults", async () => {
    const user = userEvent.setup();
    const saveTemplateDraft = vi
      .fn<Loop7AppServices["saveTemplateDraft"]>()
      .mockImplementation(
        (
          _versionId: string,
          expectedRecordVersion: number,
          draft: TemplateDraft,
        ) =>
          Promise.resolve(
            versionSnapshot({
              recordVersion: expectedRecordVersion + 1,
              draft,
            }),
          ),
      );
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          saveTemplateDraft,
        })}
      />,
    );
    await openTemplateWorkbench(user);

    const anchorLayer = screen.getByRole("group", {
      name: "固定内容框选区域",
    });
    vi.spyOn(anchorLayer, "getBoundingClientRect").mockReturnValue(
      new DOMRect(0, 0, 800, 500),
    );

    fireEvent.pointerDown(anchorLayer, {
      button: 0,
      clientX: 100,
      clientY: 100,
      pointerId: 7,
    });
    fireEvent.pointerMove(anchorLayer, {
      clientX: 102,
      clientY: 102,
      pointerId: 7,
    });
    fireEvent.pointerUp(anchorLayer, {
      clientX: 102,
      clientY: 102,
      pointerId: 7,
    });
    expect(screen.getByText("框选范围太小，请拖出更大的范围。")).toBeVisible();

    fireEvent.pointerDown(anchorLayer, {
      button: 0,
      clientX: 80,
      clientY: 50,
      pointerId: 8,
    });
    fireEvent.pointerMove(anchorLayer, {
      clientX: 240,
      clientY: 150,
      pointerId: 8,
    });
    fireEvent.pointerUp(anchorLayer, {
      clientX: 240,
      clientY: 150,
      pointerId: 8,
    });

    expect(
      screen.getByText("这是临时文字，保存前请替换为票面上的实际固定内容。"),
    ).toBeVisible();

    await user.click(
      screen.getByRole("button", { name: "2 标出要读取的内容" }),
    );
    expect(
      screen.getByRole("button", { name: "添加读取内容" }),
    ).toBeEnabled();
    const regionLayer = screen.getByRole("group", {
      name: "读取内容框选区域",
    });
    vi.spyOn(regionLayer, "getBoundingClientRect").mockReturnValue(
      new DOMRect(0, 0, 800, 500),
    );
    fireEvent.pointerDown(regionLayer, {
      button: 0,
      clientX: 320,
      clientY: 200,
      pointerId: 9,
    });
    fireEvent.pointerMove(regionLayer, {
      clientX: 560,
      clientY: 300,
      pointerId: 9,
    });
    fireEvent.pointerUp(regionLayer, {
      clientX: 560,
      clientY: 300,
      pointerId: 9,
    });

    await user.click(screen.getByRole("button", { name: "保存草稿" }));
    await waitFor(() => expect(saveTemplateDraft).toHaveBeenCalledTimes(1));
    const savedDraft = saveTemplateDraft.mock.calls[0]?.[2];
    expect(savedDraft?.anchors).toHaveLength(2);
    expect(savedDraft?.anchors[1]).toMatchObject({
      expectedText: "请替换为票面固定文字",
      bounds: { x: 0.1, y: 0.1, width: 0.2, height: 0.2 },
    });
    expect(savedDraft?.regions).toHaveLength(2);
    expect(savedDraft?.regions[1]).toMatchObject({
      field: "ordinary_net_weight",
      valueType: "weight",
      unit: "ton",
      anchorId: savedDraft?.anchors[1]?.anchorId,
      bounds: { x: 0.4, y: 0.4, width: 0.3, height: 0.2 },
    });
  });

  it("keeps a dragged box inside the image when the pointer leaves its edge", async () => {
    const user = userEvent.setup();
    const saveTemplateDraft = vi
      .fn<Loop7AppServices["saveTemplateDraft"]>()
      .mockImplementation(
        (
          _versionId: string,
          expectedRecordVersion: number,
          draft: TemplateDraft,
        ) =>
          Promise.resolve(
            versionSnapshot({
              recordVersion: expectedRecordVersion + 1,
              draft,
            }),
          ),
      );
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          saveTemplateDraft,
        })}
      />,
    );
    await openTemplateWorkbench(user);

    const anchorLayer = screen.getByRole("group", {
      name: "固定内容框选区域",
    });
    vi.spyOn(anchorLayer, "getBoundingClientRect").mockReturnValue(
      new DOMRect(0, 0, 800, 500),
    );
    fireEvent.pointerDown(anchorLayer, {
      button: 0,
      clientX: 760,
      clientY: 450,
      pointerId: 12,
    });
    fireEvent.pointerMove(anchorLayer, {
      clientX: 920,
      clientY: 620,
      pointerId: 12,
    });
    fireEvent.pointerUp(anchorLayer, {
      clientX: 920,
      clientY: 620,
      pointerId: 12,
    });

    const newAnchor = screen.getByRole("button", {
      name: "固定内容：新的固定内容",
    });
    newAnchor.focus();
    await user.keyboard(
      "{ArrowRight}{ArrowDown}{Shift>}{ArrowRight}{ArrowDown}{/Shift}",
    );
    await user.click(screen.getByRole("button", { name: "保存草稿" }));
    await waitFor(() => expect(saveTemplateDraft).toHaveBeenCalledTimes(1));
    const savedBounds = saveTemplateDraft.mock.calls[0]?.[2].anchors[1]?.bounds;
    expect(savedBounds).toBeDefined();
    expect((savedBounds?.x ?? 0) + (savedBounds?.width ?? 0)).toBeLessThanOrEqual(
      1,
    );
    expect(
      (savedBounds?.y ?? 0) + (savedBounds?.height ?? 0),
    ).toBeLessThanOrEqual(1);
    expect(savedBounds?.width).toBeGreaterThanOrEqual(0.04);
    expect(savedBounds?.height).toBeGreaterThanOrEqual(0.04);
  });

  it("blocks deleting a fixed-content box while reading regions depend on it", async () => {
    const user = userEvent.setup();
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
        })}
      />,
    );
    await openTemplateWorkbench(user);

    const anchorBox = screen.getByRole("button", {
      name: "固定内容：净重标签",
    });
    anchorBox.focus();
    await user.keyboard("{Delete}");

    expect(
      screen.getByRole("button", { name: "固定内容：净重标签" }),
    ).toBeVisible();
    expect(
      screen.getByRole("alert"),
    ).toHaveTextContent(
      "不能删除这处固定内容，还有 1 个读取区域以它为参照。",
    );
    await user.click(
      screen.getByRole("button", { name: "2 标出要读取的内容" }),
    );
    expect(
      screen.getByRole("button", { name: "读取区域：普通净重" }),
    ).toBeVisible();
  });

  it("moves, resizes and deletes a selected reading box from the keyboard", async () => {
    const user = userEvent.setup();
    const saveTemplateDraft = vi
      .fn<Loop7AppServices["saveTemplateDraft"]>()
      .mockImplementation(
        (
          _versionId: string,
          expectedRecordVersion: number,
          draft: TemplateDraft,
        ) =>
          Promise.resolve(
            versionSnapshot({
              recordVersion: expectedRecordVersion + 1,
              draft,
            }),
          ),
      );
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          saveTemplateDraft,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      screen.getByRole("button", { name: "2 标出要读取的内容" }),
    );

    const regionBox = screen.getByRole("button", {
      name: "读取区域：普通净重",
    });
    regionBox.focus();
    await user.keyboard(
      "{ArrowLeft}{ArrowUp}{Shift>}{ArrowRight}{ArrowDown}{/Shift}",
    );
    await user.click(screen.getByRole("button", { name: "保存草稿" }));
    await waitFor(() => expect(saveTemplateDraft).toHaveBeenCalledTimes(1));
    const adjustedRegion = saveTemplateDraft.mock.calls[0]?.[2].regions[0];
    expect(adjustedRegion?.bounds.x).toBeLessThan(region.bounds.x);
    expect(adjustedRegion?.bounds.y).toBeLessThan(region.bounds.y);
    expect(adjustedRegion?.bounds.width).toBeGreaterThan(region.bounds.width);
    expect(adjustedRegion?.bounds.height).toBeGreaterThan(region.bounds.height);

    const adjustedBox = screen.getByRole("button", {
      name: "读取区域：普通净重",
    });
    adjustedBox.focus();
    await user.keyboard("{Delete}");
    expect(
      screen.queryByRole("button", { name: "读取区域：普通净重" }),
    ).toBeNull();
    expect(screen.getByText("尚未标出读取内容")).toBeVisible();
  });

  it("keeps the three business time fields distinct when saving", async () => {
    const user = userEvent.setup();
    const loadingTimeRegion: TemplateRegion = {
      ...region,
      label: "装货过磅时间",
      field: "loading_weigh_time",
      valueType: "time",
      unit: "printed",
    };
    const detail = versionSnapshot({
      draft: {
        anchors: [anchor],
        regions: [loadingTimeRegion],
      },
    });
    const saveTemplateDraft = vi
      .fn<Loop7AppServices["saveTemplateDraft"]>()
      .mockImplementation((_versionId, expectedRecordVersion, nextDraft) =>
        Promise.resolve(
          versionSnapshot({
            recordVersion: expectedRecordVersion + 1,
            draft: nextDraft,
          }),
        ),
      );
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          loadTemplateFamily: vi.fn().mockResolvedValue(detail),
          saveTemplateDraft,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      screen.getByRole("button", { name: "2 标出要读取的内容" }),
    );

    const field = screen.getByLabelText("业务字段");
    expect(field).toHaveValue("loading_weigh_time");
    expect(
      within(field).getByRole("option", { name: "卸货皮重时间" }),
    ).toBeVisible();
    expect(
      within(field).getByRole("option", { name: "打印时间" }),
    ).toBeVisible();
    await user.selectOptions(field, "unloading_tare_time");
    await user.click(screen.getByRole("button", { name: "保存草稿" }));

    await waitFor(() => expect(saveTemplateDraft).toHaveBeenCalledTimes(1));
    expect(saveTemplateDraft.mock.calls[0]?.[2].regions[0]).toMatchObject({
      field: "unloading_tare_time",
      label: "卸货皮重时间",
      valueType: "time",
      unit: "printed",
    });
  });

  it("saves a versioned draft and restores the saved values after reopening", async () => {
    const user = userEvent.setup();
    const saved = versionSnapshot({
      recordVersion: 8,
      draft: {
        anchors: [
          {
            ...anchor,
            label: "净重固定文字",
            expectedText: "净重固定文字",
          },
        ],
        regions: [region],
      },
    });
    const loadTemplateFamily = vi
      .fn<Loop7AppServices["loadTemplateFamily"]>()
      .mockResolvedValueOnce(versionSnapshot())
      .mockResolvedValueOnce(saved);
    const saveTemplateDraft = vi
      .fn<Loop7AppServices["saveTemplateDraft"]>()
      .mockResolvedValue(saved);
    const appServices = services({
      loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
      loadTemplateFamily,
      saveTemplateDraft,
    });
    const firstRender = render(<App services={appServices} />);
    await openTemplateWorkbench(user);

    const label = screen.getByRole("textbox", {
      name: "票面固定文字",
    });
    await user.clear(label);
    await user.type(label, "净重固定文字");
    await user.click(screen.getByRole("button", { name: "保存草稿" }));

    await waitFor(() => expect(saveTemplateDraft).toHaveBeenCalledTimes(1));
    expect(saveTemplateDraft).toHaveBeenCalledWith(
      "template-version-1",
      7,
      expect.objectContaining({
        anchors: [
          expect.objectContaining({
            label: "净重固定文字",
            expectedText: "净重固定文字",
          }),
        ],
      }),
    );

    firstRender.unmount();
    render(<App services={appServices} />);
    await openTemplateWorkbench(userEvent.setup());

    expect(
      await screen.findByRole("textbox", { name: "票面固定文字" }),
    ).toHaveValue("净重固定文字");
    expect(loadTemplateFamily).toHaveBeenCalledTimes(2);
  });

  it("returns to the maintenance gate when authorization expires", async () => {
    const user = userEvent.setup();
    const loadTemplateFamilies = vi
      .fn<Loop7AppServices["loadTemplateFamilies"]>()
      .mockResolvedValueOnce(unlockedIndex)
      .mockResolvedValueOnce(lockedIndex);
    render(
      <App
        services={services({
          loadTemplateFamilies,
          saveTemplateDraft: vi
            .fn()
            .mockRejectedValue(new TemplateMaintenanceRequiredError()),
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(
      await screen.findByRole("button", { name: "保存草稿" }),
    );

    expect(
      await screen.findByText("模板只能由已授权的维护人员修改。"),
    ).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "维护模式已退出",
    );
    expect(
      screen.getByRole("button", { name: "进入维护模式" }),
    ).toBeEnabled();
  });

  it("passes the server-declared evaluation id when confirming development checks", async () => {
    const user = userEvent.setup();
    const runTemplateDevelopmentCheck = vi
      .fn<Loop7AppServices["runTemplateDevelopmentCheck"]>()
      .mockResolvedValue(
        versionSnapshot({
          lifecycle: "development_tested",
          lifecycleLabel: "开发样本已通过",
        }),
      );
    const detail = versionSnapshot({
      actions: {
        run_development_check: action("确认开发样本检查", 7, {
          evaluationId: "development-evaluation-001",
        }),
      },
    });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          loadTemplateFamily: vi.fn().mockResolvedValue(detail),
          runTemplateDevelopmentCheck,
        })}
      />,
    );
    await openTemplateWorkbench(user);

    await user.click(
      screen.getByRole("button", { name: "确认开发样本检查" }),
    );

    await waitFor(() =>
      expect(runTemplateDevelopmentCheck).toHaveBeenCalledWith(
        "template-version-1",
        7,
        "development-evaluation-001",
      ),
    );
  });

  it("does not confirm a development check when its evaluation id is missing", async () => {
    const user = userEvent.setup();
    const runTemplateDevelopmentCheck = vi
      .fn<Loop7AppServices["runTemplateDevelopmentCheck"]>()
      .mockResolvedValue(versionSnapshot());
    const detail = versionSnapshot({
      actions: {
        run_development_check: action("确认开发样本检查", 7, {
          evaluationId: null,
        }),
      },
    });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          loadTemplateFamily: vi.fn().mockResolvedValue(detail),
          runTemplateDevelopmentCheck,
        })}
      />,
    );
    await openTemplateWorkbench(user);

    await user.click(
      screen.getByRole("button", { name: "确认开发样本检查" }),
    );

    expect(runTemplateDevelopmentCheck).not.toHaveBeenCalled();
    expect(
      screen.getByRole("alert"),
    ).toHaveTextContent("开发样本检查记录缺失，请重新生成检查结果后再试。");
  });

  it("requires an inline second verification before publishing a shadow template", async () => {
    const user = userEvent.setup();
    const revalidateTemplateShadowAction = vi
      .fn<Loop7AppServices["revalidateTemplateShadowAction"]>()
      .mockResolvedValue("shadow-action-token");
    const published = versionSnapshot({
      lifecycle: "shadow",
      lifecycleLabel: "影子测试中",
      actions: {},
    });
    const runTemplateVersionAction = vi
      .fn<Loop7AppServices["runTemplateVersionAction"]>()
      .mockResolvedValue(published);
    const detail = versionSnapshot({
      lifecycle: "development_tested",
      lifecycleLabel: "开发样本已通过",
      recordVersion: 11,
      actions: {
        start_shadow: action("开始影子测试", 11, {
          evaluationId: "development-evaluation-001",
        }),
      },
    });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          loadTemplateFamily: vi.fn().mockResolvedValue(detail),
          revalidateTemplateShadowAction,
          runTemplateVersionAction,
        })}
      />,
    );
    await openTemplateWorkbench(user);

    await user.click(screen.getByRole("button", { name: "开始影子测试" }));

    expect(runTemplateVersionAction).not.toHaveBeenCalled();
    expect(
      screen.getByRole("region", { name: "确认开始影子测试" }),
    ).toHaveTextContent("只读影子，不影响成丰和真实结算");
    expect(
      screen.getByRole("heading", { name: "确认开始影子测试" }),
    ).toHaveFocus();
    const confirm = screen.getByRole("button", {
      name: "确认开始影子测试",
    });
    await user.click(confirm);
    expect(revalidateTemplateShadowAction).not.toHaveBeenCalled();
    expect(runTemplateVersionAction).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "请再次输入维护验证码。",
    );

    await user.type(
      screen.getByLabelText("再次输入维护验证码"),
      "loop7-access",
    );
    await user.click(confirm);

    await waitFor(() =>
      expect(revalidateTemplateShadowAction).toHaveBeenCalledWith(
        "loop7-access",
        "template-version-1",
      ),
    );
    expect(runTemplateVersionAction).toHaveBeenCalledWith(
      "template-version-1",
      "start_shadow",
      11,
      {
        evaluationId: "development-evaluation-001",
        developerAuthorization: "shadow-action-token",
      },
    );
    expect(await screen.findByText("影子测试中")).toBeVisible();
    expect(
      screen.queryByRole("region", { name: "确认开始影子测试" }),
    ).toBeNull();
  });

  it("does not request shadow authorization when evaluation evidence is missing", async () => {
    const user = userEvent.setup();
    const revalidateTemplateShadowAction = vi
      .fn<Loop7AppServices["revalidateTemplateShadowAction"]>()
      .mockResolvedValue("shadow-action-token");
    const runTemplateVersionAction = vi
      .fn<Loop7AppServices["runTemplateVersionAction"]>()
      .mockResolvedValue(versionSnapshot());
    const detail = versionSnapshot({
      lifecycle: "development_tested",
      lifecycleLabel: "开发样本已通过",
      actions: {
        start_shadow: action("开始影子测试", 11, {
          evaluationId: null,
        }),
      },
      recordVersion: 11,
    });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          loadTemplateFamily: vi.fn().mockResolvedValue(detail),
          revalidateTemplateShadowAction,
          runTemplateVersionAction,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(screen.getByRole("button", { name: "开始影子测试" }));
    await user.type(
      screen.getByLabelText("再次输入维护验证码"),
      "loop7-access",
    );
    await user.click(
      screen.getByRole("button", { name: "确认开始影子测试" }),
    );

    expect(revalidateTemplateShadowAction).not.toHaveBeenCalled();
    expect(runTemplateVersionAction).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "影子测试缺少已通过的开发样本检查记录。",
    );
    expect(screen.getByText("开发样本已通过")).toBeVisible();
  });

  it("restores a reviewed earlier shadow version through a second verification", async () => {
    const user = userEvent.setup();
    const detail = versionSnapshot({
      lifecycle: "shadow",
      lifecycleLabel: "影子测试中",
      actions: {
        restore_shadow: action("恢复上一影子版本", 4),
      },
    });
    const loadTemplateFamilyVersions = vi
      .fn<Loop7AppServices["loadTemplateFamilyVersions"]>()
      .mockResolvedValue({
        familyId: "family-loading-a",
        currentShadowVersionId: "template-version-2",
        currentShadowRecordVersion: 4,
        versions: [
          {
            versionId: "template-version-2",
            versionNumber: 2,
            lifecycleLabel: "影子测试中",
            isCurrentShadow: true,
            canRollback: false,
            label: "影子版本 2 (当前)",
          },
          {
            versionId: "template-version-1",
            versionNumber: 1,
            lifecycleLabel: "影子测试中",
            isCurrentShadow: false,
            canRollback: true,
            label: "影子版本 1",
          },
        ],
      });
    const revalidateTemplateRollbackAction = vi
      .fn<Loop7AppServices["revalidateTemplateRollbackAction"]>()
      .mockResolvedValue("rollback-action-token");
    const rollbackTemplateShadow = vi
      .fn<Loop7AppServices["rollbackTemplateShadow"]>()
      .mockResolvedValue({
        applied: true,
        familyId: "family-loading-a",
        versionId: "template-version-1",
        recordVersion: 5,
      });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          loadTemplateFamily: vi.fn().mockResolvedValue(detail),
          loadTemplateFamilyVersions,
          revalidateTemplateRollbackAction,
          rollbackTemplateShadow,
        })}
      />,
    );
    await openTemplateWorkbench(user);

    await user.click(
      screen.getByRole("button", { name: "恢复上一影子版本" }),
    );
    expect(
      await screen.findByRole("heading", { name: "确认恢复影子版本" }),
    ).toHaveFocus();
    expect(screen.getByLabelText("恢复到")).toHaveValue(
      "template-version-1",
    );
    await user.type(screen.getByLabelText("恢复原因"), "新版式读取异常");
    await user.type(
      screen.getByLabelText("再次输入维护验证码"),
      "loop7-access",
    );
    await user.click(
      screen.getByRole("button", { name: "确认恢复影子版本" }),
    );

    await waitFor(() =>
      expect(rollbackTemplateShadow).toHaveBeenCalledWith(
        "family-loading-a",
        "template-version-1",
        4,
        "新版式读取异常",
        "rollback-action-token",
      ),
    );
    expect(revalidateTemplateRollbackAction).toHaveBeenCalledWith(
      "loop7-access",
      "family-loading-a",
    );
    expect(
      await screen.findByText("影子模板已恢复到影子版本 1。"),
    ).toBeVisible();
  });

  it("keeps the current template when shadow revalidation fails", async () => {
    const user = userEvent.setup();
    const revalidateTemplateShadowAction = vi
      .fn<Loop7AppServices["revalidateTemplateShadowAction"]>()
      .mockRejectedValue(new Error("Rejected"));
    const runTemplateVersionAction = vi
      .fn<Loop7AppServices["runTemplateVersionAction"]>()
      .mockResolvedValue(versionSnapshot());
    const detail = versionSnapshot({
      lifecycle: "development_tested",
      lifecycleLabel: "开发样本已通过",
      actions: {
        start_shadow: action("开始影子测试", 11, {
          evaluationId: "development-evaluation-001",
        }),
      },
      recordVersion: 11,
    });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          loadTemplateFamily: vi.fn().mockResolvedValue(detail),
          revalidateTemplateShadowAction,
          runTemplateVersionAction,
        })}
      />,
    );
    await openTemplateWorkbench(user);
    await user.click(screen.getByRole("button", { name: "开始影子测试" }));
    await user.type(
      screen.getByLabelText("再次输入维护验证码"),
      "wrong-code",
    );
    await user.click(
      screen.getByRole("button", { name: "确认开始影子测试" }),
    );

    await waitFor(() =>
      expect(revalidateTemplateShadowAction).toHaveBeenCalledTimes(1),
    );
    expect(runTemplateVersionAction).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "维护验证没有通过，当前模板没有改变。",
    );
    expect(screen.getByText("开发样本已通过")).toBeVisible();
    expect(
      screen.getByRole("region", { name: "确认开始影子测试" }),
    ).toBeVisible();
  });

  it("renders only server-declared lifecycle actions and never offers active publication", async () => {
    const user = userEvent.setup();
    const detail = versionSnapshot({
      lifecycle: "development_tested",
      lifecycleLabel: "开发样本已通过",
      actions: {
        save_draft: action("保存草稿", 11, {
          visible: false,
        }),
        run_development_check: action("用开发样本检查", 11, {
          visible: false,
        }),
        start_shadow: action("开始影子测试", 11, {
          enabled: false,
          reason: "影子检查资料尚未准备完成",
        }),
      },
      recordVersion: 11,
    });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          loadTemplateFamily: vi.fn().mockResolvedValue(detail),
        })}
      />,
    );
    await openTemplateWorkbench(user);

    expect(screen.getByText("开发样本已通过")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "开始影子测试" }),
    ).toBeDisabled();
    expect(screen.getByText("影子检查资料尚未准备完成")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "恢复上一影子版本" }),
    ).toBeNull();
    expect(screen.queryByText(/active/i)).toBeNull();
    expect(screen.queryByText("正式发布")).toBeNull();
    expect(screen.queryByText("启用正式模板")).toBeNull();
  });

  it("shows each template quality measure separately instead of a combined hit rate", async () => {
    const user = userEvent.setup();
    const metricLabels = [
      "版式对齐",
      "固定内容找到",
      "字段读取可靠",
      "模板直接完成",
      "需要整张识别",
      "选错模板",
      "角色冲突",
      "未知版式",
      "一般耗时",
      "较慢耗时",
    ];
    const detail = versionSnapshot({
      lifecycle: "development_tested",
      lifecycleLabel: "开发样本已通过",
      checkReport: {
        summaryLabel: "合成开发检查通过",
        scopeLabel: "8 个合成案例，15 次旋转运行",
        warning: "仅用于开发调试，不代表 50 条独立锁定集通过。",
        metrics: metricLabels.map((label, index) => ({
          metricId: `metric-${index}`,
          label,
          valueLabel: index < 8 ? `${48 - index}/50` : `${12 + index} 毫秒`,
        })),
      },
    });
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
          loadTemplateFamily: vi.fn().mockResolvedValue(detail),
        })}
      />,
    );
    await openTemplateWorkbench(user);

    expect(screen.getByText("合成开发检查通过")).toBeVisible();
    expect(
      screen.getByText("8 个合成案例，15 次旋转运行"),
    ).toBeVisible();
    expect(
      screen.getByText("仅用于开发调试，不代表 50 条独立锁定集通过。"),
    ).toBeVisible();
    metricLabels.forEach((label) => {
      expect(screen.getByText(label)).toBeVisible();
    });
    expect(screen.queryByText("模板命中率")).toBeNull();
  });

  it("keeps the editor landmarks and controls in a meaningful narrow-screen order", async () => {
    Object.defineProperty(window, "innerWidth", {
      configurable: true,
      value: 540,
    });
    window.dispatchEvent(new Event("resize"));
    const user = userEvent.setup();
    render(
      <App
        services={services({
          loadTemplateFamilies: vi.fn().mockResolvedValue(unlockedIndex),
        })}
      />,
    );
    await openTemplateWorkbench(user);

    const steps = screen.getByRole("navigation", {
      name: "模板制作步骤",
    });
    const imageRegion = screen.getByRole("region", {
      name: "参考图片",
    });
    const propertiesRegion = screen.getByRole("region", {
      name: "固定内容设置",
    });
    expect(steps).toBeVisible();
    expect(imageRegion).toBeVisible();
    expect(propertiesRegion).toBeVisible();
    expect(
      imageRegion.compareDocumentPosition(propertiesRegion) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "固定内容：净重标签" }),
    ).toHaveAttribute("tabindex", "0");
    const referenceImage = screen.getByRole("img", {
      name: "一号矿装货磅单参考图",
    });
    expect(referenceImage).not.toHaveAttribute("width");
    expect(referenceImage).not.toHaveAttribute("height");
    expect(
      screen.getByRole("button", { name: "保存草稿" }),
    ).toBeVisible();
  });
});
