import { afterEach, describe, expect, it, vi } from "vitest";

import {
  TemplateMaintenanceRequiredError,
  type ServerAction,
} from "../app/contracts";
import { BrowserAppServices } from "./client";

interface TemplateFamilyIndex {
  maintenance: {
    authorized: boolean;
    statusLabel: string;
    expiresAtLabel: string | null;
  };
  families: Array<{
    familyId: string;
    name: string;
    purposeLabel: string;
    currentVersionLabel: string;
    lifecycleLabel: string;
  }>;
  actions: Record<
    string,
    ServerAction & {
      evaluationId: string | null;
    }
  >;
  acceptanceSet: {
    waybillCount: number;
    targetWaybillCount: number;
    statusLabel: string;
  };
}

interface TemplateVersionSnapshot {
  versionId: string;
  recordVersion: number;
  familyId: string;
  familyName: string;
  purpose: "loading" | "unloading";
  purposeLabel: string;
  lifecycle: "draft" | "development_tested" | "shadow";
  lifecycleLabel: string;
  referenceImage: {
    imageId: string;
    contentUrl: string;
    alt: string;
    width: number;
    height: number;
    rotation: 0 | 90 | 180 | 270;
  };
  draft: {
    anchors: Array<{
      anchorId: string;
      label: string;
      expectedText: string;
      matchMode: "exact" | "contains" | "pattern";
      required: boolean;
      roleEvidence: "loading" | "unloading" | "position_only";
      importance: "primary" | "supporting";
      bounds: {
        x: number;
        y: number;
        width: number;
        height: number;
      };
    }>;
    regions: Array<{
      regionId: string;
      label: string;
      field: "ordinary_net_weight" | "factory_net_weight";
      valueType: "weight";
      unit: "ton" | "kilogram" | "printed";
      required: boolean;
      anchorId: string;
      bounds: {
        x: number;
        y: number;
        width: number;
        height: number;
      };
    }>;
  };
  actions: Record<string, ServerAction>;
  checkReport: {
    summaryLabel: string;
    scopeLabel: string;
    warning: string;
    metrics: Array<{
      metricId: string;
      label: string;
      valueLabel: string;
    }>;
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

interface TemplateBrowserServices {
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
    role: "loading" | "unloading",
    draft: TemplateVersionSnapshot["draft"],
  ): Promise<{ created: boolean; template: TemplateVersionSnapshot }>;
  saveTemplateDraft(
    versionId: string,
    expectedRecordVersion: number,
    draft: TemplateVersionSnapshot["draft"],
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
  loadTemplateFamilyVersions(familyId: string): Promise<{
    familyId: string;
    currentShadowVersionId: string | null;
    currentShadowRecordVersion: number | null;
    versions: Array<{
      versionId: string;
      canRollback: boolean;
      label: string;
    }>;
  }>;
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
    evidence?: {
      evaluationId: string;
      developerAuthorization: string;
    },
  ): Promise<TemplateVersionSnapshot>;
}

function templateServices(): BrowserAppServices & TemplateBrowserServices {
  return new BrowserAppServices() as BrowserAppServices & TemplateBrowserServices;
}

function jsonResponse(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function sessionResponse(): Response {
  return jsonResponse({
    application_version: "1.0.0",
    api_version: "v1",
    csrf_token: "csrf-loop7",
  });
}

const familyIndexWire = {
  maintenance: {
    authorized: false,
    status_label: "未进入维护模式",
    expires_at_label: null,
  },
  families: [
    {
      family_id: "family loading/一",
      name: "一号矿装货磅单",
      purpose_label: "装货磅单",
      current_version_label: "草稿 1",
      lifecycle_label: "草稿",
    },
  ],
  actions: {
    create_template: {
      visible: true,
      enabled: false,
      reason: "请先进入维护模式",
      label: "添加第一个模板",
      expected_record_version: null,
      evaluation_id: null,
    },
  },
  acceptance_set: {
    waybill_count: 0,
    target_waybill_count: 50,
    status_label: "独立验收样本尚未建立",
  },
};

const detailWire = {
  version_id: "version 一/1",
  record_version: 7,
  family_id: "family loading/一",
  family_name: "一号矿装货磅单",
  purpose: "loading",
  purpose_label: "装货磅单",
  lifecycle: "draft",
  lifecycle_label: "草稿",
  reference_image: {
    image_id: "image 一/1",
    content_url:
      "/api/v1/template-studio/reference-images/image%20%E4%B8%80%2F1/content",
    alt: "一号矿装货磅单参考图",
    width: 800,
    height: 500,
    rotation: 0,
  },
  draft: {
    anchors: [
      {
        anchor_id: "anchor-net",
        label: "净重标签",
        expected_text: "净重",
        match_mode: "exact",
        required: true,
        role_evidence: "loading",
        importance: "primary",
        bounds: {
          x: 0.1,
          y: 0.18,
          width: 0.16,
          height: 0.08,
        },
      },
    ],
    regions: [
      {
        region_id: "region-net",
        label: "普通净重",
        field: "ordinary_net_weight",
        value_type: "weight",
        unit: "ton",
        required: true,
        anchor_id: "anchor-net",
        bounds: {
          x: 0.31,
          y: 0.18,
          width: 0.22,
          height: 0.08,
        },
      },
    ],
  },
  actions: {
    save_draft: {
      visible: true,
      enabled: true,
      reason: null,
      label: "保存草稿",
      expected_record_version: 7,
      evaluation_id: null,
    },
    run_development_check: {
      visible: true,
      enabled: true,
      reason: null,
      label: "确认开发样本检查",
      expected_record_version: 7,
      evaluation_id: "development-evaluation-001",
    },
    start_shadow: {
      visible: false,
      enabled: false,
      reason: "需要先通过开发样本检查",
      label: "开始影子测试",
      expected_record_version: 7,
      evaluation_id: null,
    },
  },
  check_report: null,
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Loop 7 template client contract", () => {
  it("maps the maintenance summary and template family business labels", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(familyIndexWire));
    vi.stubGlobal("fetch", fetchMock);

    const result = await templateServices().loadTemplateFamilies();

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/template-studio/families",
      expect.objectContaining({
        cache: "no-store",
        credentials: "same-origin",
      }),
    );
    expect(result).toEqual({
      maintenance: {
        authorized: false,
        statusLabel: "未进入维护模式",
        expiresAtLabel: null,
      },
      families: [
        {
          familyId: "family loading/一",
          name: "一号矿装货磅单",
          purposeLabel: "装货磅单",
          currentVersionLabel: "草稿 1",
          lifecycleLabel: "草稿",
        },
      ],
      actions: {
        create_template: {
          visible: true,
          enabled: false,
          reason: "请先进入维护模式",
          label: "添加第一个模板",
          expectedRecordVersion: null,
          evaluationId: null,
        },
      },
      acceptanceSet: {
        waybillCount: 0,
        targetWaybillCount: 50,
        statusLabel: "独立验收样本尚未建立",
      },
    });
  });

  it("maps normalized boxes and preserves the backend lifecycle action matrix", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(detailWire));
    vi.stubGlobal("fetch", fetchMock);

    const result = await templateServices().loadTemplateFamily(
      "family loading/一",
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/template-studio/families/family%20loading%2F%E4%B8%80",
      expect.objectContaining({ cache: "no-store" }),
    );
    expect(result).toMatchObject({
      versionId: "version 一/1",
      recordVersion: 7,
      lifecycle: "draft",
      lifecycleLabel: "草稿",
      draft: {
        anchors: [
          {
            anchorId: "anchor-net",
            expectedText: "净重",
            bounds: {
              x: 0.1,
              y: 0.18,
              width: 0.16,
              height: 0.08,
            },
          },
        ],
        regions: [
          {
            regionId: "region-net",
            field: "ordinary_net_weight",
            anchorId: "anchor-net",
          },
        ],
      },
      actions: {
        save_draft: {
          label: "保存草稿",
          enabled: true,
          expectedRecordVersion: 7,
          evaluationId: null,
        },
        run_development_check: {
          label: "确认开发样本检查",
          enabled: true,
          expectedRecordVersion: 7,
          evaluationId: "development-evaluation-001",
        },
        start_shadow: {
          visible: false,
          reason: "需要先通过开发样本检查",
          expectedRecordVersion: 7,
          evaluationId: null,
        },
      },
    });
  });

  it("uses the protected local write contract when entering maintenance mode", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(
        jsonResponse({
          ...familyIndexWire,
          maintenance: {
            authorized: true,
            status_label: "维护模式已开启",
            expires_at_label: "15 分钟后自动退出",
          },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "maintenance-unlock-key" });
    const service = templateServices();
    await service.bootstrap();

    const result = await service.unlockTemplateMaintenance("loop7-access");

    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/template-studio/developer/revalidate",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "X-CSRF-Token": "csrf-loop7",
          "X-Idempotency-Key": "maintenance-unlock-key",
        }),
        body: JSON.stringify({
          access_code: "loop7-access",
          action: "template.maintenance_session",
          resource_id: "template-studio",
        }),
      }),
    );
    expect(result.maintenance).toEqual({
      authorized: true,
      statusLabel: "维护模式已开启",
      expiresAtLabel: "15 分钟后自动退出",
    });
  });

  it("maps an expired maintenance session to the dedicated recovery error", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(
        jsonResponse(
          {
            error: {
              code: "developer_revalidation_required",
              message: "Maintenance session expired.",
            },
          },
          403,
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "expired-maintenance-key" });
    const service = templateServices();
    await service.bootstrap();

    await expect(
      service.saveTemplateDraft("version-1", 1, {
        anchors: [],
        regions: [],
      }),
    ).rejects.toBeInstanceOf(TemplateMaintenanceRequiredError);
  });

  it("uploads a raw reference image with protected file metadata", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(
        jsonResponse({
          upload: {
            staged_reference_id: "staged-reference-1",
            image_id: "reference-image-1",
            content_url:
              "/api/v1/template-studio/reference-images/reference-image-1/content",
            alt: "二号矿参考图",
            width: 1200,
            height: 1800,
            record_version: 3,
          },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "reference-upload-key" });
    const service = templateServices();
    await service.bootstrap();
    const file = new File(["reference"], "二号矿 参考图.jpg", {
      type: "image/jpeg",
    });

    const result = await service.uploadTemplateReference(file);

    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/template-studio/reference-images",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "image/jpeg",
          "X-DaHe-File-Name":
            "%E4%BA%8C%E5%8F%B7%E7%9F%BF%20%E5%8F%82%E8%80%83%E5%9B%BE.jpg",
          "X-CSRF-Token": "csrf-loop7",
          "X-Idempotency-Key": "reference-upload-key",
        }),
        body: file,
      }),
    );
    expect(result).toEqual({
      stagedReferenceId: "staged-reference-1",
      imageId: "reference-image-1",
      contentUrl:
        "/api/v1/template-studio/reference-images/reference-image-1/content",
      alt: "二号矿参考图",
      width: 1200,
      height: 1800,
      rotation: 0,
      recordVersion: 3,
    });
  });

  it("abandons a staged reference with its record version", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(
        jsonResponse({
          abandoned: true,
          record_version: 4,
          state: "abandoned",
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "reference-abandon-key" });
    const service = templateServices();
    await service.bootstrap();

    await service.abandonTemplateReference("staged reference/一", 3);

    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/template-studio/reference-images/staged%20reference%2F%E4%B8%80/abandon",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "X-Idempotency-Key": "reference-abandon-key",
        }),
        body: JSON.stringify({ expected_record_version: 3 }),
      }),
    );
  });

  it("creates a first draft from staged reference state without exposing hashes", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(
        jsonResponse({
          created: true,
          template: detailWire,
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "first-template-key" });
    const service = templateServices();
    await service.bootstrap();
    const draft: TemplateVersionSnapshot["draft"] = {
      anchors: [
        {
          anchorId: "anchor-net",
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
        },
      ],
      regions: [],
    };

    const result = await service.createTemplateFromStagedReference(
      "staged-reference-1",
      3,
      "一号矿装货磅单",
      "loading",
      draft,
    );

    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/template-studio/templates/from-staged-reference",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-CSRF-Token": "csrf-loop7",
          "X-Idempotency-Key": "first-template-key",
        }),
        body: JSON.stringify({
          staged_reference_id: "staged-reference-1",
          expected_record_version: 3,
          family_name: "一号矿装货磅单",
          role: "loading",
          draft: {
            anchors: [
              {
                anchor_id: "anchor-net",
                expected_text: "净重",
                match_mode: "exact",
                required: true,
                role_evidence: "loading",
                importance: "primary",
                bounds: {
                  x: 0.1,
                  y: 0.18,
                  width: 0.16,
                  height: 0.08,
                },
              },
            ],
            regions: [],
          },
        }),
      }),
    );
    expect(result.created).toBe(true);
    expect(result.template.versionId).toBe("version 一/1");
    expect(JSON.stringify(fetchMock.mock.calls.at(-1)?.[1])).not.toMatch(
      /reference_image_sha256|reference_mask_sha256|alignment_fingerprint|[A-Za-z]:\\/i,
    );
  });

  it("maps the durable development scope and warning without implying locked-set acceptance", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        ...detailWire,
        check_report: {
          summary_label: "合成开发检查通过",
          scope_label: "8 个合成案例，15 次旋转运行",
          warning: "仅用于开发调试，不代表 50 条独立锁定集通过。",
          metrics: [],
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await templateServices().loadTemplateFamily(
      "family loading/一",
    );

    expect(result.checkReport).toEqual({
      summaryLabel: "合成开发检查通过",
      scopeLabel: "8 个合成案例，15 次旋转运行",
      warning: "仅用于开发调试，不代表 50 条独立锁定集通过。",
      metrics: [],
    });
  });

  it("saves only normalized draft data with optimistic versioning and no local path", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(jsonResponse(detailWire));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "template-save-key" });
    const service = templateServices();
    await service.bootstrap();
    const draft: TemplateVersionSnapshot["draft"] = {
      anchors: [
        {
          anchorId: "anchor-net",
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
        },
      ],
      regions: [
        {
          regionId: "region-net",
          label: "普通净重",
          field: "ordinary_net_weight",
          valueType: "weight",
          unit: "ton",
          required: true,
          anchorId: "anchor-net",
          bounds: {
            x: 0.31,
            y: 0.18,
            width: 0.22,
            height: 0.08,
          },
        },
      ],
    };

    await service.saveTemplateDraft("version 一/1", 7, draft);

    const lastCall = fetchMock.mock.calls.at(-1);
    expect(lastCall?.[0]).toBe(
      "/api/v1/template-studio/templates/version%20%E4%B8%80%2F1/draft",
    );
    const init = lastCall?.[1] as RequestInit;
    expect(init.method).toBe("PUT");
    expect(init.headers).toEqual(
      expect.objectContaining({
        "X-CSRF-Token": "csrf-loop7",
        "X-Idempotency-Key": "template-save-key",
      }),
    );
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(body).toMatchObject({
      expected_record_version: 7,
      draft: {
        anchors: [
          {
            anchor_id: "anchor-net",
            bounds: {
              x: 0.1,
              y: 0.18,
              width: 0.16,
              height: 0.08,
            },
          },
        ],
        regions: [
          {
            region_id: "region-net",
            field: "ordinary_net_weight",
          },
        ],
      },
    });
    expect(JSON.stringify(body)).not.toMatch(
      /[A-Za-z]:\\|AppData|LOCALAPPDATA|gpu:0/i,
    );
  });

  it("marks a checked draft through the backend development-tested contract", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(jsonResponse(detailWire));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "development-tested-key" });
    const service = templateServices();
    await service.bootstrap();

    await service.runTemplateDevelopmentCheck(
      "version 一/1",
      7,
      "development-evaluation-001",
    );

    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/template-studio/templates/version%20%E4%B8%80%2F1/development-tested",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          expected_record_version: 7,
          evaluation_id: "development-evaluation-001",
        }),
      }),
    );
  });

  it("requests a version-bound developer token before shadow publication", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(
        jsonResponse({
          ...familyIndexWire,
          authorization_token: "shadow-action-token",
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "shadow-revalidate-key" });
    const service = templateServices();
    await service.bootstrap();

    const token = await service.revalidateTemplateShadowAction(
      "loop7-access",
      "version 一/1",
    );

    expect(token).toBe("shadow-action-token");
    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/template-studio/developer/revalidate",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "X-CSRF-Token": "csrf-loop7",
          "X-Idempotency-Key": "shadow-revalidate-key",
        }),
        body: JSON.stringify({
          access_code: "loop7-access",
          action: "template.publish_shadow",
          resource_id: "version 一/1",
        }),
      }),
    );
  });

  it("loads rollback targets and submits an authorized family rollback", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(
        jsonResponse({
          family_id: "family loading/一",
          current_shadow: {
            version_id: "version-2",
            record_version: 4,
          },
          versions: [
            {
              version_id: "version-2",
              version_number: 2,
              lifecycle_label: "影子测试中",
              is_current_shadow: true,
              can_rollback: false,
              label: "影子版本 2 (当前)",
            },
            {
              version_id: "version-1",
              version_number: 1,
              lifecycle_label: "影子测试中",
              is_current_shadow: false,
              can_rollback: true,
              label: "影子版本 1",
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          ...familyIndexWire,
          authorization_token: "rollback-action-token",
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          applied: true,
          shadow_pointer: {
            family_id: "family loading/一",
            version_id: "version-1",
            record_version: 5,
          },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "rollback-key" });
    const service = templateServices();
    await service.bootstrap();

    const options = await service.loadTemplateFamilyVersions(
      "family loading/一",
    );
    const token = await service.revalidateTemplateRollbackAction(
      "maintainer-code",
      "family loading/一",
    );
    const result = await service.rollbackTemplateShadow(
      "family loading/一",
      "version-1",
      4,
      "新版式读取异常",
      token,
    );

    expect(options.currentShadowRecordVersion).toBe(4);
    expect(options.versions[1]).toMatchObject({
      versionId: "version-1",
      canRollback: true,
      label: "影子版本 1",
    });
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      "/api/v1/template-studio/families/family%20loading%2F%E4%B8%80/versions",
    );
    expect(JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))).toEqual({
      access_code: "maintainer-code",
      action: "template.rollback_shadow",
      resource_id: "family loading/一",
    });
    expect(fetchMock.mock.calls[3]?.[0]).toBe(
      "/api/v1/template-studio/families/family%20loading%2F%E4%B8%80/rollback",
    );
    expect(fetchMock.mock.calls[3]?.[1]?.headers).toEqual(
      expect.objectContaining({
        "X-DaHe-Developer-Authorization": "rollback-action-token",
      }),
    );
    expect(JSON.parse(String(fetchMock.mock.calls[3]?.[1]?.body))).toEqual({
      target_version_id: "version-1",
      expected_record_version: 4,
      reason: "新版式读取异常",
    });
    expect(result).toEqual({
      applied: true,
      familyId: "family loading/一",
      versionId: "version-1",
      recordVersion: 5,
    });
  });

  it("uses explicit checked lifecycle endpoints and rejects undeclared actions client-side", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(sessionResponse())
      .mockResolvedValueOnce(jsonResponse(detailWire));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "template-shadow-key" });
    const service = templateServices();
    await service.bootstrap();

    await service.runTemplateVersionAction(
      "version 一/1",
      "start_shadow",
      7,
      {
        evaluationId: "development-evaluation-001",
        developerAuthorization: "developer-action-token",
      },
    );

    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/template-studio/templates/version%20%E4%B8%80%2F1/shadow",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "X-DaHe-Developer-Authorization": "developer-action-token",
        }),
        body: JSON.stringify({
          expected_record_version: 7,
          evaluation_id: "development-evaluation-001",
        }),
      }),
    );
    await expect(
      service.runTemplateVersionAction(
        "version 一/1",
        "restore_shadow",
        7,
        {
          evaluationId: "development-evaluation-001",
          developerAuthorization: "developer-action-token",
        },
      ),
    ).rejects.toThrow("family rollback context");
    await expect(
      service.runTemplateVersionAction(
        "version 一/1",
        "active" as "start_shadow",
        7,
      ),
    ).rejects.toThrow("declared template lifecycle action");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
