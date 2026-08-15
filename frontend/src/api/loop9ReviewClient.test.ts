import { afterEach, describe, expect, it, vi } from "vitest";

import { BrowserAppServices } from "./client";

function jsonResponse(value: object) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

const wireItem = {
  item_identity_sha256: "e".repeat(64),
  position: 1,
  review_kind: "current_locked_50",
  review_status: "confirmed",
  record_version: 2,
  platform_weights: { loading: "30.00", unloading: "29.80" },
  images: [
    {
      slot: "loading",
      image_sha256: "a".repeat(64),
      image_url: "/api/v1/loop9-review/images/loading",
    },
    {
      slot: "unloading",
      image_sha256: "b".repeat(64),
      image_url: "/api/v1/loop9-review/images/unloading",
    },
  ],
  advisory: {
    item_identity_sha256: "e".repeat(64),
    truth_status: "unconfirmed_non_truth",
    images: [
      {
        slot: "loading",
        image_sha256: "a".repeat(64),
        role: "loading",
        ordinary_net: "30.00",
        quality_conditions: ["rotation_0"],
      },
      {
        slot: "unloading",
        image_sha256: "b".repeat(64),
        role: "unloading",
        ordinary_net: "29.80",
        quality_conditions: ["rotation_0"],
      },
    ],
    pair_condition: "normal_pair",
  },
  truth: {
    images: [
      {
        slot: "loading",
        image_sha256: "a".repeat(64),
        role: "loading",
        ordinary_net: "30.00",
        quality_conditions: ["rotation_0"],
      },
      {
        slot: "unloading",
        image_sha256: "b".repeat(64),
        role: "unloading",
        ordinary_net: "29.80",
        quality_conditions: ["rotation_0"],
      },
    ],
    pair_condition: "normal_pair",
  },
  confirmation: "suggestion_confirmed",
  confirmed_at: "2026-07-30T00:00:00Z",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Loop 9 review client", () => {
  it("reads the isolated feature flag and maps the immutable review index", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          application_version: "1.1.4",
          csrf_token: "csrf-loop9",
          locked_set_review_enabled: false,
          loop9_review_enabled: true,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          package_sha256: "c".repeat(64),
          review_kind: "current_locked_50",
          advisory_message: "辅助建议，尚未成为真值",
          review_revision_sha256: "d".repeat(64),
          progress: {
            total: 50,
            confirmed: 1,
            draft: 0,
            remaining: 49,
          },
          items: [
            {
              item_identity_sha256: "e".repeat(64),
              position: 1,
              review_status: "confirmed",
              record_version: 2,
            },
          ],
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const service = new BrowserAppServices();

    await expect(service.bootstrap()).resolves.toMatchObject({
      loop9ReviewEnabled: true,
    });
    await expect(service.loadLoop9Review()).resolves.toMatchObject({
      advisoryMessage: "辅助建议，尚未成为真值",
      progress: { total: 50, confirmed: 1, remaining: 49 },
    });
  });

  it("posts only versioned truth with the standard idempotency header", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          application_version: "1.1.4",
          csrf_token: "csrf-loop9",
          locked_set_review_enabled: false,
          loop9_review_enabled: true,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          item: wireItem,
          progress: {
            total: 50,
            confirmed: 1,
            draft: 0,
            remaining: 49,
          },
          review_revision_sha256: "d".repeat(64),
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "loop9-review-key" });
    const service = new BrowserAppServices();
    await service.bootstrap();

    await service.confirmLoop9ReviewItem("e".repeat(64), {
      expectedRecordVersion: 1,
      verifiedImageSha256s: ["a".repeat(64), "b".repeat(64)],
      truth: {
        images: [
          {
            slot: "loading",
            imageSha256: "a".repeat(64),
            role: "loading",
            ordinaryNet: "30.00",
            qualityConditions: ["rotation_0"],
          },
          {
            slot: "unloading",
            imageSha256: "b".repeat(64),
            role: "unloading",
            ordinaryNet: "29.80",
            qualityConditions: ["rotation_0"],
          },
        ],
        pairCondition: "normal_pair",
      },
    });

    const request = fetchMock.mock.calls.at(-1);
    expect(request?.[0]).toBe(
      `/api/v1/loop9-review/items/${"e".repeat(64)}/confirm`,
    );
    expect(request?.[1]).toEqual(
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "X-CSRF-Token": "csrf-loop9",
          "Idempotency-Key": "loop9-review-key",
        }),
      }),
    );
    const body = JSON.parse(String(request?.[1]?.body)) as object;
    expect(body).toEqual({
      expected_record_version: 1,
      truth: {
        images: [
          {
            slot: "loading",
            image_sha256: "a".repeat(64),
            role: "loading",
            ordinary_net: "30.00",
            quality_conditions: ["rotation_0"],
          },
          {
            slot: "unloading",
            image_sha256: "b".repeat(64),
            role: "unloading",
            ordinary_net: "29.80",
            quality_conditions: ["rotation_0"],
          },
        ],
        pair_condition: "normal_pair",
      },
      verified_image_sha256s: [
        "a".repeat(64),
        "b".repeat(64),
      ],
    });
    expect(JSON.stringify(body)).not.toMatch(
      /reviewer|operator|actor|employee|notes/i,
    );
  });
});
