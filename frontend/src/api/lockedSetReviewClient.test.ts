import { afterEach, describe, expect, it, vi } from "vitest";

import { BrowserAppServices } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonResponse(value: object) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("locked-set review client", () => {
  it("reads the server feature flag from the existing session bootstrap", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          application_version: "1.1.0",
          csrf_token: "csrf-review",
          locked_set_review_enabled: true,
        }),
      ),
    );

    await expect(new BrowserAppServices().bootstrap()).resolves.toMatchObject({
      applicationVersion: "1.1.0",
      lockedSetReviewEnabled: true,
    });
  });

  it("maps the package index and one detail without introducing answer fields", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          package: {
            package_id: "locked-review-001",
            status: "awaiting_human_review",
          },
          progress: {
            total: 50,
            completed: 1,
            remaining: 49,
            replace_candidate: 0,
          },
          items: [
            {
              sample_id: "L7-001",
              position: 1,
              review_status: "confirmed",
              record_version: 2,
              decision: "confirmed",
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          sample_id: "L7-001",
          position: 1,
          record_version: 2,
          review_status: "completed",
          selection_clues: ["legacy_review_hint"],
          images: [
            {
              submitted_slot: "loading",
              image_url: "/api/v1/locked-set-review/images/loading-hash",
              selection_clues: ["rotation_90_hint"],
              human_review: {
                role: "unloading",
                ordinary_net: "30.25",
                quality_conditions: ["rotation_90", "screen"],
                notes: null,
              },
            },
            {
              submitted_slot: "unloading",
              image_url: "/api/v1/locked-set-review/images/unloading-hash",
              selection_clues: [],
              human_review: {
                role: null,
                ordinary_net: null,
                quality_conditions: [],
                notes: null,
              },
            },
          ],
          pair_review: {
              conditions: ["swapped_pair"],
            notes: "两张票位置可能放反",
          },
          decision: "confirmed",
          replace_reason: null,
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const service = new BrowserAppServices();

    const index = await service.loadLockedSetReview();
    const detail = await service.loadLockedSetReviewItem("L7-001");

    expect(index.progress).toEqual({
      total: 50,
      completed: 1,
      remaining: 49,
      replaceCandidate: 0,
    });
    expect(index.items[0]).toMatchObject({
      sampleId: "L7-001",
      reviewStatus: "confirmed",
      recordVersion: 2,
    });
    expect(detail.images[0]).toMatchObject({
      submittedSlot: "loading",
      imageUrl: "/api/v1/locked-set-review/images/loading-hash",
      review: {
        role: "unloading",
        ordinaryNet: "30.25",
        qualityConditions: ["rotation_90", "screen"],
      },
    });
    expect(detail.images[1]?.review).toBeNull();
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "/api/v1/locked-set-review/items/L7-001",
      expect.objectContaining({ cache: "no-store" }),
    );
  });

  it("posts a versioned review with the requested idempotency header", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          application_version: "1.1.0",
          csrf_token: "csrf-review",
          locked_set_review_enabled: true,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          item: {
            sample_id: "L7-001",
            position: 1,
            record_version: 3,
            review_status: "confirmed",
            selection_clues: [],
            images: [],
            pair_review: { conditions: ["normal_pair"], notes: null },
            decision: "confirmed",
            replace_reason: null,
          },
          progress: {
            total: 50,
            completed: 2,
            remaining: 48,
            replace_candidate: 0,
          },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "review-idempotency-key" });
    const service = new BrowserAppServices();
    await service.bootstrap();

    await service.saveLockedSetReviewItem("L7-001", {
      expectedRecordVersion: 2,
      decision: "confirmed",
      images: [
        {
          submittedSlot: "loading",
          role: "loading",
          ordinaryNet: "30.50",
          qualityConditions: ["rotation_0", "printed"],
          notes: "",
        },
        {
          submittedSlot: "unloading",
          role: "unloading",
          ordinaryNet: "30.25",
          qualityConditions: ["rotation_90", "screen"],
          notes: "屏幕拍摄",
        },
      ],
      pairConditions: ["normal_pair"],
      pairNotes: null,
      replaceReason: null,
    });

    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/locked-set-review/items/L7-001/review",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "X-CSRF-Token": "csrf-review",
          "Idempotency-Key": "review-idempotency-key",
        }),
        body: JSON.stringify({
          expected_record_version: 2,
          decision: "confirmed",
          images: [
            {
              submitted_slot: "loading",
              role: "loading",
              ordinary_net: "30.50",
              quality_conditions: ["rotation_0", "printed"],
              notes: "",
            },
            {
              submitted_slot: "unloading",
              role: "unloading",
              ordinary_net: "30.25",
              quality_conditions: ["rotation_90", "screen"],
              notes: "屏幕拍摄",
            },
          ],
          pair_conditions: ["normal_pair"],
          pair_notes: null,
          replace_reason: null,
        }),
      }),
    );
    expect(
      fetchMock.mock.calls.at(-1)?.[1]?.headers,
    ).not.toHaveProperty("X-Idempotency-Key");
  });

  it("reuses the standard idempotency key after an uncertain save failure", async () => {
    const savedItem = {
      item: {
        sample_id: "L7-001",
        position: 1,
        record_version: 1,
        review_status: "replace_candidate",
        selection_clues: [],
        images: [],
        pair_review: { conditions: [], notes: null },
        decision: "replace_candidate",
        replace_reason: "图片无法辨认",
      },
      progress: {
        total: 50,
        completed: 1,
        remaining: 49,
        replace_candidate: 1,
      },
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          application_version: "1.1.0",
          csrf_token: "csrf-review",
          locked_set_review_enabled: true,
        }),
      )
      .mockRejectedValueOnce(new Error("connection reset"))
      .mockResolvedValueOnce(jsonResponse(savedItem));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("crypto", { randomUUID: () => "stable-review-key" });
    const service = new BrowserAppServices();
    await service.bootstrap();
    const input = {
      expectedRecordVersion: 0,
      decision: "replace_candidate" as const,
      images: [],
      pairConditions: [],
      pairNotes: null,
      replaceReason: "图片无法辨认",
    };

    await expect(
      service.saveLockedSetReviewItem("L7-001", input),
    ).rejects.toThrow("connection reset");
    await service.saveLockedSetReviewItem("L7-001", input);

    expect(fetchMock.mock.calls[1]?.[1]?.headers).toMatchObject({
      "Idempotency-Key": "stable-review-key",
    });
    expect(fetchMock.mock.calls[2]?.[1]?.headers).toMatchObject({
      "Idempotency-Key": "stable-review-key",
    });
  });
});
