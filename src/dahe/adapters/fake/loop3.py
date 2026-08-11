from __future__ import annotations

from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec

LOOP3_PIPELINE_FINGERPRINT = "loop3-fake-ocr-v1"
SHARED_LOADING_IMAGE_SHA256 = (
    "52f865758aaba0299633e826c412bc8d045a4678d2da31357f41759060e35e27"
)
SHORT_UNLOADING_IMAGE_SHA256 = (
    "a68dea53c89b0efc17d4110c381f9c4abc2ad3a89ab1e0e336f4c654553fc300"
)


LONG_ITEMS = (
    ScheduledWorkItemSpec(
        "L3-LONG-001",
        "normal_ready",
        loading_image_sha256=(
            "1fb50147ce84e9978f1e1aae4ee0a6a3a4deeeb1a1b2d219b32640c6aa437b46"
        ),
        unloading_image_sha256=(
            "01169e812fc3a3f179bfa23b41483bad959589959d69ba94070103b7cd6c8c91"
        ),
    ),
    ScheduledWorkItemSpec(
        "L3-LONG-002",
        "awaiting_review",
        review_reason="suspected_swapped",
        loading_image_sha256=(
            "0309c03cb5ad68a93c47255ba232cad6440408a640d16a9043b91d884a6d3dc7"
        ),
        unloading_image_sha256=(
            "cc3ff89b47d00d7a82f5d0690de71e0b837542236b8c2e7eda7a07849ba1dabe"
        ),
    ),
    ScheduledWorkItemSpec(
        "L3-LONG-003",
        "awaiting_review",
        review_reason="numeric_mismatch",
        loading_image_sha256=(
            "ff290842f087c081774919a9bac24e54de6d13158e11393f3bb8693aa92c7623"
        ),
        unloading_image_sha256=(
            "de667220697f731aa1c912f7fe49f3289a55cc764cdbd98532cedb0a66bbcb01"
        ),
    ),
    ScheduledWorkItemSpec(
        "L3-LONG-004",
        "normal_ready",
        loading_image_sha256=SHARED_LOADING_IMAGE_SHA256,
        unloading_image_sha256=(
            "5323d9dbc5396c5e8d155c8ae8d5cd22bdc24bc31a0212cf02ef3d0982103613"
        ),
    ),
    ScheduledWorkItemSpec(
        "L3-LONG-005",
        "normal_ready",
        loading_image_sha256=(
            "44b64207e985deefd44ef2bad7c6e94d3bf116dd5764269bc090fce55e1b612a"
        ),
        unloading_image_sha256=(
            "944c8ef38d41c4f91a5a94709d27787f8f63ac02efd59320f183abf327cb1920"
        ),
    ),
    ScheduledWorkItemSpec(
        "L3-LONG-006",
        "normal_ready",
        loading_image_sha256=(
            "35bd0f4d43987b54439346614faae367040f53e60a7280a12c2f66f996876e5b"
        ),
        unloading_image_sha256=(
            "dd38bed337a62882bc37813f78bdc1487871cbbd6645f975f1625daa85ea2b1d"
        ),
    ),
)

LOOP3_FIXTURES: dict[str, ScheduledJobSpec] = {
    "audit-batch-long-001": ScheduledJobSpec(
        fixture_id="audit-batch-long-001",
        job_kind="test_fixture",
        task_type="audit",
        scope_label="并行审核演练（长批次）",  # noqa: RUF001
        conflict_key="audit:loop3-long-001",
        items=LONG_ITEMS,
        pipeline_fingerprint=LOOP3_PIPELINE_FINGERPRINT,
    ),
    "audit-batch-short-002": ScheduledJobSpec(
        fixture_id="audit-batch-short-002",
        job_kind="test_fixture",
        task_type="audit",
        scope_label="并行审核演练（短批次）",  # noqa: RUF001
        conflict_key="audit:loop3-short-002",
        items=(
            ScheduledWorkItemSpec(
                "L3-SHORT-101",
                "normal_ready",
                loading_image_sha256=SHARED_LOADING_IMAGE_SHA256,
                unloading_image_sha256=SHORT_UNLOADING_IMAGE_SHA256,
            ),
        ),
        pipeline_fingerprint=LOOP3_PIPELINE_FINGERPRINT,
    ),
    "loading-probe-001": ScheduledJobSpec(
        fixture_id="loading-probe-001",
        job_kind="test_fixture",
        task_type="loading_probe",
        scope_label="装卸车并行调度探针",
        conflict_key="test_fixture:loading-probe-001",
        items=(
            ScheduledWorkItemSpec(
                "L3-PLATFORM-201",
                None,
                required_resource="platform_browser",
            ),
            ScheduledWorkItemSpec(
                "L3-PLATFORM-202",
                None,
                required_resource="platform_browser",
            ),
        ),
    ),
}


def get_loop3_fixture(fixture_id: str) -> ScheduledJobSpec:
    try:
        return LOOP3_FIXTURES[fixture_id]
    except KeyError as exc:
        raise ValueError("unknown deterministic Loop 3 fixture") from exc
