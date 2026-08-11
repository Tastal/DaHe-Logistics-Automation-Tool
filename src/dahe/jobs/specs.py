from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

OcrExecutionMode = Literal["fake", "local"]
JobRunMode = Literal["shadow", "operational"]


@dataclass(frozen=True, slots=True)
class ScheduledWorkItemSpec:
    """Frozen input for one deterministic scheduled work item."""

    item_key: str
    expected_outcome: str | None
    review_reason: str | None = None
    loading_image_sha256: str | None = None
    unloading_image_sha256: str | None = None
    loading_image_relative_path: str | None = None
    unloading_image_relative_path: str | None = None
    required_resource: str | None = None
    vehicle_number: str | None = None
    platform_loading_net: str | None = None
    platform_unloading_net: str | None = None
    ticket_loading_net: str | None = None
    ticket_unloading_net: str | None = None
    diagnostic_code: str | None = None
    evidence_preloaded: bool = False


@dataclass(frozen=True, slots=True)
class ScheduledJobSpec:
    """Adapter-neutral input accepted by the cooperative job store."""

    fixture_id: str
    job_kind: str
    task_type: str
    scope_label: str
    conflict_key: str
    items: tuple[ScheduledWorkItemSpec, ...]
    pipeline_fingerprint: str | None = None
    ocr_execution_mode: OcrExecutionMode = "fake"
    run_mode: JobRunMode = "shadow"

    def __post_init__(self) -> None:
        if self.run_mode not in {"shadow", "operational"}:
            raise ValueError("scheduled job run mode is invalid")
        if any(item.evidence_preloaded for item in self.items) and not (
            self.task_type == "audit" and self.ocr_execution_mode == "local"
        ):
            raise ValueError(
                "preloaded evidence is limited to local OCR audit jobs"
            )
        if self.ocr_execution_mode == "local":
            fingerprint = self.pipeline_fingerprint
            if (
                self.task_type != "audit"
                or fingerprint is None
                or len(fingerprint) != 64
                or fingerprint != fingerprint.lower()
                or any(character not in "0123456789abcdef" for character in fingerprint)
            ):
                raise ValueError(
                    "local OCR jobs require an audit SHA-256 pipeline contract"
                )
            if any(
                (
                    item.loading_image_relative_path is None
                    or item.unloading_image_relative_path is None
                )
                and not (
                    item.expected_outcome == "awaiting_review"
                    and item.review_reason == "missing_ticket"
                )
                for item in self.items
            ):
                raise ValueError(
                    "local OCR jobs require complete evidence or an explicit missing ticket"
                )
            if any(
                item.evidence_preloaded
                and not (
                    (
                        item.loading_image_sha256 is not None
                        and item.unloading_image_sha256 is not None
                        and item.loading_image_relative_path is not None
                        and item.unloading_image_relative_path is not None
                    )
                    or (
                        item.expected_outcome == "awaiting_review"
                        and item.review_reason == "missing_ticket"
                    )
                )
                for item in self.items
            ):
                raise ValueError(
                    "preloaded evidence must be complete or an explicit missing ticket"
                )
