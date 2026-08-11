from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Protocol

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class LocalAuditTechnicalError(RuntimeError):
    """Raised when local OCR evidence cannot safely enter a business decision."""

    def __init__(self, message: str, *, diagnostic_code: str) -> None:
        super().__init__(message)
        self.diagnostic_code = diagnostic_code


@dataclass(frozen=True, slots=True)
class LocalAuditEvaluationInput:
    work_item_id: str
    snapshot_id: str
    loading_image_sha256: str
    unloading_image_sha256: str
    platform_loading_net: str
    platform_unloading_net: str
    pipeline_fingerprint: str
    runtime_fingerprint: str
    loading_output_json: str
    unloading_output_json: str

    def __post_init__(self) -> None:
        if not self.work_item_id or not self.snapshot_id:
            raise ValueError("local audit identities are required")
        for label, value in (
            ("loading image", self.loading_image_sha256),
            ("unloading image", self.unloading_image_sha256),
            ("pipeline", self.pipeline_fingerprint),
            ("runtime", self.runtime_fingerprint),
        ):
            if _SHA256.fullmatch(value) is None:
                raise ValueError(f"{label} identity must be lowercase SHA-256")
        if not self.platform_loading_net or not self.platform_unloading_net:
            raise ValueError("local audit platform weights are required")
        if not self.loading_output_json or not self.unloading_output_json:
            raise ValueError("local audit OCR outputs are required")


@dataclass(frozen=True, slots=True)
class LocalAuditEvaluation:
    business_outcome: str
    decision: str
    review_reason: str | None
    ticket_loading_net: str | None
    ticket_unloading_net: str | None

    def __post_init__(self) -> None:
        if self.business_outcome not in {"normal_ready", "awaiting_review"}:
            raise ValueError("local audit business outcome is invalid")
        if self.decision not in {
            "pass",
            "review",
            "weight_mismatch",
            "suspected_problem",
        }:
            raise ValueError("local audit decision is invalid")
        if self.business_outcome == "normal_ready":
            if self.decision != "pass" or self.review_reason is not None:
                raise ValueError("normal local audit result must be an unqualified pass")
        elif self.review_reason is None:
            raise ValueError("review local audit result requires a reason")


@dataclass(frozen=True, slots=True)
class LocalAuditObservationProjection:
    """Bounded role and weight evidence derived from one committed OCR result."""

    ticket_role: Literal["loading", "unloading", "unknown"]
    role_quality: str
    role_fingerprint: str
    role_high_confidence: bool
    template_set_fingerprint: str
    ordinary_net_amount: str | None
    ordinary_net_unit: str | None
    ordinary_net_reliable: bool
    weight_review_reason: str | None

    def __post_init__(self) -> None:
        if self.ticket_role not in {"loading", "unloading", "unknown"}:
            raise ValueError("local audit ticket role is invalid")
        if not self.role_quality:
            raise ValueError("local audit role quality is required")
        for value, label in (
            (self.role_fingerprint, "role"),
            (self.template_set_fingerprint, "template set"),
        ):
            if _SHA256.fullmatch(value) is None:
                raise ValueError(
                    f"local audit {label} fingerprint must be lowercase SHA-256"
                )
        if not isinstance(self.role_high_confidence, bool):
            raise ValueError("local audit role confidence flag is invalid")
        if not isinstance(self.ordinary_net_reliable, bool):
            raise ValueError("local audit weight reliability flag is invalid")


class LocalAuditEvaluator(Protocol):
    def evaluate(
        self,
        request: LocalAuditEvaluationInput,
    ) -> LocalAuditEvaluation: ...


class LocalAuditObservationProjector(Protocol):
    def project_observation(
        self,
        *,
        output_json: str,
        expected_image_sha256: str,
        expected_runtime_fingerprint: str,
    ) -> LocalAuditObservationProjection: ...
