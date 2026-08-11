from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class AuditLayer(StrEnum):
    EVIDENCE = "evidence"
    OCR = "ocr"
    DECISION = "decision"
    MANUAL = "manual"


class InvalidationCause(StrEnum):
    IMAGE_CHANGED = "image_changed"
    PLATFORM_VALUE_CHANGED = "platform_value_changed"
    OCR_PIPELINE_CHANGED = "ocr_pipeline_changed"
    AUDIT_RULE_CHANGED = "audit_rule_changed"
    MANUAL_ACTION_REVOKED = "manual_action_revoked"


@dataclass(frozen=True, slots=True)
class EvidenceRevisionInput:
    platform_snapshot_sha256: str
    loading_image_sha256: str | None
    unloading_image_sha256: str | None

    def __post_init__(self) -> None:
        _require_sha(self.platform_snapshot_sha256, "platform snapshot")
        for field, label in (
            (self.loading_image_sha256, "loading image"),
            (self.unloading_image_sha256, "unloading image"),
        ):
            if field is not None:
                _require_sha(field, label)


def _require_sha(value: str, label: str) -> None:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} fingerprint must be a lowercase SHA-256")


def _fingerprint(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_evidence_fingerprint(value: EvidenceRevisionInput) -> str:
    return _fingerprint(
        {
            "loading_image_sha256": value.loading_image_sha256,
            "platform_snapshot_sha256": value.platform_snapshot_sha256,
            "unloading_image_sha256": value.unloading_image_sha256,
        }
    )


def build_ocr_cache_key(
    *,
    image_sha256: str,
    pipeline_fingerprint: str,
    template_set_fingerprint: str,
) -> str:
    for value, label in (
        (image_sha256, "image"),
        (pipeline_fingerprint, "pipeline"),
        (template_set_fingerprint, "template set"),
    ):
        _require_sha(value, label)
    return _fingerprint(
        {
            "image_sha256": image_sha256,
            "pipeline_fingerprint": pipeline_fingerprint,
            "template_set_fingerprint": template_set_fingerprint,
        }
    )


def build_decision_fingerprint(
    *,
    evidence_fingerprint: str,
    loading_ocr_fingerprint: str | None,
    unloading_ocr_fingerprint: str | None,
    rule_version: str,
) -> str:
    _require_sha(evidence_fingerprint, "evidence")
    for value, label in (
        (loading_ocr_fingerprint, "loading OCR"),
        (unloading_ocr_fingerprint, "unloading OCR"),
    ):
        if value is not None:
            _require_sha(value, label)
    if not rule_version.strip():
        raise ValueError("rule version is required")
    return _fingerprint(
        {
            "evidence_fingerprint": evidence_fingerprint,
            "loading_ocr_fingerprint": loading_ocr_fingerprint,
            "rule_version": rule_version,
            "unloading_ocr_fingerprint": unloading_ocr_fingerprint,
        }
    )


def invalidated_layers(cause: InvalidationCause) -> frozenset[AuditLayer]:
    return {
        InvalidationCause.IMAGE_CHANGED: frozenset(AuditLayer),
        InvalidationCause.PLATFORM_VALUE_CHANGED: frozenset(
            {AuditLayer.EVIDENCE, AuditLayer.DECISION, AuditLayer.MANUAL}
        ),
        InvalidationCause.OCR_PIPELINE_CHANGED: frozenset(
            {AuditLayer.OCR, AuditLayer.DECISION, AuditLayer.MANUAL}
        ),
        InvalidationCause.AUDIT_RULE_CHANGED: frozenset(
            {AuditLayer.DECISION, AuditLayer.MANUAL}
        ),
        InvalidationCause.MANUAL_ACTION_REVOKED: frozenset({AuditLayer.MANUAL}),
    }[cause]
