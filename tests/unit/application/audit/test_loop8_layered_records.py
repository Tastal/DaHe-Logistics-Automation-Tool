from __future__ import annotations

from dahe.application.audit.layered_records import (
    AuditLayer,
    EvidenceRevisionInput,
    InvalidationCause,
    build_decision_fingerprint,
    build_evidence_fingerprint,
    build_ocr_cache_key,
    invalidated_layers,
)


def sha(character: str) -> str:
    return character * 64


def evidence() -> EvidenceRevisionInput:
    return EvidenceRevisionInput(
        platform_snapshot_sha256=sha("a"),
        loading_image_sha256=sha("b"),
        unloading_image_sha256=sha("c"),
    )


def test_layer_fingerprints_are_deterministic_and_separate() -> None:
    first = build_evidence_fingerprint(evidence())
    assert first == build_evidence_fingerprint(evidence())

    changed_platform = EvidenceRevisionInput(
        platform_snapshot_sha256=sha("d"),
        loading_image_sha256=sha("b"),
        unloading_image_sha256=sha("c"),
    )
    assert build_evidence_fingerprint(changed_platform) != first

    ocr_key = build_ocr_cache_key(
        image_sha256=sha("b"),
        pipeline_fingerprint=sha("e"),
        template_set_fingerprint=sha("f"),
    )
    assert ocr_key == build_ocr_cache_key(
        image_sha256=sha("b"),
        pipeline_fingerprint=sha("e"),
        template_set_fingerprint=sha("f"),
    )
    assert build_decision_fingerprint(
        evidence_fingerprint=first,
        loading_ocr_fingerprint=ocr_key,
        unloading_ocr_fingerprint=sha("1"),
        rule_version="audit-rules-v1",
    ) != build_decision_fingerprint(
        evidence_fingerprint=first,
        loading_ocr_fingerprint=ocr_key,
        unloading_ocr_fingerprint=sha("1"),
        rule_version="audit-rules-v2",
    )


def test_each_change_invalidates_only_its_downstream_layers() -> None:
    assert invalidated_layers(InvalidationCause.IMAGE_CHANGED) == frozenset(
        {AuditLayer.EVIDENCE, AuditLayer.OCR, AuditLayer.DECISION, AuditLayer.MANUAL}
    )
    assert invalidated_layers(InvalidationCause.PLATFORM_VALUE_CHANGED) == frozenset(
        {AuditLayer.EVIDENCE, AuditLayer.DECISION, AuditLayer.MANUAL}
    )
    assert invalidated_layers(InvalidationCause.OCR_PIPELINE_CHANGED) == frozenset(
        {AuditLayer.OCR, AuditLayer.DECISION, AuditLayer.MANUAL}
    )
    assert invalidated_layers(InvalidationCause.AUDIT_RULE_CHANGED) == frozenset(
        {AuditLayer.DECISION, AuditLayer.MANUAL}
    )
    assert invalidated_layers(InvalidationCause.MANUAL_ACTION_REVOKED) == frozenset(
        {AuditLayer.MANUAL}
    )
