from __future__ import annotations

from dataclasses import fields, replace

from dahe.adapters.fake.audit import (
    FIXTURE_ID,
    FakeAuditSource,
    FakeEvidenceExtractor,
)
from dahe.ports.ocr import EvidenceExtractionInput, EvidenceImageInput


def test_ocr_input_contains_only_evidence_identity_and_image_fields() -> None:
    extraction_fields = {field.name for field in fields(EvidenceExtractionInput)}
    image_fields = {field.name for field in fields(EvidenceImageInput)}

    assert extraction_fields == {
        "evidence_set_id",
        "loading_image",
        "unloading_image",
    }
    assert image_fields == {"image_sha256", "relative_path"}
    assert all("platform" not in name for name in extraction_fields | image_fields)


def test_fake_ocr_values_are_independent_from_platform_expected_weights() -> None:
    extractor = FakeEvidenceExtractor()
    baseline_snapshot = FakeAuditSource().acquire(FIXTURE_ID)
    changed_platform = replace(
        baseline_snapshot,
        platform_loading_net="88.88",
        platform_unloading_net="77.77",
    )

    assert changed_platform.evidence_input == baseline_snapshot.evidence_input
    baseline = extractor.extract(baseline_snapshot.evidence_input)
    changed = extractor.extract(changed_platform.evidence_input)

    assert baseline.loading_ticket is not None
    assert baseline.unloading_ticket is not None
    assert changed.loading_ticket is not None
    assert changed.unloading_ticket is not None

    baseline_loading = baseline.loading_ticket.weights.ordinary_net.reading
    baseline_unloading = baseline.unloading_ticket.weights.ordinary_net.reading
    changed_loading = changed.loading_ticket.weights.ordinary_net.reading
    changed_unloading = changed.unloading_ticket.weights.ordinary_net.reading
    assert baseline_loading is not None
    assert baseline_unloading is not None
    assert changed_loading is not None
    assert changed_unloading is not None

    assert changed_loading.amount == baseline_loading.amount
    assert changed_unloading.amount == baseline_unloading.amount
