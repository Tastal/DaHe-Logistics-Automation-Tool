from __future__ import annotations

import json
from decimal import Decimal

import pytest

from dahe.adapters.ocr.locked_set_evaluator import (
    LocalOcrLockedImageEvaluator,
)
from dahe.adapters.ocr.protocol import (
    NormalizedBox,
    OcrFieldValue,
    OcrResult,
    OcrResultStatus,
    OcrRoleObservation,
    OcrTextLine,
)
from dahe.application.template_studio.development_evaluation import (
    development_matcher_fingerprint,
)
from dahe.application.template_studio.matcher import (
    build_template_set_fingerprint,
)
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    NormalizedRect,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateVersion,
)
from dahe.jobs.ocr_errors import OcrErrorKind
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrImageExecution,
    OcrImageExecutionError,
    OcrImageWork,
    OcrRuntimeIdentity,
)
from dahe.verification.application_build import (
    ApplicationBuildManifest,
    ApplicationBuildSource,
)
from dahe.verification.locked_set_runner import (
    IndependentLockedImage,
    LockedSetRunnerError,
)


def _sha256(index: int) -> str:
    return f"{index:064x}"


def _application_build_manifest() -> ApplicationBuildManifest:
    return ApplicationBuildManifest(
        application_version="test-build",
        sources=(
            ApplicationBuildSource(
                path="adapters/ocr/locked_set_evaluator.py",
                sha256=_sha256(62_000),
            ),
        ),
    )


def _rect(x: str, y: str, width: str, height: str) -> NormalizedRect:
    return NormalizedRect(
        x=Decimal(x),
        y=Decimal(y),
        width=Decimal(width),
        height=Decimal(height),
    )


def _version(role: TicketRole, marker: str) -> TemplateVersion:
    title = "装货磅单" if role is TicketRole.LOADING else "卸货磅单"
    return TemplateVersion(
        version_id=f"{marker}-v1",
        definition=TemplateDefinition(
            family_id=f"{marker}-family",
            name=f"{marker} ticket",
            role=role,
            anchors=(
                TemplateAnchor(
                    anchor_id=f"{marker}-title",
                    expected_text=title,
                    box=_rect("0.10", "0.08", "0.30", "0.08"),
                    required=True,
                    weight=Decimal("1"),
                    max_edit_distance=Decimal("0.10"),
                    loading_evidence=(
                        Decimal("0.9") if role is TicketRole.LOADING else Decimal("-0.4")
                    ),
                    unloading_evidence=(
                        Decimal("0.9") if role is TicketRole.UNLOADING else Decimal("-0.4")
                    ),
                ),
            ),
            regions=(),
        ),
        lifecycle=TemplateLifecycle.SHADOW,
        parent_version_id=None,
        record_version=3,
    )


class _Gateway:
    def __init__(
        self,
        runtime_kind: str,
        *,
        fail: bool = False,
        invalid_result_json: bool = False,
        ticket_role: TicketRole = TicketRole.LOADING,
        ordinary_net_amount: str | None = "30.00",
        ordinary_net_unit: str | None = "t",
        ordinary_net_confidence: Decimal = Decimal("0.98"),
        elapsed_ms: float = 2.5,
    ) -> None:
        self._identity = OcrRuntimeIdentity(
            runtime_kind=runtime_kind,  # type: ignore[arg-type]
            profile_id=f"{runtime_kind}-qualified",
            runtime_fingerprint=(_sha256(61_001) if runtime_kind == "gpu" else _sha256(61_002)),
        )
        self.fail = fail
        self.invalid_result_json = invalid_result_json
        self.ticket_role = ticket_role
        self.ordinary_net_amount = ordinary_net_amount
        self.ordinary_net_unit = ordinary_net_unit
        self.ordinary_net_confidence = ordinary_net_confidence
        self.elapsed_ms = elapsed_ms
        self.calls: list[OcrImageWork] = []

    @property
    def identity(self) -> OcrRuntimeIdentity:
        return self._identity

    def extract(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution:
        self.calls.append(image)
        if self.fail:
            raise OcrImageExecutionError(
                OcrErrorKind.WORKER_CRASHED,
                "OCR-SYNTHETIC-FAILURE",
                "synthetic failure",
            )
        title = "装货磅单" if self.ticket_role is TicketRole.LOADING else "卸货磅单"
        role_text = (
            ("装货", "磅单", "净重")
            if self.ticket_role is TicketRole.LOADING
            else ("卸货", "磅单", "净重")
        )
        ordinary_net = (
            {}
            if self.ordinary_net_amount is None
            else {
                "ordinary_net": OcrFieldValue(
                    raw_text=self.ordinary_net_amount,
                    amount=self.ordinary_net_amount,
                    unit=self.ordinary_net_unit,
                    confidence=self.ordinary_net_confidence,
                )
            }
        )
        result = OcrResult(
            command_id="locked-command-001",
            status=OcrResultStatus.OK,
            worker_identity="locked-test-worker",
            runtime_fingerprint=self.identity.runtime_fingerprint,
            verified_image_sha256=image.image_sha256,
            elapsed_ms=self.elapsed_ms,
            text_lines=(
                OcrTextLine(
                    text=title,
                    confidence=Decimal("0.99"),
                    box=NormalizedBox(
                        x=Decimal("0.10"),
                        y=Decimal("0.08"),
                        width=Decimal("0.30"),
                        height=Decimal("0.08"),
                    ),
                ),
            ),
            fields=ordinary_net,
            role_observation=OcrRoleObservation(
                fixed_text=role_text,
                layout_fingerprint="locked-test-layout",
                orientation_degrees=0,
            ),
            error=None,
        )
        output_json = json.dumps(
            result.model_dump(mode="json"),
            ensure_ascii=False,
        )
        if self.invalid_result_json:
            output_json = "{not-valid-ocr-json"
        return OcrImageExecution(
            image_sha256=image.image_sha256,
            output_json=output_json,
            output_fingerprint=_sha256(61_003),
        )

    def close(self) -> None:
        return


def _templates() -> tuple[TemplateVersion, ...]:
    return (
        _version(TicketRole.LOADING, "loading"),
        _version(TicketRole.UNLOADING, "unloading"),
    )


def test_local_evaluator_requires_hash_bound_application_build_evidence() -> None:
    cpu = _Gateway("cpu")
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="cpu",
        gateways={"cpu": cpu},
    )
    manifest = _application_build_manifest()
    try:
        evaluator = LocalOcrLockedImageEvaluator(
            backend=backend,
            templates=_templates(),
            application_build_sha256=manifest.canonical_sha256,
            application_build_manifest=manifest,
            timeout_seconds=2,
        )
        assert evaluator.run_context.application_build_manifest == manifest
        with pytest.raises(LockedSetRunnerError, match="application build"):
            LocalOcrLockedImageEvaluator(
                backend=backend,
                templates=_templates(),
                application_build_sha256=_sha256(62_001),
                application_build_manifest=manifest,
                timeout_seconds=2,
            )
    finally:
        backend.close()


def test_local_evaluator_uses_only_independent_image_and_records_context() -> None:
    cpu = _Gateway("cpu")
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="cpu",
        gateways={"cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    try:
        prediction = evaluator(
            IndependentLockedImage(
                image_sha256=_sha256(1),
                relative_path="locked/images/001.png",
            )
        )
        context = evaluator.run_context
    finally:
        backend.close()

    assert prediction.image_sha256 == _sha256(1)
    assert prediction.role is TicketRole.LOADING
    assert prediction.runtime_comparison.status == "single_cpu"
    assert prediction.runtime_comparison.critical_fields_match is None
    assert prediction.runtime_comparison.selected_runtime_kind == "cpu"
    assert len(prediction.runtime_comparison.outputs) == 1
    assert prediction.runtime_comparison.outputs[0].ordinary_net_amount == Decimal("30.00")
    assert cpu.calls == [
        OcrImageWork(
            image_sha256=_sha256(1),
            relative_path="locked/images/001.png",
        )
    ]
    assert context.application_build_sha256 == (
        _application_build_manifest().canonical_sha256
    )
    assert context.expected_runtime_kinds == ("cpu",)
    assert len(context.ocr_composition_evidence_sha256) == 64
    assert context.template_set_sha256 == build_template_set_fingerprint(_templates())
    assert context.matcher_sha256 == development_matcher_fingerprint()


def test_dual_runtime_evaluation_runs_gpu_and_cpu_and_records_consistent_outputs() -> None:
    gpu = _Gateway("gpu", elapsed_ms=2.5)
    cpu = _Gateway("cpu", elapsed_ms=8.5)
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gpu, "cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    image = IndependentLockedImage(
        image_sha256=_sha256(6),
        relative_path="locked/images/006.png",
    )
    try:
        prediction = evaluator(image)
    finally:
        backend.close()

    assert prediction.role is TicketRole.LOADING
    assert [item.image_sha256 for item in gpu.calls] == [_sha256(6)]
    assert [item.image_sha256 for item in cpu.calls] == [_sha256(6)]
    comparison = prediction.runtime_comparison
    assert comparison.status == "dual_consistent"
    assert comparison.selected_runtime_kind == "gpu"
    assert comparison.critical_fields_match is True
    assert comparison.differences == ()
    assert comparison.failures == ()
    by_runtime = {item.runtime_kind: item for item in comparison.outputs}
    assert set(by_runtime) == {"cpu", "gpu"}
    assert by_runtime["gpu"].worker_elapsed_ms == Decimal("2.5")
    assert by_runtime["cpu"].worker_elapsed_ms == Decimal("8.5")
    assert all(item.wall_elapsed_ms >= 0 for item in comparison.outputs)
    assert all(
        item.safety_route == "eligible_for_downstream_comparison" for item in comparison.outputs
    )


@pytest.mark.parametrize(
    (
        "ordinary_net_amount",
        "ordinary_net_unit",
        "expected_amount",
        "expected_reliable",
    ),
    [
        ("30.00", "t", Decimal("30.00"), True),
        ("31.251", "t", Decimal("31.251"), False),
        ("31250", "kg", Decimal("31250"), False),
        ("invalid", "t", None, False),
        ("0.00", "t", None, False),
        (None, None, None, False),
    ],
)
def test_formal_evaluator_reuses_authoritative_ordinary_net_reliability(
    ordinary_net_amount: str | None,
    ordinary_net_unit: str | None,
    expected_amount: Decimal | None,
    expected_reliable: bool,
) -> None:
    cpu = _Gateway(
        "cpu",
        ordinary_net_amount=ordinary_net_amount,
        ordinary_net_unit=ordinary_net_unit,
    )
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="cpu",
        gateways={"cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    try:
        prediction = evaluator(
            IndependentLockedImage(
                image_sha256=_sha256(9),
                relative_path="locked/images/009.png",
            )
        )
    finally:
        backend.close()

    output = prediction.runtime_comparison.outputs[0]
    assert output.ordinary_net_amount == expected_amount
    assert output.ordinary_net_reliable is expected_reliable
    assert output.safety_route == (
        "eligible_for_downstream_comparison"
        if expected_reliable
        else "non_automatic"
    )


@pytest.mark.parametrize(
    ("cpu_options", "expected_difference"),
    [
        ({"ordinary_net_amount": "30.01"}, "ordinary_net_amount"),
        ({"ordinary_net_unit": "kg"}, "ordinary_net_unit"),
        ({"ticket_role": TicketRole.UNLOADING}, "role"),
    ],
)
def test_dual_runtime_critical_difference_is_preserved_and_fails_the_formal_gate(
    cpu_options: dict[str, object],
    expected_difference: str,
) -> None:
    gpu = _Gateway("gpu")
    cpu = _Gateway("cpu", **cpu_options)  # type: ignore[arg-type]
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gpu, "cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    image = IndependentLockedImage(
        image_sha256=_sha256(7),
        relative_path="locked/images/007.png",
    )
    try:
        prediction = evaluator(image)
    finally:
        backend.close()

    comparison = prediction.runtime_comparison
    assert evaluator.run_context.expected_runtime_kinds == ("cpu", "gpu")
    assert comparison.status == "dual_different"
    assert comparison.selected_runtime_kind == "cpu"
    assert comparison.critical_fields_match is False
    assert expected_difference in comparison.differences
    assert {item.runtime_kind for item in comparison.outputs} == {"cpu", "gpu"}
    assert comparison.failures == ()
    selected = next(
        item
        for item in comparison.outputs
        if item.runtime_kind == comparison.selected_runtime_kind
    )
    assert prediction.assessment_fingerprint == selected.assessment_fingerprint
    assert [item.image_sha256 for item in gpu.calls] == [_sha256(7)]
    assert [item.image_sha256 for item in cpu.calls] == [_sha256(7)]


def test_dual_runtime_weight_difference_requires_human_review_without_converting() -> None:
    gpu = _Gateway("gpu", ordinary_net_amount="32.7")
    cpu = _Gateway("cpu", ordinary_net_amount="3270")
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gpu, "cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    try:
        prediction = evaluator(
            IndependentLockedImage(
                image_sha256=_sha256(70),
                relative_path="locked/images/070.png",
            )
        )
    finally:
        backend.close()

    assert prediction.automatic_review_reason == "ocr_weight_disagreement"
    assert prediction.runtime_comparison.status == "dual_different"
    outputs = {
        output.runtime_kind: output
        for output in prediction.runtime_comparison.outputs
    }
    assert outputs["cpu"].ordinary_net_amount == Decimal("3270")
    assert outputs["cpu"].weight_review_reason == (
        "ticket_weight_format_suspicious"
    )
    assert outputs["cpu"].ordinary_net_reliable is False
    assert outputs["gpu"].ordinary_net_amount == Decimal("32.7")
    assert outputs["gpu"].weight_review_reason is None
    assert outputs["gpu"].ordinary_net_reliable is True


def test_gpu_failure_retries_same_independent_image_on_cpu() -> None:
    gpu = _Gateway("gpu", fail=True)
    cpu = _Gateway("cpu")
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gpu, "cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    image = IndependentLockedImage(
        image_sha256=_sha256(2),
        relative_path="locked/images/002.png",
    )
    try:
        prediction = evaluator(image)
    finally:
        backend.close()

    assert prediction.role is TicketRole.LOADING
    assert [item.image_sha256 for item in gpu.calls] == [_sha256(2)]
    assert [item.image_sha256 for item in cpu.calls] == [_sha256(2)]
    comparison = prediction.runtime_comparison
    assert comparison.status == "gpu_failed_cpu_fallback"
    assert comparison.selected_runtime_kind == "cpu"
    assert comparison.critical_fields_match is None
    assert comparison.differences == ()
    assert [item.runtime_kind for item in comparison.outputs] == ["cpu"]
    assert [item.runtime_kind for item in comparison.failures] == ["gpu"]


def test_invalid_gpu_protocol_result_retries_same_image_on_cpu() -> None:
    gpu = _Gateway("gpu", invalid_result_json=True)
    cpu = _Gateway("cpu")
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gpu, "cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    image = IndependentLockedImage(
        image_sha256=_sha256(4),
        relative_path="locked/images/004.png",
    )
    try:
        prediction = evaluator(image)
    finally:
        backend.close()

    assert prediction.role is TicketRole.LOADING
    assert [item.image_sha256 for item in gpu.calls] == [_sha256(4)]
    assert [item.image_sha256 for item in cpu.calls] == [_sha256(4)]
    assert prediction.runtime_comparison.status == "gpu_failed_cpu_fallback"
    assert prediction.runtime_comparison.critical_fields_match is None


def test_gpu_execution_boundary_failure_retries_same_image_on_cpu(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gpu = _Gateway("gpu")
    cpu = _Gateway("cpu")
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gpu, "cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    original_execute = evaluator._execute

    def fail_gpu_boundary(
        image: IndependentLockedImage,
        runtime_kind: str,
    ) -> object:
        if runtime_kind == "gpu":
            raise LockedSetRunnerError("synthetic GPU timeout")
        return original_execute(image, runtime_kind)  # type: ignore[arg-type]

    monkeypatch.setattr(evaluator, "_execute", fail_gpu_boundary)
    image = IndependentLockedImage(
        image_sha256=_sha256(5),
        relative_path="locked/images/005.png",
    )
    try:
        prediction = evaluator(image)
    finally:
        backend.close()

    assert prediction.role is TicketRole.LOADING
    assert gpu.calls == []
    assert [item.image_sha256 for item in cpu.calls] == [_sha256(5)]
    assert prediction.runtime_comparison.status == "gpu_failed_cpu_fallback"
    assert prediction.runtime_comparison.critical_fields_match is None


def test_all_runtime_failures_remain_technical_failures() -> None:
    gpu = _Gateway("gpu", fail=True)
    cpu = _Gateway("cpu", fail=True)
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gpu, "cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    try:
        with pytest.raises(LockedSetRunnerError, match="OCR runtime"):
            evaluator(
                IndependentLockedImage(
                    image_sha256=_sha256(3),
                    relative_path="locked/images/003.png",
                )
            )
    finally:
        backend.close()


def test_cpu_parity_failure_does_not_adopt_successful_gpu_output() -> None:
    gpu = _Gateway("gpu")
    cpu = _Gateway("cpu", fail=True)
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gpu, "cpu": cpu},
    )
    evaluator = LocalOcrLockedImageEvaluator(
        backend=backend,
        templates=_templates(),
        application_build_sha256=_application_build_manifest().canonical_sha256,
        application_build_manifest=_application_build_manifest(),
        timeout_seconds=2,
    )
    image = IndependentLockedImage(
        image_sha256=_sha256(8),
        relative_path="locked/images/008.png",
    )
    try:
        with pytest.raises(LockedSetRunnerError, match="OCR runtime"):
            evaluator(image)
    finally:
        backend.close()

    assert [item.image_sha256 for item in gpu.calls] == [_sha256(8)]
    assert [item.image_sha256 for item in cpu.calls] == [_sha256(8)]


def test_evaluator_requires_both_shadow_roles() -> None:
    cpu = _Gateway("cpu")
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="cpu",
        gateways={"cpu": cpu},
    )
    try:
        with pytest.raises(LockedSetRunnerError, match="loading and unloading"):
            LocalOcrLockedImageEvaluator(
                backend=backend,
                templates=(_version(TicketRole.LOADING, "loading"),),
                application_build_sha256=(
                    _application_build_manifest().canonical_sha256
                ),
                application_build_manifest=_application_build_manifest(),
                timeout_seconds=2,
            )
    finally:
        backend.close()


def test_evaluator_rejects_gpu_only_composition_without_cpu_fallback() -> None:
    gpu = _Gateway("gpu")
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gpu},
    )
    try:
        with pytest.raises(LockedSetRunnerError, match="CPU fallback"):
            LocalOcrLockedImageEvaluator(
                backend=backend,
                templates=_templates(),
                application_build_sha256=(
                    _application_build_manifest().canonical_sha256
                ),
                application_build_manifest=_application_build_manifest(),
                timeout_seconds=2,
            )
    finally:
        backend.close()
