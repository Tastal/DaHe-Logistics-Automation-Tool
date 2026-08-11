from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from dahe.adapters.ocr.coordinator import OcrImageOutput
from dahe.adapters.ocr.diff_report import compare_runtime_outputs
from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.jobs.ocr_errors import OcrErrorKind

LOADING_HASH = "a" * 64
UNLOADING_HASH = "b" * 64


def _output(
    image_sha256: str,
    runtime_kind: RuntimeKind,
    *,
    net: str,
    role: TicketRole,
) -> OcrImageOutput:
    return OcrImageOutput(
        image_sha256=image_sha256,
        runtime_kind=runtime_kind,
        runtime_fingerprint=f"{runtime_kind.value}-runtime",
        output_fingerprint=f"{runtime_kind.value}-{image_sha256}",
        ordinary_net_amount=Decimal(net),
        ordinary_net_unit="t",
        gross_amount=None,
        tare_amount=None,
        role=role,
        role_reliable=True,
        field_reliable=True,
        elapsed_ms=25,
    )


@pytest.mark.parametrize(
    "error_kind",
    [
        OcrErrorKind.NO_GPU,
        OcrErrorKind.DRIVER_INCOMPATIBLE,
        OcrErrorKind.INSUFFICIENT_MEMORY,
        OcrErrorKind.OUT_OF_MEMORY,
        OcrErrorKind.WORKER_CRASHED,
        OcrErrorKind.WORKER_TIMEOUT,
        OcrErrorKind.SMOKE_FAILED,
    ],
)
def test_authoritative_error_contract_allows_expected_gpu_fallbacks(
    error_kind: OcrErrorKind,
) -> None:
    assert error_kind.gpu_fallback_allowed is True


@pytest.mark.parametrize(
    "error_kind",
    [
        OcrErrorKind.EVIDENCE_MISMATCH,
        OcrErrorKind.MODEL_MANIFEST_INVALID,
        OcrErrorKind.PROTOCOL_ERROR,
        OcrErrorKind.RUNTIME_MISSING,
    ],
)
def test_authoritative_error_contract_rejects_unsafe_gpu_fallbacks(
    error_kind: OcrErrorKind,
) -> None:
    assert error_kind.gpu_fallback_allowed is False


def test_runtime_difference_report_is_per_image_and_critical_field_aware() -> None:
    cpu = (
        _output(
            LOADING_HASH,
            RuntimeKind.CPU,
            net="12.34",
            role=TicketRole.LOADING,
        ),
        _output(
            UNLOADING_HASH,
            RuntimeKind.CPU,
            net="12.32",
            role=TicketRole.UNLOADING,
        ),
    )
    gpu = (
        replace(
            cpu[0],
            runtime_kind=RuntimeKind.GPU,
            runtime_fingerprint="gpu-runtime",
            output_fingerprint="gpu-loading",
        ),
        replace(
            cpu[1],
            runtime_kind=RuntimeKind.GPU,
            runtime_fingerprint="gpu-runtime",
            output_fingerprint="gpu-unloading",
            ordinary_net_amount=Decimal("12.31"),
        ),
    )

    report = compare_runtime_outputs(cpu=cpu, gpu=gpu)

    assert report.sample_count == 2
    assert report.critical_match_count == 1
    assert report.all_critical_fields_match is False
    by_hash = {item.image_sha256: item for item in report.items}
    assert by_hash[LOADING_HASH].critical_fields_match is True
    assert by_hash[UNLOADING_HASH].differences == ("ordinary_net_amount",)
