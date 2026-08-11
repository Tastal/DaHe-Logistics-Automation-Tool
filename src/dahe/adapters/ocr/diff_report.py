from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from dahe.adapters.ocr.coordinator import OcrImageOutput


@dataclass(frozen=True, slots=True)
class RuntimeDifferenceItem:
    image_sha256: str
    critical_fields_match: bool
    differences: tuple[str, ...]
    cpu_elapsed_ms: float
    gpu_elapsed_ms: float


@dataclass(frozen=True, slots=True)
class RuntimeDifferenceReport:
    sample_count: int
    critical_match_count: int
    all_critical_fields_match: bool
    items: tuple[RuntimeDifferenceItem, ...]


def _critical_payload(output: OcrImageOutput) -> dict[str, Decimal | str | bool | None]:
    return {
        "ordinary_net_amount": output.ordinary_net_amount,
        "ordinary_net_unit": output.ordinary_net_unit,
        "gross_amount": output.gross_amount,
        "tare_amount": output.tare_amount,
        "role": output.role.value,
        "role_reliable": output.role_reliable,
        "field_reliable": output.field_reliable,
    }


def compare_runtime_outputs(
    *,
    cpu: tuple[OcrImageOutput, ...],
    gpu: tuple[OcrImageOutput, ...],
) -> RuntimeDifferenceReport:
    cpu_by_hash = {item.image_sha256: item for item in cpu}
    gpu_by_hash = {item.image_sha256: item for item in gpu}
    if len(cpu_by_hash) != len(cpu) or len(gpu_by_hash) != len(gpu):
        raise ValueError("runtime comparison inputs contain duplicate images")
    if set(cpu_by_hash) != set(gpu_by_hash):
        raise ValueError("CPU and GPU runtime comparison image sets differ")

    items: list[RuntimeDifferenceItem] = []
    for image_sha256 in sorted(cpu_by_hash):
        cpu_item = cpu_by_hash[image_sha256]
        gpu_item = gpu_by_hash[image_sha256]
        cpu_payload = _critical_payload(cpu_item)
        gpu_payload = _critical_payload(gpu_item)
        differences = tuple(
            field
            for field in cpu_payload
            if cpu_payload[field] != gpu_payload[field]
        )
        items.append(
            RuntimeDifferenceItem(
                image_sha256=image_sha256,
                critical_fields_match=not differences,
                differences=differences,
                cpu_elapsed_ms=cpu_item.elapsed_ms,
                gpu_elapsed_ms=gpu_item.elapsed_ms,
            )
        )
    match_count = sum(item.critical_fields_match for item in items)
    return RuntimeDifferenceReport(
        sample_count=len(items),
        critical_match_count=match_count,
        all_critical_fields_match=match_count == len(items),
        items=tuple(items),
    )

