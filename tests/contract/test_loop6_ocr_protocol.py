from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from dahe.adapters.ocr.protocol import (
    MAX_COMMAND_ID_CHARS,
    MAX_COMMAND_LINE_BYTES,
    MAX_PROFILE_ID_CHARS,
    MAX_RELATIVE_PATH_CHARS,
    MAX_RESULT_LINE_BYTES,
    OCR_BATCH_PROTOCOL_VERSION,
    OCR_PROTOCOL_VERSION,
    OcrBatchCommand,
    OcrBatchImage,
    OcrBatchResult,
    OcrCommand,
    OcrOperation,
    OcrProtocolError,
    OcrResult,
    parse_result_line,
)

IMAGE_SHA = "1" * 64
PIPELINE_SHA = "2" * 64
RUNTIME_SHA = "3" * 64


def _valid_command() -> dict[str, object]:
    return {
        "protocol_version": OCR_PROTOCOL_VERSION,
        "command_id": "command-001",
        "operation": "extract",
        "image_sha256": IMAGE_SHA,
        "relative_path": "evidence/sha256/11/11/image.png",
        "pipeline_fingerprint": PIPELINE_SHA,
        "runtime_fingerprint": RUNTIME_SHA,
        "profile_id": "gpu-safe-local",
    }


def test_extract_command_contains_only_independent_image_evidence() -> None:
    command = OcrCommand.model_validate(_valid_command())

    assert command.operation is OcrOperation.EXTRACT
    assert command.image_sha256 == IMAGE_SHA
    assert set(command.model_dump(mode="json")) == {
        "protocol_version",
        "command_id",
        "operation",
        "image_sha256",
        "relative_path",
        "pipeline_fingerprint",
        "runtime_fingerprint",
        "profile_id",
    }


def test_extract_batch_binds_one_vehicle_images_to_ordered_roles() -> None:
    command = OcrBatchCommand(
        protocol_version=OCR_BATCH_PROTOCOL_VERSION,
        command_id="vehicle-001",
        operation="extract_batch",
        images=(
            OcrBatchImage(
                image_sha256=IMAGE_SHA,
                relative_path="evidence/loading.png",
                role="loading",
            ),
            OcrBatchImage(
                image_sha256="4" * 64,
                relative_path="evidence/unloading.png",
                role="unloading",
            ),
        ),
        pipeline_fingerprint=PIPELINE_SHA,
        runtime_fingerprint=RUNTIME_SHA,
        profile_id="gpu-safe-local",
    )

    assert command.protocol_version == 2
    assert [image.role for image in command.images] == ["loading", "unloading"]
    assert set(command.model_dump(mode="json")) == {
        "protocol_version",
        "command_id",
        "operation",
        "images",
        "pipeline_fingerprint",
        "runtime_fingerprint",
        "profile_id",
    }


@pytest.mark.parametrize(
    "images",
    [
        (),
        tuple(
            OcrBatchImage(
                image_sha256=str(index) * 64,
                relative_path=f"evidence/{index}.png",
                role="loading" if index % 2 else "unloading",
            )
            for index in (1, 2, 3)
        ),
        (
            OcrBatchImage(
                image_sha256=IMAGE_SHA,
                relative_path="evidence/first.png",
                role="loading",
            ),
            OcrBatchImage(
                image_sha256="4" * 64,
                relative_path="evidence/second.png",
                role="loading",
            ),
        ),
    ],
)
def test_extract_batch_rejects_empty_oversized_or_duplicate_roles(
    images: tuple[OcrBatchImage, ...],
) -> None:
    with pytest.raises(ValidationError):
        OcrBatchCommand(
            protocol_version=OCR_BATCH_PROTOCOL_VERSION,
            command_id="vehicle-invalid",
            operation="extract_batch",
            images=images,
            pipeline_fingerprint=PIPELINE_SHA,
            runtime_fingerprint=RUNTIME_SHA,
            profile_id="gpu-safe-local",
        )


def test_extract_batch_result_preserves_input_order_and_identity() -> None:
    payload = {
        "protocol_version": OCR_BATCH_PROTOCOL_VERSION,
        "command_id": "vehicle-001",
        "status": "ok",
        "worker_identity": "worker-001",
        "runtime_fingerprint": RUNTIME_SHA,
        "elapsed_ms": 20,
        "items": [
            {
                "role": "loading",
                "verified_image_sha256": IMAGE_SHA,
                "elapsed_ms": 9,
                "text_lines": [],
                "fields": {},
                "role_observation": None,
            },
            {
                "role": "unloading",
                "verified_image_sha256": "4" * 64,
                "elapsed_ms": 11,
                "text_lines": [],
                "fields": {},
                "role_observation": None,
            },
        ],
        "error": None,
    }

    result = parse_result_line(json.dumps(payload))

    assert isinstance(result, OcrBatchResult)
    assert [item.role for item in result.items] == ["loading", "unloading"]


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "expected_weight",
        "platform_weight",
        "platform_loading_net",
        "platform_unloading_net",
        "upload_slot",
        "candidate_weight",
    ],
)
def test_protocol_rejects_platform_or_expected_value_fields(
    forbidden_key: str,
) -> None:
    payload = _valid_command()
    payload[forbidden_key] = "12.34"

    with pytest.raises(ValidationError):
        OcrCommand.model_validate(payload)


@pytest.mark.parametrize(
    "relative_path",
    [
        r"C:\Users\operator\ticket.png",
        "/evidence/ticket.png",
        "../ticket.png",
        "evidence/../../ticket.png",
        r"evidence\..\ticket.png",
        "//server/share/ticket.png",
    ],
)
def test_protocol_rejects_absolute_or_escaping_image_paths(
    relative_path: str,
) -> None:
    payload = _valid_command()
    payload["relative_path"] = relative_path

    with pytest.raises(ValidationError):
        OcrCommand.model_validate(payload)


def test_result_parser_rejects_malformed_or_oversized_ndjson() -> None:
    with pytest.raises(OcrProtocolError):
        parse_result_line("{not-json")

    with pytest.raises(OcrProtocolError):
        parse_result_line(" " * (MAX_RESULT_LINE_BYTES + 1))


def test_command_serialization_rejects_non_utf8_or_oversized_values() -> None:
    payload = _valid_command()
    payload["command_id"] = "\ud800"
    with pytest.raises((ValidationError, OcrProtocolError)):
        OcrCommand.model_validate(payload).to_ndjson()

    for field, limit in (
        ("command_id", MAX_COMMAND_ID_CHARS),
        ("profile_id", MAX_PROFILE_ID_CHARS),
        ("relative_path", MAX_RELATIVE_PATH_CHARS),
    ):
        payload = _valid_command()
        payload[field] = "x" * (limit + 1)
        with pytest.raises(ValidationError):
            OcrCommand.model_validate(payload)

    command = OcrCommand.model_validate(_valid_command())
    assert len(command.to_ndjson().encode("utf-8")) <= MAX_COMMAND_LINE_BYTES


def test_result_parser_requires_correlation_and_exact_schema() -> None:
    payload = {
        "protocol_version": OCR_PROTOCOL_VERSION,
        "command_id": "command-001",
        "status": "ok",
        "worker_identity": "worker-001",
        "runtime_fingerprint": RUNTIME_SHA,
        "verified_image_sha256": IMAGE_SHA,
        "elapsed_ms": 12.5,
        "text_lines": [
            {
                "text": "NET WEIGHT 12.34 t",
                "confidence": "0.98",
                "box": {"x": "0.1", "y": "0.2", "width": "0.5", "height": "0.1"},
            }
        ],
        "fields": {
            "ordinary_net": {
                "raw_text": "12.34 t",
                "amount": "12.34",
                "unit": "t",
                "confidence": "0.98",
            }
        },
        "role_observation": {
            "fixed_text": ["NET WEIGHT"],
            "layout_fingerprint": "layout-v1",
            "orientation_degrees": 0,
        },
        "error": None,
    }

    result = parse_result_line(json.dumps(payload))

    assert isinstance(result, OcrResult)
    assert result.command_id == "command-001"
    assert result.verified_image_sha256 == IMAGE_SHA
    assert result.fields["ordinary_net"].amount == "12.34"

    payload["unexpected"] = True
    with pytest.raises(OcrProtocolError):
        parse_result_line(json.dumps(payload))


def test_worker_protocol_schema_and_source_do_not_define_forbidden_inputs(
    project_root: Path,
) -> None:
    surfaces = [
        *(project_root / "src" / "dahe" / "adapters" / "ocr").rglob("*.py"),
        *(project_root / "ocr-runtime" / "src" / "dahe_ocr_worker").rglob("*.py"),
        *(project_root / "protocol" / "ocr").rglob("*.json"),
    ]
    text = "\n".join(path.read_text(encoding="utf-8").lower() for path in surfaces)
    forbidden = (
        "expected_weight",
        "platform_weight",
        "platform_loading_net",
        "platform_unloading_net",
        "candidate_weight",
        "upload_slot",
        "web_weight",
        "page_weight",
    )
    for term in forbidden:
        assert term not in text
