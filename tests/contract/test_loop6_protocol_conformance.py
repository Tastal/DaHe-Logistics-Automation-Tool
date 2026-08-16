from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from dahe.adapters.ocr.protocol import (
    MAX_COMMAND_ID_CHARS,
    MAX_COMMAND_LINE_BYTES,
    MAX_PROFILE_ID_CHARS,
    MAX_RELATIVE_PATH_CHARS,
    MAX_RESULT_LINE_BYTES,
    OCR_BATCH_PROTOCOL_VERSION,
    OcrBatchCommand,
    OcrCommand,
    OcrProtocolError,
    parse_result_line,
)

IMAGE_SHA = "1" * 64
PIPELINE_SHA = "2" * 64
RUNTIME_SHA = "3" * 64


@contextmanager
def _worker_protocol(project_root: Path) -> Iterator[ModuleType]:
    worker_src = str(project_root / "ocr-runtime" / "src")
    sys.path.insert(0, worker_src)
    try:
        yield importlib.import_module("dahe_ocr_worker.protocol")
    finally:
        sys.path.remove(worker_src)
        for module_name in tuple(sys.modules):
            if module_name == "dahe_ocr_worker" or module_name.startswith("dahe_ocr_worker."):
                sys.modules.pop(module_name, None)


def _extract_payload() -> dict[str, object]:
    return {
        "protocol_version": 1,
        "command_id": "command-001",
        "operation": "extract",
        "image_sha256": IMAGE_SHA,
        "relative_path": "证据/磅单.png",
        "pipeline_fingerprint": PIPELINE_SHA,
        "runtime_fingerprint": RUNTIME_SHA,
        "profile_id": "cpu-portable",
    }


def _hello_payload() -> dict[str, object]:
    payload = _extract_payload()
    payload.update(
        {
            "operation": "hello",
            "image_sha256": None,
            "relative_path": None,
            "pipeline_fingerprint": None,
        }
    )
    return payload


def _batch_payload() -> dict[str, object]:
    return {
        "protocol_version": OCR_BATCH_PROTOCOL_VERSION,
        "command_id": "vehicle-001",
        "operation": "extract_batch",
        "images": [
            {
                "image_sha256": IMAGE_SHA,
                "relative_path": "证据/装货.png",
                "role": "loading",
            },
            {
                "image_sha256": "4" * 64,
                "relative_path": "证据/卸货.png",
                "role": "unloading",
            },
        ],
        "pipeline_fingerprint": PIPELINE_SHA,
        "runtime_fingerprint": RUNTIME_SHA,
        "profile_id": "gpu-portable",
    }


@pytest.mark.parametrize("payload_factory", [_extract_payload, _hello_payload])
def test_main_schema_and_worker_accept_the_same_valid_commands(
    project_root: Path,
    payload_factory: object,
) -> None:
    payload = payload_factory()  # type: ignore[operator]
    schema = json.loads(
        (project_root / "protocol" / "ocr" / "v1" / "command.schema.json").read_text(
            encoding="utf-8"
        )
    )

    Draft202012Validator(schema).validate(payload)
    main_command = OcrCommand.model_validate(payload)
    with _worker_protocol(project_root) as worker_protocol:
        worker_command = worker_protocol.parse_command(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        )

    assert worker_command.command_id == main_command.command_id
    assert worker_command.operation == main_command.operation.value
    assert worker_command.relative_path == main_command.relative_path


def test_main_schema_and_worker_accept_the_same_vehicle_batch(
    project_root: Path,
) -> None:
    payload = _batch_payload()
    schema = json.loads(
        (project_root / "protocol" / "ocr" / "v2" / "command.schema.json").read_text(
            encoding="utf-8"
        )
    )

    Draft202012Validator(schema).validate(payload)
    main_command = OcrBatchCommand.model_validate(payload)
    with _worker_protocol(project_root) as worker_protocol:
        worker_command = worker_protocol.parse_command(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        )

    assert worker_command.protocol_version == main_command.protocol_version == 2
    assert [image.role for image in worker_command.images] == [
        image.role for image in main_command.images
    ]
    assert [image.image_sha256 for image in worker_command.images] == [
        image.image_sha256 for image in main_command.images
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("unexpected", True),
        ("protocol_version", 2),
        ("operation", "settle"),
        ("relative_path", "../ticket.png"),
        ("image_sha256", None),
        ("command_id", "x" * (MAX_COMMAND_ID_CHARS + 1)),
        ("profile_id", "x" * (MAX_PROFILE_ID_CHARS + 1)),
        ("relative_path", "x" * (MAX_RELATIVE_PATH_CHARS + 1)),
    ],
)
def test_main_schema_and_worker_reject_the_same_invalid_commands(
    project_root: Path,
    field: str,
    value: object,
) -> None:
    payload = _extract_payload()
    payload[field] = value
    schema = json.loads(
        (project_root / "protocol" / "ocr" / "v1" / "command.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert list(Draft202012Validator(schema).iter_errors(payload))
    with pytest.raises(ValidationError):
        OcrCommand.model_validate(payload)
    with (
        _worker_protocol(project_root) as worker_protocol,
        pytest.raises(worker_protocol.WorkerProtocolViolation),
    ):
        worker_protocol.parse_command(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        )


def test_three_protocol_surfaces_share_limits_and_fields(project_root: Path) -> None:
    schema = json.loads(
        (project_root / "protocol" / "ocr" / "v1" / "command.schema.json").read_text(
            encoding="utf-8"
        )
    )
    main_fields = set(OcrCommand.model_fields)

    with _worker_protocol(project_root) as worker_protocol:
        assert main_fields == worker_protocol.COMMAND_FIELDS
        assert worker_protocol.MAX_COMMAND_LINE_BYTES == MAX_COMMAND_LINE_BYTES
        assert worker_protocol.MAX_COMMAND_ID_CHARS == MAX_COMMAND_ID_CHARS
        assert worker_protocol.MAX_PROFILE_ID_CHARS == MAX_PROFILE_ID_CHARS
        assert worker_protocol.MAX_RELATIVE_PATH_CHARS == MAX_RELATIVE_PATH_CHARS

    assert set(schema["properties"]) == main_fields
    assert schema["properties"]["command_id"]["maxLength"] == MAX_COMMAND_ID_CHARS
    assert schema["properties"]["profile_id"]["maxLength"] == MAX_PROFILE_ID_CHARS
    assert schema["properties"]["relative_path"]["maxLength"] == MAX_RELATIVE_PATH_CHARS


def test_worker_wire_decoder_rejects_invalid_utf8_or_unterminated_commands(
    project_root: Path,
) -> None:
    with _worker_protocol(project_root) as worker_protocol:
        with pytest.raises(worker_protocol.WorkerProtocolViolation):
            worker_protocol.decode_command_bytes(b"\xff\n")
        with pytest.raises(worker_protocol.WorkerProtocolViolation):
            worker_protocol.decode_command_bytes(b"{}")
        with pytest.raises(worker_protocol.WorkerProtocolViolation):
            worker_protocol.decode_command_bytes(
                b"x" * (worker_protocol.MAX_COMMAND_LINE_BYTES + 2)
            )


def test_main_result_schema_and_worker_serializer_share_one_bounded_contract(
    project_root: Path,
) -> None:
    payload = {
        "protocol_version": 1,
        "command_id": "command-001",
        "status": "ok",
        "worker_identity": "worker-001",
        "runtime_fingerprint": RUNTIME_SHA,
        "verified_image_sha256": IMAGE_SHA,
        "elapsed_ms": 12.5,
        "text_lines": [
            {
                "text": "NET 12.34 T",
                "confidence": 0.98,
                "box": {"x": 0.1, "y": 0.2, "width": 0.5, "height": 0.1},
            }
        ],
        "fields": {
            "ordinary_net": {
                "raw_text": "NET 12.34 T",
                "amount": "12.34",
                "unit": "t",
                "confidence": 0.98,
            }
        },
        "role_observation": {
            "fixed_text": ["NET"],
            "layout_fingerprint": "4" * 64,
            "orientation_degrees": 0,
        },
        "error": None,
    }
    schema = json.loads(
        (project_root / "protocol" / "ocr" / "v1" / "result.schema.json").read_text(
            encoding="utf-8"
        )
    )

    Draft202012Validator(schema).validate(payload)
    with _worker_protocol(project_root) as worker_protocol:
        line = worker_protocol.result_line(payload)
        assert worker_protocol.MAX_RESULT_LINE_BYTES == MAX_RESULT_LINE_BYTES
    result = parse_result_line(line)
    assert result.fields["ordinary_net"].amount == "12.34"

    payload["status"] = "error"
    assert list(Draft202012Validator(schema).iter_errors(payload))
    with pytest.raises(OcrProtocolError):
        parse_result_line(json.dumps(payload))
