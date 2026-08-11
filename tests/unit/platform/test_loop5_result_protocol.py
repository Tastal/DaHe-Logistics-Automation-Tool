from __future__ import annotations

import json
from dataclasses import replace

import pytest

from dahe.adapters.chengfeng.protocol import (
    ConnectorCommand,
    ConnectorDiagnosticClassification,
    ConnectorPayloadKind,
    ConnectorPayloadReference,
    ConnectorResult,
    ConnectorResultOutcome,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    ChengfengOperation,
    ChengfengStage,
)

_SHA256 = "0" * 64


def _reference(
    *,
    kind: ConnectorPayloadKind = ConnectorPayloadKind.WAYBILL_PAGE,
    relative_path: str = "connector-results/00/page.json",
    media_type: str = "application/json",
    byte_size: int = 123,
) -> ConnectorPayloadReference:
    return ConnectorPayloadReference(
        kind=kind,
        relative_path=relative_path,
        sha256=_SHA256,
        media_type=media_type,
        byte_size=byte_size,
    )


def _success() -> ConnectorResult:
    return ConnectorResult(
        protocol_version=1,
        command_id="synthetic-command-001",
        operation=ChengfengOperation.LIST_WAYBILLS,
        outcome=ConnectorResultOutcome.SUCCEEDED,
        stage=ChengfengStage.LIST_QUERY,
        diagnostic_classification=ConnectorDiagnosticClassification.NONE,
        payload_references=(_reference(),),
    )


def _command() -> ConnectorCommand:
    return ConnectorCommand(
        protocol_version=1,
        command_id="synthetic-command-001",
        operation=ChengfengOperation.LIST_WAYBILLS,
        authority=BrowserCommandAuthority(
            session_id="synthetic-session",
            instance_id="synthetic-instance",
            worker_id="synthetic-worker",
            job_id="synthetic-job",
            control_epoch=1,
            fencing_token="process-local-fencing-token",
        ),
        parameters={
            "scope": "loop5-synthetic-scope",
            "page_number": 1,
            "page_size": 50,
        },
        credential_reference="windows-credential:chengfeng-test",
    )


def _payload(**updates: object) -> dict[str, object]:
    payload = json.loads(_success().to_ndjson())
    payload.update(updates)
    return payload


def _ndjson(payload: object) -> str:
    return json.dumps(payload, separators=(",", ":")) + "\n"


def test_command_round_trips_as_one_strict_utf8_ndjson_record() -> None:
    command = _command()

    serialized = command.to_ndjson()

    assert serialized.count("\n") == 1
    assert ConnectorCommand.from_ndjson(serialized) == command
    assert ConnectorCommand.from_ndjson(serialized.encode("utf-8")) == command


@pytest.mark.parametrize("prefix", ["_", "-"])
def test_command_accepts_urlsafe_fencing_token_prefixes(prefix: str) -> None:
    command = replace(
        _command(),
        authority=replace(
            _command().authority,
            fencing_token=prefix + "a" * 42,
        ),
    )

    assert ConnectorCommand.from_ndjson(command.to_ndjson()) == command


@pytest.mark.parametrize(
    ("operation", "parameters"),
    [
        (
            ChengfengOperation.GET_WAYBILL_DETAIL,
            {"platform_waybill_id": "waybill-001"},
        ),
        (
            ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
            {"ticket_ref": "ticket-001"},
        ),
    ],
)
def test_command_parser_accepts_each_declared_read_operation(
    operation: ChengfengOperation,
    parameters: dict[str, object],
) -> None:
    payload = json.loads(_command().to_ndjson())
    payload["operation"] = operation.value
    payload["parameters"] = parameters

    parsed = ConnectorCommand.from_ndjson(_ndjson(payload))

    assert parsed.operation is operation
    assert parsed.parameters == parameters


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol_version", 2),
        ("protocol_version", True),
        ("command_id", 123),
        ("operation", "settlement_confirm"),
        ("operation", "receipt_cancel"),
        ("operation", "pay"),
        ("authority", []),
        ("parameters", []),
        ("credential_reference", 123),
    ],
)
def test_command_parser_rejects_wrong_types_versions_and_write_operations(
    field: str,
    value: object,
) -> None:
    payload = json.loads(_command().to_ndjson())
    payload[field] = value

    with pytest.raises((TypeError, ValueError)):
        ConnectorCommand.from_ndjson(_ndjson(payload))


@pytest.mark.parametrize(
    "extra",
    [
        {"unexpected": True},
        {"cookie": "session-secret"},
        {"raw_response": "<html>sensitive</html>"},
    ],
)
def test_command_parser_rejects_extra_top_level_fields(extra: dict[str, object]) -> None:
    payload = json.loads(_command().to_ndjson())
    payload.update(extra)

    with pytest.raises(ValueError, match="fields must match schema"):
        ConnectorCommand.from_ndjson(_ndjson(payload))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("session_id", 1),
        ("instance_id", None),
        ("worker_id", []),
        ("job_id", True),
        ("control_epoch", "1"),
        ("control_epoch", False),
        ("fencing_token", {}),
    ],
)
def test_command_parser_rejects_wrong_authority_field_types(
    field: str,
    value: object,
) -> None:
    payload = json.loads(_command().to_ndjson())
    authority = payload["authority"]
    assert isinstance(authority, dict)
    authority[field] = value

    with pytest.raises((TypeError, ValueError)):
        ConnectorCommand.from_ndjson(_ndjson(payload))


def test_command_parser_rejects_missing_or_extra_authority_fields() -> None:
    missing = json.loads(_command().to_ndjson())
    missing_authority = missing["authority"]
    assert isinstance(missing_authority, dict)
    del missing_authority["job_id"]

    extra = json.loads(_command().to_ndjson())
    extra_authority = extra["authority"]
    assert isinstance(extra_authority, dict)
    extra_authority["cookie"] = "session-secret"

    for payload in (missing, extra):
        with pytest.raises(ValueError, match="fields must match schema"):
            ConnectorCommand.from_ndjson(_ndjson(payload))


@pytest.mark.parametrize(
    "parameters",
    [
        {"token": "raw-secret"},
        {"cook_ie": "session-secret"},
        {"credentials": "username:password"},
        {"nested": {"session_id": "raw-session"}},
        {"url": "https://files.example/image.png?signature=raw-secret"},
        {"note": "Authorization: Bearer raw-secret"},
        {"phone": "13800138000"},
    ],
)
def test_command_parser_rejects_sensitive_parameters(
    parameters: dict[str, object],
) -> None:
    payload = json.loads(_command().to_ndjson())
    payload["parameters"] = parameters

    with pytest.raises(ValueError, match=r"(?i)(sensitive|credentials|personal)"):
        ConnectorCommand.from_ndjson(_ndjson(payload))


@pytest.mark.parametrize(
    "malformed",
    [
        _command().to_ndjson() + _command().to_ndjson(),
        _command().to_ndjson().rstrip("\n"),
        _command().to_ndjson().replace("\n", "\r\n"),
        _command().to_ndjson()[:-1] + "\n{}\n",
    ],
)
def test_command_parser_rejects_newline_and_multi_record_injection(
    malformed: str,
) -> None:
    with pytest.raises(ValueError, match="one LF-terminated"):
        ConnectorCommand.from_ndjson(malformed)


def test_command_parser_rejects_invalid_utf8() -> None:
    with pytest.raises(ValueError, match="valid UTF-8"):
        ConnectorCommand.from_ndjson(b'{"protocol_version":1}\xff\n')


@pytest.mark.parametrize(
    "malformed",
    [
        '{"protocol_version":1,"protocol_version":1}\n',
        (
            '{"protocol_version":1,"command_id":"synthetic-command-001",'
            '"operation":"list_waybills","authority":{"session_id":"one",'
            '"session_id":"two"},"parameters":{},"credential_reference":null}\n'
        ),
    ],
)
def test_command_parser_rejects_duplicate_json_fields(malformed: str) -> None:
    with pytest.raises(ValueError, match="duplicate JSON field"):
        ConnectorCommand.from_ndjson(malformed)


@pytest.mark.parametrize(
    ("operation", "parameters"),
    [
        (ChengfengOperation.LIST_WAYBILLS, {"scope": "synthetic"}),
        (
            ChengfengOperation.LIST_WAYBILLS,
            {
                "scope": "synthetic",
                "page_number": "1",
                "page_size": 50,
            },
        ),
        (
            ChengfengOperation.LIST_WAYBILLS,
            {
                "scope": "synthetic",
                "page_number": 1,
                "page_size": 0,
            },
        ),
        (
            ChengfengOperation.GET_WAYBILL_DETAIL,
            {"platform_waybill_id": "waybill-001", "extra": True},
        ),
        (ChengfengOperation.DOWNLOAD_TICKET_IMAGE, {"ticket_ref": 123}),
    ],
)
def test_command_parser_enforces_exact_parameters_for_each_read_operation(
    operation: ChengfengOperation,
    parameters: dict[str, object],
) -> None:
    payload = json.loads(_command().to_ndjson())
    payload["operation"] = operation.value
    payload["parameters"] = parameters

    with pytest.raises((TypeError, ValueError)):
        ConnectorCommand.from_ndjson(_ndjson(payload))


def test_success_result_round_trips_as_one_strict_ndjson_record() -> None:
    result = _success()

    serialized = result.to_ndjson()

    assert serialized.endswith("\n")
    assert serialized.count("\n") == 1
    assert ConnectorResult.from_ndjson(serialized) == result
    assert ConnectorResult.from_ndjson(serialized.encode()) == result


def test_result_correlation_accepts_its_originating_command() -> None:
    _success().validate_for(_command())


def test_result_correlation_rejects_protocol_command_and_operation_mismatches() -> None:
    command = _command()

    wrong_version = _success()
    object.__setattr__(wrong_version, "protocol_version", 2)
    with pytest.raises(ValueError, match="protocol_version"):
        wrong_version.validate_for(command)

    with pytest.raises(ValueError, match="command_id"):
        replace(_success(), command_id="different-command").validate_for(command)

    wrong_operation = ConnectorResult(
        protocol_version=1,
        command_id=command.command_id,
        operation=ChengfengOperation.GET_WAYBILL_DETAIL,
        outcome=ConnectorResultOutcome.SUCCEEDED,
        stage=ChengfengStage.DETAIL_QUERY,
        diagnostic_classification=ConnectorDiagnosticClassification.NONE,
        payload_references=(_reference(kind=ConnectorPayloadKind.WAYBILL_DETAIL),),
    )
    with pytest.raises(ValueError, match="operation"):
        wrong_operation.validate_for(command)


def test_failed_result_round_trips_without_a_payload_or_raw_error() -> None:
    result = ConnectorResult(
        protocol_version=1,
        command_id="synthetic-command-002",
        operation=ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
        outcome=ConnectorResultOutcome.FAILED,
        stage=ChengfengStage.IMAGE_DOWNLOAD,
        diagnostic_classification=ConnectorDiagnosticClassification.IMAGE_TIMEOUT,
        payload_references=(),
    )

    serialized = result.to_ndjson()

    assert ConnectorResult.from_ndjson(serialized) == result
    assert "exception" not in serialized
    assert "response_body" not in serialized
    assert "message" not in serialized


def test_image_timeout_cannot_be_attached_to_a_non_image_operation() -> None:
    with pytest.raises(ValueError, match="image_timeout"):
        ConnectorResult(
            protocol_version=1,
            command_id="synthetic-command-invalid-diagnostic",
            operation=ChengfengOperation.LIST_WAYBILLS,
            outcome=ConnectorResultOutcome.FAILED,
            stage=ChengfengStage.LIST_QUERY,
            diagnostic_classification=ConnectorDiagnosticClassification.IMAGE_TIMEOUT,
            payload_references=(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol_version", 2),
        ("protocol_version", True),
        ("operation", "settlement_confirm"),
        ("operation", "receipt_cancel"),
        ("operation", "pay"),
        ("outcome", "partial"),
        ("stage", "settlement"),
        ("diagnostic_classification", "raw_exception"),
    ],
)
def test_parser_rejects_unknown_versions_write_operations_and_enum_values(
    field: str,
    value: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        ConnectorResult.from_ndjson(_ndjson(_payload(**{field: value})))


@pytest.mark.parametrize(
    "payload",
    [
        {"unexpected": True},
        {"cookie": "session-secret"},
        {"authorization": "Bearer secret"},
        {"raw_image_bytes": "iVBORw0KGgo="},
    ],
)
def test_parser_rejects_every_extra_top_level_field(payload: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="fields must match schema"):
        ConnectorResult.from_ndjson(_ndjson(_payload(**payload)))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol_version", "1"),
        ("command_id", 1),
        ("operation", 1),
        ("outcome", True),
        ("stage", None),
        ("diagnostic_classification", []),
        ("payload_references", {}),
    ],
)
def test_parser_rejects_wrong_top_level_types(field: str, value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        ConnectorResult.from_ndjson(_ndjson(_payload(**{field: value})))


@pytest.mark.parametrize(
    "relative_path",
    [
        "../outside.png",
        "/absolute/image.png",
        r"C:\images\ticket.png",
        "https://files.example/ticket.png?token=secret",
        "images/ticket.png?signature=secret",
        "images//ticket.png",
        "images/./ticket.png",
    ],
)
def test_payload_reference_rejects_escape_paths_urls_and_signed_urls(
    relative_path: str,
) -> None:
    with pytest.raises(ValueError, match="relative_path"):
        _reference(relative_path=relative_path)


@pytest.mark.parametrize(
    ("kind", "media_type"),
    [
        (ConnectorPayloadKind.WAYBILL_PAGE, "image/png"),
        (ConnectorPayloadKind.WAYBILL_DETAIL, "image/jpeg"),
        (ConnectorPayloadKind.TICKET_IMAGE, "application/json"),
    ],
)
def test_payload_reference_rejects_media_type_that_does_not_match_kind(
    kind: ConnectorPayloadKind,
    media_type: str,
) -> None:
    with pytest.raises(ValueError, match="does not match payload kind"):
        _reference(kind=kind, media_type=media_type)


@pytest.mark.parametrize(
    ("kind", "media_type", "maximum"),
    [
        (ConnectorPayloadKind.WAYBILL_PAGE, "application/json", 8 * 1024 * 1024),
        (ConnectorPayloadKind.WAYBILL_DETAIL, "application/json", 8 * 1024 * 1024),
        (ConnectorPayloadKind.TICKET_IMAGE, "image/png", 32 * 1024 * 1024),
    ],
)
def test_payload_reference_accepts_v1_size_boundary(
    kind: ConnectorPayloadKind,
    media_type: str,
    maximum: int,
) -> None:
    reference = _reference(
        kind=kind,
        media_type=media_type,
        byte_size=maximum,
    )

    assert reference.byte_size == maximum


@pytest.mark.parametrize(
    ("kind", "media_type", "maximum"),
    [
        (ConnectorPayloadKind.WAYBILL_PAGE, "application/json", 8 * 1024 * 1024),
        (ConnectorPayloadKind.WAYBILL_DETAIL, "application/json", 8 * 1024 * 1024),
        (ConnectorPayloadKind.TICKET_IMAGE, "image/jpeg", 32 * 1024 * 1024),
    ],
)
def test_payload_reference_rejects_size_above_v1_limit(
    kind: ConnectorPayloadKind,
    media_type: str,
    maximum: int,
) -> None:
    with pytest.raises(ValueError, match="exceeds the v1 limit"):
        _reference(
            kind=kind,
            media_type=media_type,
            byte_size=maximum + 1,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"raw_bytes": "iVBORw0KGgo="},
        {"token": "secret"},
        {"url": "https://files.example/image.png"},
    ],
)
def test_parser_rejects_extra_payload_fields(mutation: dict[str, object]) -> None:
    payload = _payload()
    references = payload["payload_references"]
    assert isinstance(references, list)
    assert isinstance(references[0], dict)
    references[0].update(mutation)

    with pytest.raises(ValueError, match="fields must match schema"):
        ConnectorResult.from_ndjson(_ndjson(payload))


@pytest.mark.parametrize(
    "malformed",
    [
        _success().to_ndjson() + _success().to_ndjson(),
        _success().to_ndjson().rstrip("\n"),
        _success().to_ndjson().replace("\n", "\r\n"),
        _success().to_ndjson()[:-1] + "\n{}\n",
    ],
)
def test_parser_rejects_newline_and_multi_record_injection(malformed: str) -> None:
    with pytest.raises(ValueError, match="one LF-terminated"):
        ConnectorResult.from_ndjson(malformed)


def test_result_invariants_prevent_mislabeled_payload_or_error() -> None:
    with pytest.raises(ValueError, match="payload kind"):
        ConnectorResult(
            protocol_version=1,
            command_id="synthetic-command-003",
            operation=ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
            outcome=ConnectorResultOutcome.SUCCEEDED,
            stage=ChengfengStage.IMAGE_DOWNLOAD,
            diagnostic_classification=ConnectorDiagnosticClassification.NONE,
            payload_references=(_reference(),),
        )

    with pytest.raises(ValueError, match="failure diagnostic"):
        ConnectorResult(
            protocol_version=1,
            command_id="synthetic-command-004",
            operation=ChengfengOperation.LIST_WAYBILLS,
            outcome=ConnectorResultOutcome.SUCCEEDED,
            stage=ChengfengStage.LIST_QUERY,
            diagnostic_classification=ConnectorDiagnosticClassification.TRANSIENT_NETWORK,
            payload_references=(_reference(),),
        )

    with pytest.raises(ValueError, match="cannot publish payload"):
        ConnectorResult(
            protocol_version=1,
            command_id="synthetic-command-005",
            operation=ChengfengOperation.LIST_WAYBILLS,
            outcome=ConnectorResultOutcome.FAILED,
            stage=ChengfengStage.LIST_QUERY,
            diagnostic_classification=ConnectorDiagnosticClassification.TRANSIENT_NETWORK,
            payload_references=(_reference(),),
        )


def test_image_result_contains_only_a_hash_and_relative_reference() -> None:
    result = ConnectorResult(
        protocol_version=1,
        command_id="synthetic-command-006",
        operation=ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
        outcome=ConnectorResultOutcome.SUCCEEDED,
        stage=ChengfengStage.IMAGE_DOWNLOAD,
        diagnostic_classification=ConnectorDiagnosticClassification.NONE,
        payload_references=(
            _reference(
                kind=ConnectorPayloadKind.TICKET_IMAGE,
                relative_path="evidence/00/ticket.png",
                media_type="image/png",
            ),
        ),
    )

    payload = json.loads(result.to_ndjson())

    assert payload["payload_references"] == [
        {
            "byte_size": 123,
            "kind": "ticket_image",
            "media_type": "image/png",
            "relative_path": "evidence/00/ticket.png",
            "sha256": _SHA256,
        }
    ]
    assert "content" not in result.to_ndjson()
