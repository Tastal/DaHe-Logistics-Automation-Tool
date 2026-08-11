from __future__ import annotations

import hashlib
import os
from dataclasses import FrozenInstanceError, dataclass, replace
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.protocol import (
    ConnectorCommand,
    ConnectorDiagnosticClassification,
    ConnectorPayloadKind,
    ConnectorPayloadReference,
    ConnectorResult,
    ConnectorResultOutcome,
)
from dahe.adapters.chengfeng.result_verifier import (
    ResultFileVerificationError,
    VerifiedConnectorPayload,
    verify_connector_result_files,
)
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    ChengfengOperation,
    ChengfengStage,
)

_COMMAND_DIRECTORY = hashlib.sha256(b"command-001").hexdigest()
_DEFAULT_PATH = f"connector-staging/{_COMMAND_DIRECTORY}/page.json"


@dataclass
class _Authorizer:
    fail_on_call: int | None = None
    calls: int = 0

    def authorize(self, authority: BrowserCommandAuthority) -> None:
        self.calls += 1
        if self.calls == self.fail_on_call:
            raise PermissionError("synthetic authority expired")


def _command(
    operation: ChengfengOperation = ChengfengOperation.LIST_WAYBILLS,
) -> ConnectorCommand:
    parameters: dict[str, object]
    if operation is ChengfengOperation.LIST_WAYBILLS:
        parameters = {"scope": "synthetic", "page_number": 1, "page_size": 50}
    elif operation is ChengfengOperation.GET_WAYBILL_DETAIL:
        parameters = {"platform_waybill_id": "waybill-001"}
    else:
        parameters = {"ticket_ref": "ticket-001"}
    return ConnectorCommand(
        protocol_version=1,
        command_id="command-001",
        operation=operation,
        authority=BrowserCommandAuthority(
            session_id="session-001",
            instance_id="instance-001",
            worker_id="worker-001",
            job_id="job-001",
            control_epoch=1,
            fencing_token="fencing-token-001",
        ),
        parameters=parameters,
        credential_reference=None,
    )


def _result(
    content: bytes,
    *,
    relative_path: str = _DEFAULT_PATH,
    sha256: str | None = None,
    byte_size: int | None = None,
    operation: ChengfengOperation = ChengfengOperation.LIST_WAYBILLS,
) -> ConnectorResult:
    if operation is ChengfengOperation.LIST_WAYBILLS:
        kind = ConnectorPayloadKind.WAYBILL_PAGE
        media_type = "application/json"
        stage = ChengfengStage.LIST_QUERY
    elif operation is ChengfengOperation.GET_WAYBILL_DETAIL:
        kind = ConnectorPayloadKind.WAYBILL_DETAIL
        media_type = "application/json"
        stage = ChengfengStage.DETAIL_QUERY
    else:
        kind = ConnectorPayloadKind.TICKET_IMAGE
        media_type = "image/png"
        stage = ChengfengStage.IMAGE_DOWNLOAD
    return ConnectorResult(
        protocol_version=1,
        command_id="command-001",
        operation=operation,
        outcome=ConnectorResultOutcome.SUCCEEDED,
        stage=stage,
        diagnostic_classification=ConnectorDiagnosticClassification.NONE,
        payload_references=(
            ConnectorPayloadReference(
                kind=kind,
                relative_path=relative_path,
                sha256=sha256 or hashlib.sha256(content).hexdigest(),
                media_type=media_type,
                byte_size=len(content) if byte_size is None else byte_size,
            ),
        ),
    )


def _write_payload(data_root: Path, relative_path: str, content: bytes) -> Path:
    target = data_root.joinpath(*relative_path.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


def test_verified_payload_is_immutable_and_authorized_before_and_after_read(
    tmp_path: Path,
) -> None:
    content = b'{"ok":true}'
    result = _result(content)
    _write_payload(tmp_path, result.payload_references[0].relative_path, content)
    authorizer = _Authorizer()

    verified = verify_connector_result_files(
        command=_command(),
        result=result,
        data_root=tmp_path,
        authorizer=authorizer,
    )

    assert authorizer.calls == 2
    assert verified == (
        VerifiedConnectorPayload(
            kind=ConnectorPayloadKind.WAYBILL_PAGE,
            relative_path=_DEFAULT_PATH,
            sha256=hashlib.sha256(content).hexdigest(),
            media_type="application/json",
            byte_size=len(content),
            content=content,
        ),
    )
    with pytest.raises(FrozenInstanceError):
        verified[0].byte_size = 1


def test_result_mismatch_is_rejected_before_authorization(tmp_path: Path) -> None:
    content = b'{"ok":true}'
    result = replace(_result(content), command_id="different-command")
    authorizer = _Authorizer()

    with pytest.raises(ValueError, match="command_id"):
        verify_connector_result_files(
            command=_command(),
            result=result,
            data_root=tmp_path,
            authorizer=authorizer,
        )

    assert authorizer.calls == 0


def test_result_cannot_reference_another_commands_staged_payload(tmp_path: Path) -> None:
    content = b'{"ok":true}'
    other_directory = hashlib.sha256(b"other-command").hexdigest()
    relative_path = f"connector-staging/{other_directory}/page.json"
    result = _result(content, relative_path=relative_path)
    _write_payload(tmp_path, relative_path, content)
    authorizer = _Authorizer()

    with pytest.raises(ResultFileVerificationError, match="originating"):
        verify_connector_result_files(
            command=_command(),
            result=result,
            data_root=tmp_path,
            authorizer=authorizer,
        )
    assert authorizer.calls == 0


def test_second_authorization_failure_never_returns_verified_content(
    tmp_path: Path,
) -> None:
    content = b'{"ok":true}'
    result = _result(content)
    _write_payload(tmp_path, result.payload_references[0].relative_path, content)
    authorizer = _Authorizer(fail_on_call=2)

    with pytest.raises(PermissionError, match="expired"):
        verify_connector_result_files(
            command=_command(),
            result=result,
            data_root=tmp_path,
            authorizer=authorizer,
        )

    assert authorizer.calls == 2


@pytest.mark.parametrize(
    ("declared_sha256", "declared_size", "content", "message"),
    [
        ("f" * 64, None, b'{"ok":true}', "SHA-256"),
        (None, 1, b'{"ok":true}', "size"),
        (None, None, b"not-json", "UTF-8 JSON"),
    ],
)
def test_declared_hash_size_and_json_media_are_reverified(
    tmp_path: Path,
    declared_sha256: str | None,
    declared_size: int | None,
    content: bytes,
    message: str,
) -> None:
    result = _result(
        content,
        sha256=declared_sha256,
        byte_size=declared_size,
    )
    _write_payload(tmp_path, result.payload_references[0].relative_path, content)

    with pytest.raises(ResultFileVerificationError, match=message):
        verify_connector_result_files(
            command=_command(),
            result=result,
            data_root=tmp_path,
            authorizer=_Authorizer(),
        )


@pytest.mark.parametrize(
    "content",
    [
        b"not-an-image",
        b"\x89PNGbad",
        b"\xff\xd8\xffmissing-end-marker",
    ],
)
def test_ticket_image_signature_is_reverified(tmp_path: Path, content: bytes) -> None:
    result = _result(
        content,
        relative_path=f"connector-staging/{_COMMAND_DIRECTORY}/ticket.png",
        operation=ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
    )
    _write_payload(tmp_path, result.payload_references[0].relative_path, content)

    with pytest.raises(ResultFileVerificationError, match="image signature"):
        verify_connector_result_files(
            command=_command(ChengfengOperation.DOWNLOAD_TICKET_IMAGE),
            result=result,
            data_root=tmp_path,
            authorizer=_Authorizer(),
        )


@pytest.mark.parametrize(
    ("media_type", "content"),
    [
        ("image/png", b"\x89PNG\r\n\x1a\nsynthetic"),
        ("image/jpeg", b"\xff\xd8\xff\xe0synthetic\xff\xd9"),
    ],
)
def test_ticket_image_signature_must_match_declared_media_type(
    tmp_path: Path,
    media_type: str,
    content: bytes,
) -> None:
    result = _result(
        content,
        relative_path=f"connector-staging/{_COMMAND_DIRECTORY}/ticket.bin",
        operation=ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
    )
    reference = result.payload_references[0]
    object.__setattr__(reference, "media_type", media_type)
    _write_payload(tmp_path, reference.relative_path, content)

    verified = verify_connector_result_files(
        command=_command(ChengfengOperation.DOWNLOAD_TICKET_IMAGE),
        result=result,
        data_root=tmp_path,
        authorizer=_Authorizer(),
    )

    assert verified[0].media_type == media_type


def test_ticket_image_rejects_a_different_valid_image_signature(
    tmp_path: Path,
) -> None:
    jpeg = b"\xff\xd8\xff\xe0synthetic\xff\xd9"
    result = _result(
        jpeg,
        relative_path=f"connector-staging/{_COMMAND_DIRECTORY}/ticket.png",
        operation=ChengfengOperation.DOWNLOAD_TICKET_IMAGE,
    )
    _write_payload(tmp_path, result.payload_references[0].relative_path, jpeg)

    with pytest.raises(ResultFileVerificationError, match="image signature"):
        verify_connector_result_files(
            command=_command(ChengfengOperation.DOWNLOAD_TICKET_IMAGE),
            result=result,
            data_root=tmp_path,
            authorizer=_Authorizer(),
        )


@pytest.mark.parametrize(
    ("relative_path", "message"),
    [
        ("other-directory/page.json", "connector-staging"),
        ("connector-staging/CON.json", "reserved"),
        (f"connector-staging/{_COMMAND_DIRECTORY}/missing.json", "does not exist"),
    ],
)
def test_path_scope_reserved_names_and_missing_files_are_rejected(
    tmp_path: Path,
    relative_path: str,
    message: str,
) -> None:
    content = b'{"ok":true}'
    result = _result(content, relative_path=relative_path)
    if "missing" not in relative_path:
        _write_payload(tmp_path, relative_path, content)

    with pytest.raises(ResultFileVerificationError, match=message):
        verify_connector_result_files(
            command=_command(),
            result=result,
            data_root=tmp_path,
            authorizer=_Authorizer(),
        )


def test_lexical_escape_is_rejected_even_if_protocol_object_is_tampered(
    tmp_path: Path,
) -> None:
    content = b'{"ok":true}'
    result = _result(content)
    reference = result.payload_references[0]
    object.__setattr__(
        reference,
        "relative_path",
        "connector-staging/../../outside.json",
    )

    with pytest.raises(ResultFileVerificationError, match="connector-staging"):
        verify_connector_result_files(
            command=_command(),
            result=result,
            data_root=tmp_path,
            authorizer=_Authorizer(),
        )


def test_symlink_component_is_rejected_when_supported(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "page.json").write_bytes(b'{"ok":true}')
    staging = tmp_path / "connector-staging"
    staging.mkdir()
    link = staging / _COMMAND_DIRECTORY
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")
    content = b'{"ok":true}'
    result = _result(content)

    with pytest.raises(ResultFileVerificationError, match="symlink or reparse"):
        verify_connector_result_files(
            command=_command(),
            result=result,
            data_root=tmp_path,
            authorizer=_Authorizer(),
        )
