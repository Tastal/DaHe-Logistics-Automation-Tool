from __future__ import annotations

import importlib
import json


def _redaction() -> object:
    return importlib.import_module("dahe.adapters.chengfeng.redaction")


def test_redact_text_removes_headers_credentials_signed_queries_and_phone() -> None:
    module = _redaction()
    source = (
        "Cookie: cf_session=COOKIE-SECRET; "
        "Authorization: Bearer BEARER-SECRET; "
        "password=PASSWORD-SECRET&token=TOKEN-SECRET&signature=SIGNATURE-SECRET&"
        "accessKey=ACCESS-SECRET&phone=13800138000"
    )

    redacted = module.redact_text(source)

    for secret in (
        "COOKIE-SECRET",
        "BEARER-SECRET",
        "PASSWORD-SECRET",
        "TOKEN-SECRET",
        "SIGNATURE-SECRET",
        "ACCESS-SECRET",
        "13800138000",
    ):
        assert secret not in redacted
    assert "[REDACTED]" in redacted


def test_redact_mapping_recurses_without_mutating_the_input() -> None:
    module = _redaction()
    source = {
        "headers": {
            "Cookie": "session=COOKIE-SECRET",
            "Authorization": "Bearer BEARER-SECRET",
        },
        "request": {
            "url": "https://contract.chengfeng.invalid/image?token=TOKEN-SECRET",
            "safe_id": "synthetic-waybill-001",
        },
        "items": [{"phone": "13800138000"}],
    }

    redacted = module.redact_mapping(source)

    assert source["headers"]["Cookie"] == "session=COOKIE-SECRET"
    serialized = json.dumps(redacted, ensure_ascii=False)
    assert "COOKIE-SECRET" not in serialized
    assert "BEARER-SECRET" not in serialized
    assert "TOKEN-SECRET" not in serialized
    assert "13800138000" not in serialized
    assert "synthetic-waybill-001" in serialized


def test_safe_diagnostic_keeps_classification_but_omits_raw_response_and_secrets() -> None:
    module = _redaction()
    raw_cause = RuntimeError(
        "GET https://contract.chengfeng.invalid/image?signature=SIGNATURE-SECRET "
        "Cookie: session=COOKIE-SECRET"
    )
    error = RuntimeError("synthetic wrapper")
    error.__cause__ = raw_cause

    diagnostic = module.safe_diagnostic(
        error=error,
        stage="image_download",
        diagnostic_code="CF-IMAGE-TIMEOUT",
        retryable=True,
        response_status=504,
        response_body="<html>FULL-SENSITIVE-RESPONSE</html>",
        correlation_id="synthetic-correlation-001",
    )
    serialized = json.dumps(diagnostic, ensure_ascii=False)

    assert diagnostic["stage"] == "image_download"
    assert diagnostic["diagnostic_code"] == "CF-IMAGE-TIMEOUT"
    assert diagnostic["retryable"] is True
    assert diagnostic["cause_type"] == "RuntimeError"
    assert diagnostic["response_status"] == 504
    assert diagnostic["correlation_id"] == "synthetic-correlation-001"
    assert "SIGNATURE-SECRET" not in serialized
    assert "COOKIE-SECRET" not in serialized
    assert "FULL-SENSITIVE-RESPONSE" not in serialized
    assert "response_sha256" in diagnostic


def test_connector_command_serialization_contains_authority_not_credentials() -> None:
    ports = importlib.import_module("dahe.ports.chengfeng")
    protocol = importlib.import_module("dahe.adapters.chengfeng.protocol")
    authority = ports.BrowserCommandAuthority(
        session_id="chengfeng_session",
        instance_id="loop5-instance",
        worker_id="loop5-worker",
        job_id="loop5-job",
        control_epoch=1,
        fencing_token="process-local-fencing-token",
    )
    command = protocol.ConnectorCommand(
        protocol_version=1,
        command_id="synthetic-command-001",
        operation=ports.ChengfengOperation.LIST_WAYBILLS,
        authority=authority,
        parameters={
            "scope": "loop5-synthetic-scope",
            "page_number": 1,
            "page_size": 50,
        },
        credential_reference="windows-credential:chengfeng-test",
    )

    serialized = command.to_ndjson()

    assert serialized.endswith("\n")
    assert '"protocol_version":1' in serialized
    assert '"credential_reference":"windows-credential:chengfeng-test"' in serialized
    assert "password" not in serialized.casefold()
    assert "cookie" not in serialized.casefold()
    assert "authorization" not in serialized.casefold()


def test_authority_repr_does_not_expose_the_process_local_fencing_token() -> None:
    ports = importlib.import_module("dahe.ports.chengfeng")
    authority = ports.BrowserCommandAuthority(
        session_id="chengfeng_session",
        instance_id="loop5-instance",
        worker_id="loop5-worker",
        job_id="loop5-job",
        control_epoch=1,
        fencing_token="process-local-secret-token",
    )

    assert "process-local-secret-token" not in repr(authority)
