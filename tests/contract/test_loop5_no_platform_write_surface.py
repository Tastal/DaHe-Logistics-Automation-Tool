from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest
from pydantic import ValidationError

EXPECTED_READ_OPERATIONS = {
    "list_waybills",
    "get_waybill_detail",
    "download_ticket_image",
}
FORBIDDEN_LOCAL_ROUTES = {
    "/api/v1/settlement/confirm",
    "/api/v1/settlement/pay",
    "/api/v1/payment",
    "/api/v1/receipts/{waybill_id}/cancel",
    "/api/v1/platform/request",
}


def test_public_connector_operation_enum_contains_only_frozen_read_operations() -> None:
    ports = importlib.import_module("dahe.ports.chengfeng")

    assert {operation.value for operation in ports.ChengfengOperation} == (EXPECTED_READ_OPERATIONS)


def test_connector_command_rejects_unknown_and_financial_write_operations() -> None:
    ports = importlib.import_module("dahe.ports.chengfeng")
    protocol = importlib.import_module("dahe.adapters.chengfeng.protocol")
    authority = ports.BrowserCommandAuthority(
        session_id="chengfeng_session",
        instance_id="loop5-instance",
        worker_id="loop5-worker",
        job_id="loop5-job",
        control_epoch=1,
        fencing_token="test-token",
    )

    for operation in (
        "raw_request",
        "confirm_settlement",
        "payment",
        "cancel_receipt",
    ):
        with pytest.raises((ValueError, TypeError)):
            protocol.ConnectorCommand(
                protocol_version=1,
                command_id=f"forbidden-{operation}",
                operation=operation,
                authority=authority,
                parameters={},
                credential_reference=None,
            )


def test_openapi_has_no_financial_or_generic_platform_write_route(
    tmp_path: Path,
    project_root: Path,
) -> None:
    app_module = importlib.import_module("dahe.api.app")
    app = app_module.create_app(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop5-openapi-test",
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )

    paths = set(app.openapi()["paths"])

    assert paths.isdisjoint(FORBIDDEN_LOCAL_ROUTES)
    assert "/api/v1/jobs/{job_id}/cancel" in paths


def test_frozen_adapter_has_no_generic_request_or_platform_write_method() -> None:
    frozen = importlib.import_module("dahe.adapters.chengfeng.frozen")
    config_module = importlib.import_module("dahe.config.schema")
    public_callables = {
        name
        for name, member in inspect.getmembers(
            frozen.FrozenChengfengAdapter,
            predicate=callable,
        )
        if not name.startswith("_")
    }

    assert public_callables == EXPECTED_READ_OPERATIONS
    with pytest.raises(ValidationError):
        config_module.AppConfig(real_platform_access=True)
