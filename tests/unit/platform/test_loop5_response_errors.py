from __future__ import annotations

import importlib
from pathlib import Path

import pytest

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "chengfeng" / "loop5-synthetic-v1"


def _modules() -> tuple[object, object, object]:
    manifest_module = importlib.import_module("dahe.adapters.chengfeng.manifest")
    frozen_module = importlib.import_module("dahe.adapters.chengfeng.frozen")
    port_module = importlib.import_module("dahe.ports.chengfeng")
    return manifest_module, frozen_module, port_module


def _adapter(
    *,
    fault: str | None = None,
    operation: str = "list_waybills",
    dns_ok: bool = True,
) -> tuple[object, object, object]:
    manifest_module, frozen_module, port_module = _modules()
    manifest = manifest_module.FrozenContractManifest.load(FIXTURE_ROOT)
    transport = frozen_module.FrozenTransport(manifest=manifest)
    if fault is not None:
        transport.fail_next(operation=operation, fault=frozen_module.FrozenFault(fault))
    diagnostic_probe = frozen_module.FrozenDiagnosticProbe(dns_ok=dns_ok)
    adapter = frozen_module.FrozenChengfengAdapter(
        manifest=manifest,
        transport=transport,
        diagnostic_probe=diagnostic_probe,
    )
    return adapter, transport, port_module


def test_list_and_detail_ignore_irrelevant_fields_but_preserve_nullable_values() -> None:
    adapter, _, _ = _adapter()

    page = adapter.list_waybills(
        scope="loop5-synthetic-scope",
        page_number=1,
        page_size=50,
    )
    first = adapter.get_waybill_detail("synthetic-waybill-001")
    second = adapter.get_waybill_detail("synthetic-waybill-002")

    assert page.total == 2
    assert not hasattr(page, "server_note")
    assert not hasattr(page.items[0], "display_label")
    assert first.loading_net == "30.00"
    assert second.vehicle_number is None
    assert second.loading_net is None


def test_login_page_is_classified_as_waiting_external_not_page_change() -> None:
    adapter, _, ports = _adapter(fault="login_required")

    with pytest.raises(ports.LoginRequiredError) as captured:
        adapter.list_waybills(
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )

    error = captured.value
    assert error.stage.value == "list_query"
    assert error.diagnostic_code == "CF-LOGIN-REQUIRED"
    assert error.retryable is False
    assert not hasattr(error, "next_job_status")
    assert not isinstance(error, ports.PageContractChangedError)


def test_unknown_html_is_page_contract_change_not_login_failure() -> None:
    adapter, _, ports = _adapter(fault="page_contract_changed")

    with pytest.raises(ports.PageContractChangedError) as captured:
        adapter.list_waybills(
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )

    error = captured.value
    assert error.stage.value == "list_query"
    assert error.diagnostic_code == "CF-PAGE-CONTRACT-CHANGED"
    assert error.retryable is False
    assert not hasattr(error, "next_job_status")
    assert not isinstance(error, ports.LoginRequiredError)


def test_image_timeout_is_retryable_and_distinct_from_login_and_page_change() -> None:
    adapter, _, ports = _adapter(
        fault="image_timeout",
        operation="download_ticket_image",
    )

    with pytest.raises(ports.ImageDownloadTimeoutError) as captured:
        adapter.download_ticket_image("synthetic-ticket-load-001")

    error = captured.value
    assert error.stage.value == "image_download"
    assert error.diagnostic_code == "CF-IMAGE-TIMEOUT"
    assert error.retryable is True
    assert not hasattr(error, "next_job_status")
    assert not isinstance(error, (ports.LoginRequiredError, ports.PageContractChangedError))


def test_transient_list_failure_is_retryable_network_error_with_original_cause() -> None:
    adapter, _, ports = _adapter(fault="network_transient")

    with pytest.raises(ports.TransientNetworkError) as captured:
        adapter.list_waybills(
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )

    error = captured.value
    assert error.stage.value == "list_query"
    assert error.diagnostic_code == "CF-NETWORK-TRANSIENT"
    assert error.retryable is True
    assert not hasattr(error, "next_job_status")
    assert error.__cause__ is not None


def test_dns_diagnostic_failure_does_not_block_successful_business_request() -> None:
    adapter, transport, _ = _adapter(dns_ok=False)

    page = adapter.list_waybills(
        scope="loop5-synthetic-scope",
        page_number=1,
        page_size=50,
    )

    assert page.total == 2
    assert transport.request_count("list_waybills") == 1
    assert adapter.diagnostics[-1].code == "CF-DNS-DIAGNOSTIC"
    assert adapter.diagnostics[-1].blocking is False
