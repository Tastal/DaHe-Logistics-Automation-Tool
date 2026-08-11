from __future__ import annotations

import importlib
import json
import socket
from pathlib import Path

import pytest
from pydantic import ValidationError

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "chengfeng" / "loop5-synthetic-v1"
EXPECTED_OPERATIONS = (
    "list_waybills",
    "get_waybill_detail",
    "download_ticket_image",
)


def _manifest_type() -> type:
    module = importlib.import_module("dahe.adapters.chengfeng.manifest")
    return module.FrozenContractManifest


def _frozen_types() -> tuple[type, type]:
    module = importlib.import_module("dahe.adapters.chengfeng.frozen")
    return module.FrozenChengfengAdapter, module.FrozenTransport


def _load_manifest() -> object:
    return _manifest_type().load(FIXTURE_ROOT)


def _adapter() -> object:
    manifest = _load_manifest()
    adapter_type, transport_type = _frozen_types()
    transport = transport_type(manifest=manifest)
    return adapter_type(manifest=manifest, transport=transport)


def test_manifest_freezes_one_synthetic_origin_and_exact_read_operations() -> None:
    manifest = _load_manifest()

    assert manifest.schema_version == 1
    assert manifest.request_contract_version == "loop5.synthetic.v1"
    assert manifest.origin == "https://contract.chengfeng.invalid"
    assert tuple(manifest.allowed_operations) == EXPECTED_OPERATIONS
    assert manifest.safety.network_allowed is False
    assert manifest.safety.real_platform_capture is False
    assert manifest.safety.real_host_or_path_verified is False


def test_loading_manifest_verifies_every_declared_fixture_hash(tmp_path: Path) -> None:
    manifest = _load_manifest()
    report = manifest.verify_fixture_files()

    raw = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    declared_files = {request["response"]["body_file"] for request in raw["requests"]} | {
        response["body_file"] for response in raw["fault_responses"].values()
    }
    assert set(report.verified_files) == declared_files

    damaged_root = tmp_path / "damaged-contract"
    damaged_root.mkdir()
    for source in FIXTURE_ROOT.iterdir():
        if source.is_file():
            (damaged_root / source.name).write_bytes(source.read_bytes())
    (damaged_root / "list.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match=r"(?i)(sha-?256|hash|size)"):
        _manifest_type().load(damaged_root)


def test_synthetic_contract_contains_no_credentials_or_production_markers() -> None:
    manifest = _load_manifest()
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in FIXTURE_ROOT.iterdir()
        if path.suffix in {".json", ".html", ".b64"}
    ).casefold()

    assert manifest.safety.credentials_present is False
    assert manifest.safety.signed_urls_present is False
    assert manifest.safety.production_identifiers_present is False
    assert "cookie:" not in combined
    assert "authorization:" not in combined
    assert "password" not in combined
    assert "accesskey" not in combined
    assert "contract.chengfeng.invalid" in combined


def test_frozen_adapter_replays_list_details_and_images_without_socket_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[tuple[object, ...]] = []

    def reject_connect(*args: object, **kwargs: object) -> None:
        attempts.append((*args, kwargs))
        raise AssertionError("Loop 5 frozen replay must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", reject_connect)
    adapter = _adapter()

    page = adapter.list_waybills(
        scope="loop5-synthetic-scope",
        page_number=1,
        page_size=50,
    )
    details = [adapter.get_waybill_detail(item.platform_waybill_id) for item in page.items]
    images = [
        adapter.download_ticket_image(ticket.ticket_ref)
        for detail in details
        for ticket in detail.tickets
    ]

    assert page.total == 2
    assert [item.waybill_number for item in page.items] == [
        "SYN-WB-001",
        "SYN-WB-002",
    ]
    assert details[1].vehicle_number is None
    assert details[1].loading_net is None
    assert len(images) == 4
    assert all(image.media_type == "image/png" for image in images)
    assert all(len(image.content) == 68 for image in images)
    assert attempts == []


def test_normal_application_cannot_enable_or_expose_real_platform_access(
    tmp_path: Path,
    project_root: Path,
) -> None:
    config_module = importlib.import_module("dahe.config.schema")
    app_module = importlib.import_module("dahe.api.app")

    with pytest.raises(ValidationError):
        config_module.AppConfig(real_platform_access=True)

    app = app_module.create_app(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop5-contract-app",
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    meta_route = next(
        route for route in app.routes if getattr(route, "path", None) == "/api/v1/meta"
    )
    assert meta_route.endpoint()["real_platform_access"] is False
    assert meta_route.endpoint()["platform_adapter"] == "fake"
