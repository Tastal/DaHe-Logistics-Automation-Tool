from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.discovery import DiscoveryEvidenceStore
from dahe.verification.loop9_dataset_isolation import (
    load_loop9_exclusion_inventory,
)
from tools import loop9_register_discovery_exclusion as module


def _discovery(data_root: Path) -> Path:
    return DiscoveryEvidenceStore(data_root).seal(
        observations=[
            {
                "method": "POST",
                "origin": "https://pc.chengfengkuaiyun.com",
                "path": (
                    "/api/order-center-server/app/clientOrderItem/"
                    "getOrderItemDetailsByIdPC"
                ),
                "path_sha256": None,
                "query_keys": [],
                "request_fields": [
                    {"path": "$.orderItemId", "type": "integer"}
                ],
                "resource_kind": "json_api",
                "response_status": 200,
                "content_kind": "json",
                "response_fields": [
                    {"path": "$.data.id", "type": "integer"}
                ],
            }
        ],
        build_sha256="a" * 64,
        access_window_id="window-one",
        captured_at=datetime(2026, 7, 30, tzinfo=UTC),
    ).path.resolve()


def test_cli_registers_identity_only_discovery_exclusion_without_raw_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_root = tmp_path.resolve()
    discovery = _discovery(data_root)
    monkeypatch.setattr(module.sys, "stdin", io.StringIO("67011222\n"))

    assert module.main(
        [
            "--data-root",
            str(data_root),
            "--discovery-evidence",
            str(discovery),
        ]
    ) == 0

    registry_files = tuple(
        (data_root / "loop9-development-exclusions").glob("*.json")
    )
    binding_files = tuple(
        (
            data_root
            / "platform-contract-discovery-exclusions"
        ).glob("*.json")
    )
    assert len(registry_files) == 1
    assert len(binding_files) == 1
    inventory = load_loop9_exclusion_inventory(
        registry_files[0].resolve()
    )
    assert len(inventory.platform_identity_sha256s) == 1
    assert inventory.image_sha256s == ()
    assert inventory.perceptual_fingerprints == ()
    assert inventory.scope_exclusion_tokens == ()
    persisted = (
        registry_files[0].read_text(encoding="utf-8")
        + binding_files[0].read_text(encoding="utf-8")
        + capsys.readouterr().out
    )
    assert "67011222" not in persisted
    assert json.loads(binding_files[0].read_text(encoding="utf-8"))[
        "source_discovery_sha256"
    ] == discovery.stem


def test_cli_rejects_empty_or_relative_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = _discovery(tmp_path.resolve())
    monkeypatch.setattr(module.sys, "stdin", io.StringIO("\n"))
    with pytest.raises(SystemExit, match="stdin"):
        module.main(
            [
                "--data-root",
                str(tmp_path.resolve()),
                "--discovery-evidence",
                str(discovery),
            ]
        )

    with pytest.raises(SystemExit):
        module.main(
            [
                "--data-root",
                "relative",
                "--discovery-evidence",
                str(discovery),
            ]
        )


def test_stdin_accepts_powershell_utf8_bom(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.TextIOWrapper(
        io.BytesIO(b"\xef\xbb\xbf67011222\r\n"),
        encoding="gbk",
        errors="surrogateescape",
    )
    monkeypatch.setattr(module.sys, "stdin", stream)

    assert module._source_identities_from_stdin() == ("67011222",)
