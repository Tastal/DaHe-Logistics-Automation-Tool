from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.verification.loop9_dataset_artifacts import (
    Loop9DatasetArtifactError,
)
from tools import loop9_build_dataset_artifacts as module


@dataclass(frozen=True)
class _FakeManifest:
    canonical_sha256: str = "a" * 64

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "canonical_sha256": self.canonical_sha256,
        }


def test_formal_command_writes_once_and_rejects_relative_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    source = (data_root / "shadow.json").resolve()
    source.write_text("{}", encoding="utf-8")
    output = (tmp_path / "formal.json").resolve()
    selection = (data_root / "selection.json").resolve()
    selection.write_text("{}", encoding="utf-8")
    loaded: list[tuple[Path, Path, object]] = []
    batch = object()
    monkeypatch.setattr(
        module,
        "_load_shadow_batch",
        lambda path: batch,
    )
    monkeypatch.setattr(
        module,
        "_load_active_formal_selection",
        lambda **values: (
            loaded.append(
                (
                    values["data_root"],
                    values["path"],
                    values["shadow_batch"],
                )
            )
            or object()
        ),
    )
    monkeypatch.setattr(
        module,
        "build_formal_dataset_manifest",
        lambda **values: _FakeManifest(),
    )
    arguments = [
        "formal",
        "--data-root",
        str(data_root),
        "--shadow-batch",
        str(source),
        "--formal-selection",
        str(selection),
        "--dataset-id",
        "loop9-shadow-30",
        "--output",
        str(output),
    ]

    assert module.main(arguments) == 0
    assert json.loads(output.read_text(encoding="utf-8"))[
        "canonical_sha256"
    ] == "a" * 64
    assert json.loads(capsys.readouterr().out)["artifact_kind"] == "formal"
    assert loaded == [(data_root, selection, batch)]

    with pytest.raises(Loop9DatasetArtifactError, match="already exists"):
        module.main(arguments)

    relative = list(arguments)
    relative[-1] = "relative.json"
    with pytest.raises(SystemExit):
        module.main(relative)


def test_json_loader_rejects_duplicate_fields(tmp_path: Path) -> None:
    source = (tmp_path / "duplicate.json").resolve()
    source.write_text('{"field":1,"field":1}', encoding="utf-8")

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="duplicate",
    ):
        module._load_json(source, "test evidence")


def test_shadow_batch_source_requires_content_addressed_filename(
    tmp_path: Path,
) -> None:
    source = (tmp_path / "shadow.json").resolve()
    source.write_text("{}", encoding="utf-8")

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="content-addressed",
    ):
        module._load_shadow_batch(source)


def test_identity_key_must_stay_inside_data_root_and_pass_acl_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    key = data_root / "identity.key"
    key.write_bytes(b"x" * 32)
    outside = (tmp_path / "outside.key").resolve()
    outside.write_bytes(b"x" * 32)
    monkeypatch.setattr(
        module,
        "_identity_key_acl_is_restricted",
        lambda path: True,
    )

    assert module._load_identity_key(
        data_root=data_root,
        identity_key=key,
    ) == b"x" * 32

    with pytest.raises(Loop9DatasetArtifactError, match="data root"):
        module._load_identity_key(
            data_root=data_root,
            identity_key=outside,
        )

    monkeypatch.setattr(
        module,
        "_identity_key_acl_is_restricted",
        lambda path: False,
    )
    with pytest.raises(Loop9DatasetArtifactError, match="permissions"):
        module._load_identity_key(
            data_root=data_root,
            identity_key=key,
        )


def test_identity_authority_is_derived_from_data_root_and_not_in_cli_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    validation = data_root / "daily.json"
    validation.write_text("{}", encoding="utf-8")
    output = data_root / "inventory.json"
    monkeypatch.setattr(
        module,
        "load_or_create_loop9_identity_authority",
        lambda _root: SimpleNamespace(
            salt=b"secret-identity-material-32-bytes",
            namespace="chengfeng:waybill",
        ),
    )
    monkeypatch.setattr(
        module,
        "_build_daily_inventory_from_data_root",
        lambda **values: _FakeManifest(),
    )

    assert module.main(
        [
            "daily-inventory",
            "--data-root",
            str(data_root),
            "--daily-validation",
            str(validation),
            "--output",
            str(output),
        ]
    ) == 0

    rendered = capsys.readouterr().out
    assert "secret-identity" not in rendered
    assert "chengfeng:waybill" not in rendered


def test_legacy_loop7_command_uses_existing_identity_authority_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    source = (tmp_path / "source-authority.json").resolve()
    source.write_text("{}", encoding="utf-8")
    output = (data_root / "legacy-loop7.json").resolve()
    source_authority = object()
    identity_context = "9" * 64
    received: list[dict[str, object]] = []

    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        lambda path: (
            source_authority
            if path == source
            else pytest.fail("unexpected source authority path")
        ),
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "load_loop9_identity_authority",
        lambda root: (
            SimpleNamespace(context_sha256=identity_context)
            if root == data_root
            else pytest.fail("unexpected data root")
        ),
        raising=False,
    )

    def build(**values: object) -> _FakeManifest:
        received.append(values)
        return _FakeManifest()

    monkeypatch.setattr(
        module,
        "build_legacy_loop7_exclusion_inventory",
        build,
        raising=False,
    )

    assert module.main(
        [
            "legacy-loop7-exclusions",
            "--data-root",
            str(data_root),
            "--source-development-authority",
            str(source),
            "--inventory-id",
            "loop9-legacy-loop7-source",
            "--output",
            str(output),
        ]
    ) == 0

    assert received == [
        {
            "inventory_id": "loop9-legacy-loop7-source",
            "source_authority": source_authority,
            "identity_context_sha256": identity_context,
        }
    ]
    assert json.loads(capsys.readouterr().out)["artifact_kind"] == (
        "legacy-loop7-exclusions"
    )
    assert output.is_file()


def test_legacy_loop7_command_rejects_output_outside_data_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    source = (tmp_path / "source-authority.json").resolve()
    source.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        lambda _path: object(),
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "load_loop9_identity_authority",
        lambda _root: SimpleNamespace(context_sha256="9" * 64),
        raising=False,
    )

    with pytest.raises(
        Loop9DatasetArtifactError,
        match="inside the DaHe data root",
    ):
        module.main(
            [
                "legacy-loop7-exclusions",
                "--data-root",
                str(data_root),
                "--source-development-authority",
                str(source),
                "--inventory-id",
                "loop9-legacy-loop7-source",
                "--output",
                str((tmp_path / "outside.json").resolve()),
            ]
        )


def test_daily_inventory_replay_loads_the_current_selected_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    (data_root / "evidence").mkdir(parents=True)
    validation = data_root / "daily.json"
    validation.write_text(
        json.dumps(
            {
                "snapshot_evidence": [
                    {"snapshot_id": f"snapshot-{index}"}
                    for index in range(1, 4)
                ]
            }
        ),
        encoding="utf-8",
    )
    loaded_ids: list[str] = []
    closed: list[bool] = []
    received_selection: list[dict[str, str]] = []

    class FakeRuntime:
        def __init__(self, **_values: object) -> None:
            pass

        def close(self) -> None:
            closed.append(True)

    class FakeStore:
        def __init__(self, _runtime: object) -> None:
            pass

        def get_formal_snapshot_authority(
            self,
            snapshot_id: str,
        ) -> object:
            loaded_ids.append(snapshot_id)
            return SimpleNamespace()

        def list_snapshot_observations(
            self,
            _snapshot_id: str,
        ) -> tuple[object, ...]:
            return ()

    def build(**values: object) -> _FakeManifest:
        selection = values["contract_selection"]
        received_selection.append(selection.to_payload())  # type: ignore[union-attr]
        return _FakeManifest()

    monkeypatch.setattr(module, "SqliteRuntime", FakeRuntime)
    monkeypatch.setattr(module, "SqliteDailyStore", FakeStore)
    monkeypatch.setattr(
        module,
        "load_selected_daily_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256="a" * 64,
                source_discovery_sha256="b" * 64,
            ),
            contract_file_sha256="c" * 64,
            freeze_evidence_sha256="d" * 64,
            selection_sha256="e" * 64,
        ),
    )
    monkeypatch.setattr(module, "build_daily_triplet_inventory", build)

    result = module._build_daily_inventory_from_data_root(
        data_root=data_root,
        daily_validation_path=validation,
        identity_salt=b"x" * 32,
        identity_namespace="test-context",
    )

    assert result == _FakeManifest()
    assert loaded_ids == ["snapshot-1", "snapshot-2", "snapshot-3"]
    assert closed == [True]
    assert received_selection == [
        {
            "contract_canonical_sha256": "a" * 64,
            "contract_file_sha256": "c" * 64,
            "freeze_evidence_sha256": "d" * 64,
            "selection_sha256": "e" * 64,
            "source_discovery_sha256": "b" * 64,
        }
    ]


def test_daily_manifest_rebuilds_from_formal_root_not_external_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "formal").resolve()
    data_root.mkdir()
    validation = data_root / "daily-validation.json"
    validation.write_text(
        json.dumps({"schema_version": 5}),
        encoding="utf-8",
    )
    output = data_root / "daily-manifest.json"
    received: list[dict[str, object]] = []

    def rebuild(**values: object) -> object:
        received.append(values)
        return SimpleNamespace(
            manifest=_FakeManifest(),
        )

    monkeypatch.setattr(
        module,
        "rebuild_current_daily_dataset_artifacts_from_store",
        rebuild,
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: "b" * 64,
    )

    assert module.main(
        [
            "daily-manifest",
            "--data-root",
            str(data_root),
            "--daily-validation",
            str(validation),
            "--dataset-id",
            "loop9-daily-validation",
            "--output",
            str(output),
        ]
    ) == 0
    assert json.loads(output.read_text(encoding="utf-8"))[
        "canonical_sha256"
    ] == "a" * 64
    assert received == [
        {
            "dataset_id": "loop9-daily-validation",
            "daily_validation": {"schema_version": 5},
            "data_root": data_root,
            "project_root": module.ROOT,
            "source_build_sha256": "b" * 64,
        }
    ]

    with pytest.raises(SystemExit):
        module.main(
            [
                "daily-manifest",
                "--daily-inventory",
                str(data_root / "untrusted.json"),
                "--dataset-id",
                "loop9-daily-validation",
                "--output",
                str(data_root / "other.json"),
            ]
        )
