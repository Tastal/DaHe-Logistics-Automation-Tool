from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from dahe.system.instance_lock import AlreadyRunningError
from tools import loop7_candidate_review_export as module

_HASHES = {
    name: hashlib.sha256(name.encode("utf-8")).hexdigest()
    for name in (
        "package",
        "history",
        "record",
        "images",
        "manifest",
        "quality",
        "source",
        "seal",
    )
}


def _arguments(
    *,
    command: str,
    data_root: Path,
    output: Path | None = None,
) -> list[str]:
    values = [
        command,
        "--data-root",
        str(data_root),
        "--reviewer-id",
        "reviewer-fixed",
        "--dataset-id",
        "locked-review-50",
    ]
    if command == "snapshot-development":
        assert output is not None
        values.extend(
            [
                "--reason",
                "Development-only benchmark snapshot.",
                "--output",
                str(output),
            ]
        )
    return values


def _install_successful_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    *,
    data_root: Path,
    events: list[str],
) -> tuple[SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    review_root = data_root / "locked-set-review"
    review_root.mkdir(parents=True)
    package = SimpleNamespace(
        canonical_sha256=_HASHES["package"],
        package_id="private-package-id",
        review_root=review_root,
    )
    authority = SimpleNamespace(
        package_sha256=_HASHES["package"],
        canonical_sha256=_HASHES["history"],
        payload={
            "schema_version": 1,
            "kind": "locked_set_review_authority_snapshot",
            "package_sha256": _HASHES["package"],
            "sample_count": 50,
            "latest_record_count": 50,
            "history_record_count": 57,
            "idempotency_record_count": 57,
            "latest_records": [{"sample_id": "sample-private"}],
            "history_records": [{"sample_id": "sample-private"}],
            "idempotency_records": [{"idempotency_key": "private-key"}],
        },
        latest_records=tuple(range(50)),
        history_records=tuple(range(57)),
        idempotency_records=tuple(range(57)),
    )
    formal_export = SimpleNamespace(
        manifest=SimpleNamespace(dataset_id="locked-review-50"),
        manifest_payload={"dataset_id": "locked-review-50"},
        manifest_sha256=_HASHES["manifest"],
        source_authority_payload={
            "dataset_id": "locked-review-50",
            "package_sha256": _HASHES["package"],
            "manifest_sha256": _HASHES["manifest"],
            "record_count": 50,
            "record_set_sha256": _HASHES["record"],
            "verified_image_count": 100,
            "verified_image_set_sha256": _HASHES["images"],
        },
        source_authority_sha256=_HASHES["source"],
        record_set_sha256=_HASHES["record"],
        quality_coverage_payload={"dataset_id": "locked-review-50"},
        quality_coverage_sha256=_HASHES["quality"],
    )

    def prepare(config: Any, project_root: Path) -> Path:
        events.append("prepare")
        assert config.data_root == data_root
        assert project_root == module.ROOT
        return data_root

    class Guard:
        instance_id = "isolated-cli-instance"

        def __init__(
            self,
            guarded_root: Path,
            port: int,
            application_version: str,
        ) -> None:
            events.append("guard_init")
            assert guarded_root == data_root
            assert port == 8877
            assert application_version

        def __enter__(self) -> Guard:
            events.append("guard_enter")
            return self

        def __exit__(self, *_: object) -> None:
            events.append("guard_exit")

    class Runtime:
        def __init__(
            self,
            *,
            data_root: Path,
            project_root: Path,
            instance_id: str,
        ) -> None:
            events.append("runtime")
            assert data_root == data_root_expected
            assert project_root == module.ROOT
            assert instance_id == "isolated-cli-instance"

        def close(self) -> None:
            events.append("runtime_close")

    data_root_expected = data_root

    class Repository:
        def build_authority_snapshot(self) -> SimpleNamespace:
            events.append("authority")
            return authority

    def repository(*, runtime: object, package_sha256: str) -> Repository:
        events.append("repository")
        assert isinstance(runtime, Runtime)
        assert package_sha256 == _HASHES["package"]
        return Repository()

    def load_package(root: Path) -> SimpleNamespace:
        events.append("load_package")
        assert root == data_root
        return package

    def build_export(**kwargs: object) -> SimpleNamespace:
        events.append("build_export")
        assert kwargs == {
            "package": package,
            "records": authority.latest_records,
            "configured_reviewer_id": "reviewer-fixed",
            "dataset_id": "locked-review-50",
        }
        return formal_export

    monkeypatch.setattr(module, "prepare_startup_environment", prepare)
    monkeypatch.setattr(module, "SingleInstanceGuard", Guard)
    monkeypatch.setattr(module, "SqliteRuntime", Runtime)
    monkeypatch.setattr(
        module,
        "SqliteLockedSetReviewRepository",
        repository,
    )
    monkeypatch.setattr(
        module,
        "load_locked_set_review_package",
        load_package,
    )
    monkeypatch.setattr(
        module,
        "build_candidate_review_formal_export",
        build_export,
    )
    return package, authority, formal_export


@pytest.mark.parametrize(
    ("command", "tail"),
    (
        ("seal-formal", []),
        (
            "snapshot-development",
            [
                "--reason",
                "Development-only evidence.",
                "--output",
                "relative.json",
            ],
        ),
    ),
)
def test_parser_requires_absolute_paths(
    command: str,
    tail: list[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        module._parser().parse_args(
            [
                command,
                "--data-root",
                "relative-data",
                "--reviewer-id",
                "reviewer",
                "--dataset-id",
                "dataset",
                *tail,
            ]
        )

    assert error.value.code == 2


def test_snapshot_parser_rejects_relative_output(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as error:
        module._parser().parse_args(
            [
                "snapshot-development",
                "--data-root",
                str((tmp_path / "data").resolve()),
                "--reviewer-id",
                "reviewer",
                "--dataset-id",
                "dataset",
                "--reason",
                "Development-only evidence.",
                "--output",
                "relative.json",
            ]
        )

    assert error.value.code == 2


def test_seal_formal_uses_one_locked_authority_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    events: list[str] = []
    package, authority, formal_export = _install_successful_pipeline(
        monkeypatch,
        data_root=data_root,
        events=events,
    )
    seal = SimpleNamespace(
        seal_sha256=_HASHES["seal"],
        seal_root=package.review_root / "seals" / _HASHES["seal"],
        seal_payload={"seal_sha256": _HASHES["seal"]},
    )

    def create_seal(**kwargs: object) -> SimpleNamespace:
        events.append("create_seal")
        assert kwargs == {
            "review_data_root": package.review_root,
            "formal_export": formal_export,
            "review_history_authority_payload": authority.payload,
            "review_history_authority_sha256": authority.canonical_sha256,
        }
        return seal

    monkeypatch.setattr(
        module,
        "create_candidate_review_seal",
        create_seal,
    )

    result = module.main(
        _arguments(
            command="seal-formal",
            data_root=data_root,
        )
    )

    printed = capsys.readouterr().out
    summary = json.loads(printed)
    assert result == 0
    assert events == [
        "prepare",
        "guard_init",
        "guard_enter",
        "load_package",
        "runtime",
        "repository",
        "authority",
        "runtime_close",
        "build_export",
        "create_seal",
        "guard_exit",
    ]
    assert summary == {
        "history_record_count": 57,
        "latest_record_count": 50,
        "manifest_sha256": _HASHES["manifest"],
        "quality_coverage_sha256": _HASHES["quality"],
        "record_set_sha256": _HASHES["record"],
        "review_history_authority_sha256": _HASHES["history"],
        "seal_sha256": _HASHES["seal"],
        "status": "formal_seal_validated",
        "verified_image_count": 100,
        "verified_image_set_sha256": _HASHES["images"],
    }
    assert str(data_root) not in printed
    assert "reviewer-fixed" not in printed
    assert "locked-review-50" not in printed
    assert "private-package-id" not in printed
    assert "sample-private" not in printed
    assert "private-key" not in printed


def test_snapshot_development_writes_bound_nonformal_artifact_without_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    output = (tmp_path / "exports" / "development.json").resolve()
    events: list[str] = []
    _, _, _ = _install_successful_pipeline(
        monkeypatch,
        data_root=data_root,
        events=events,
    )

    def fail_seal(**_: object) -> None:
        raise AssertionError("development snapshot must never create a formal seal")

    monkeypatch.setattr(
        module,
        "create_candidate_review_seal",
        fail_seal,
    )

    result = module.main(
        _arguments(
            command="snapshot-development",
            data_root=data_root,
            output=output,
        )
    )

    printed = capsys.readouterr().out
    summary = json.loads(printed)
    payload = json.loads(output.read_text(encoding="utf-8"))
    unsigned_payload = dict(payload)
    snapshot_sha256 = unsigned_payload.pop("snapshot_sha256")
    assert result == 0
    assert events == [
        "prepare",
        "guard_init",
        "guard_enter",
        "load_package",
        "runtime",
        "repository",
        "authority",
        "runtime_close",
        "build_export",
        "guard_exit",
    ]
    assert payload == {
        "schema_version": 1,
        "kind": "candidate_review_development_snapshot",
        "development_only": True,
        "formal_release_eligible": False,
        "reason": "Development-only benchmark snapshot.",
        "dataset_id": "locked-review-50",
        "package_sha256": _HASHES["package"],
        "record_count": 50,
        "record_set_sha256": _HASHES["record"],
        "history_record_count": 57,
        "review_history_authority_sha256": _HASHES["history"],
        "verified_image_count": 100,
        "verified_image_set_sha256": _HASHES["images"],
        "manifest_sha256": _HASHES["manifest"],
        "quality_coverage_sha256": _HASHES["quality"],
        "source_authority_sha256": _HASHES["source"],
        "snapshot_sha256": snapshot_sha256,
    }
    assert snapshot_sha256 == module._canonical_sha256(unsigned_payload)
    assert summary == {
        "history_record_count": 57,
        "latest_record_count": 50,
        "manifest_sha256": _HASHES["manifest"],
        "quality_coverage_sha256": _HASHES["quality"],
        "record_set_sha256": _HASHES["record"],
        "review_history_authority_sha256": _HASHES["history"],
        "snapshot_sha256": snapshot_sha256,
        "status": "development_snapshot_created",
        "verified_image_count": 100,
        "verified_image_set_sha256": _HASHES["images"],
    }
    assert str(output) not in printed
    assert str(data_root) not in printed
    assert "reviewer-fixed" not in printed
    assert "Development-only benchmark snapshot." not in printed
    assert "locked-review-50" not in printed


@pytest.mark.parametrize("location", ("data-root", "review-root"))
def test_snapshot_rejects_output_inside_protected_roots_before_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    protected_root = data_root if location == "data-root" else data_root / "locked-set-review"
    output = protected_root / "development.json"
    called = False

    def fail_prepare(*_: object) -> None:
        nonlocal called
        called = True
        raise AssertionError("protected output must fail before startup writes")

    monkeypatch.setattr(module, "prepare_startup_environment", fail_prepare)

    with pytest.raises(
        module.CandidateReviewExportToolError,
        match="protected",
    ):
        module.main(
            _arguments(
                command="snapshot-development",
                data_root=data_root,
                output=output,
            )
        )

    assert called is False
    assert not output.exists()


def test_snapshot_refuses_existing_output_without_starting_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    output = (tmp_path / "existing.json").resolve()
    output.write_bytes(b'{"owned_by":"another process"}\n')

    def fail_prepare(*_: object) -> None:
        raise AssertionError("existing output must fail before startup writes")

    monkeypatch.setattr(module, "prepare_startup_environment", fail_prepare)

    with pytest.raises(
        module.CandidateReviewExportToolError,
        match="already exists",
    ):
        module.main(
            _arguments(
                command="snapshot-development",
                data_root=data_root,
                output=output,
            )
        )

    assert output.read_bytes() == b'{"owned_by":"another process"}\n'


def test_lock_collision_prevents_package_or_database_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    events: list[str] = []

    def prepare(_: object, __: Path) -> Path:
        events.append("prepare")
        return data_root

    class Guard:
        def __init__(self, *_: object) -> None:
            events.append("guard_init")

        def __enter__(self) -> None:
            events.append("guard_enter")
            raise AlreadyRunningError("application is already running")

        def __exit__(self, *_: object) -> None:
            raise AssertionError("unacquired guard must not exit")

    def fail_access(*_: object, **__: object) -> None:
        raise AssertionError("locked application data must not be read")

    monkeypatch.setattr(module, "prepare_startup_environment", prepare)
    monkeypatch.setattr(module, "SingleInstanceGuard", Guard)
    monkeypatch.setattr(
        module,
        "load_locked_set_review_package",
        fail_access,
    )
    monkeypatch.setattr(module, "SqliteRuntime", fail_access)

    with pytest.raises(AlreadyRunningError):
        module.main(
            _arguments(
                command="seal-formal",
                data_root=data_root,
            )
        )

    assert events == ["prepare", "guard_init", "guard_enter"]


def test_atomic_writer_refuses_racing_or_existing_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = (tmp_path / "development.json").resolve()
    output.write_bytes(b'{"owned_by":"another process"}\n')

    with pytest.raises(
        module.CandidateReviewExportToolError,
        match="already exists",
    ):
        module._write_json_exclusive_atomic(
            output,
            {"schema_version": 1},
        )
    assert output.read_bytes() == b'{"owned_by":"another process"}\n'

    output.unlink()
    real_link = module.os.link

    def race_link(source: Path, destination: Path) -> None:
        destination.write_bytes(b'{"won_by":"another process"}\n')
        real_link(source, destination)

    monkeypatch.setattr(module.os, "link", race_link)
    with pytest.raises(
        module.CandidateReviewExportToolError,
        match="appeared during",
    ):
        module._write_json_exclusive_atomic(
            output,
            {"schema_version": 1},
        )

    assert output.read_bytes() == b'{"won_by":"another process"}\n'
    assert not tuple(tmp_path.glob(".*.tmp"))
