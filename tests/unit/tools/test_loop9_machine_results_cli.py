from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.verification.loop9_machine_results import Loop9MachineResultError
from tools import loop9_machine_results as module


def _path(tmp_path: Path, name: str) -> Path:
    return (tmp_path / name).resolve()


def test_run_cli_accepts_only_absolute_paths_and_delegates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_root = _path(tmp_path, "data")
    data_root.mkdir()
    source_batch = _path(tmp_path, f"{'a' * 64}.json")
    source_batch.write_text("{}", encoding="utf-8")
    source_selection = _path(tmp_path, f"{'b' * 64}.json")
    source_selection.write_text("{}", encoding="utf-8")
    received: dict[str, object] = {}

    def run(arguments: object) -> dict[str, object]:
        received["arguments"] = arguments
        return {
            "canonical_sha256": "b" * 64,
            "item_count": 30,
            "machine_result": "machine.json",
            "shadow_review_auxiliary": "auxiliary.json",
            "successful_runtime_observation_count": 120,
            "technical_failure_count": 0,
        }

    monkeypatch.setattr(module, "_run", run)
    assert (
        module.main(
            [
                "run",
                "--data-root",
                str(data_root),
                "--source-batch",
                str(source_batch),
                "--source-selection",
                str(source_selection),
                "--job-id",
                "job-001",
            ]
        )
        == 0
    )
    arguments = received["arguments"]
    assert arguments.data_root == data_root
    assert arguments.source_batch == source_batch
    assert arguments.source_selection == source_selection
    assert arguments.job_id == "job-001"
    assert json.loads(capsys.readouterr().out)["successful_runtime_observation_count"] == 120

    with pytest.raises(SystemExit):
        module.main(
            [
                "run",
                "--data-root",
                "relative",
                "--source-batch",
                str(source_batch),
                "--source-selection",
                str(source_selection),
                "--job-id",
                "job-001",
            ]
        )


def test_evaluate_cli_delegates_without_authority_sha_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = {
        name: _path(tmp_path, name)
        for name in (
            "data",
            "package",
            "seal.json",
            "machine.json",
            "selection.json",
        )
    }
    paths["data"].mkdir()
    paths["package"].mkdir()
    paths["seal.json"].write_text("{}", encoding="utf-8")
    paths["machine.json"].write_text("{}", encoding="utf-8")
    paths["selection.json"].write_text("{}", encoding="utf-8")
    received: dict[str, object] = {}

    def evaluate(arguments: object) -> dict[str, object]:
        received["arguments"] = arguments
        return {
            "canonical_sha256": "c" * 64,
            "gate_passed": True,
            "output": "evaluation.json",
            "review_kind": "real_shadow_30",
        }

    monkeypatch.setattr(module, "_evaluate", evaluate)
    assert (
        module.main(
            [
                "evaluate",
                "--data-root",
                str(paths["data"]),
                "--package-dir",
                str(paths["package"]),
                "--seal",
                str(paths["seal.json"]),
                "--machine-result",
                str(paths["machine.json"]),
                "--locked-selection",
                str(paths["selection.json"]),
            ]
        )
        == 0
    )
    assert received["arguments"].machine_result == paths["machine.json"]
    assert received["arguments"].locked_selection == paths["selection.json"]

    parser = module._parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "run",
                "--data-root",
                str(paths["data"]),
                "--source-batch",
                str(paths["machine.json"]),
                "--job-id",
                "job-001",
                "--development-authority-sha256",
                "d" * 64,
            ]
        )


def test_current_locked_evaluate_publishes_selection_scoped_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = _path(tmp_path, "data")
    data_root.mkdir()
    selection_path = _path(tmp_path, "selection.json")
    selection_path.write_text("{}\n", encoding="utf-8")
    package_dir = _path(tmp_path, "package")
    package_dir.mkdir()
    seal_path = _path(tmp_path, "seal.json")
    seal_path.write_text("{}\n", encoding="utf-8")
    machine_path = _path(tmp_path, "machine.json")
    machine_path.write_text("{}\n", encoding="utf-8")
    evaluation_path = _path(tmp_path, "evaluation.json")
    evaluation_path.write_text("{}\n", encoding="utf-8")
    selection = SimpleNamespace(canonical_sha256="a" * 64)
    published: dict[str, object] = {}

    monkeypatch.setattr(
        module,
        "evaluate_sealed_machine_results",
        lambda **_kwargs: {
            "canonical_sha256": "b" * 64,
            "gate_passed": True,
            "review_kind": "current_locked_50",
        },
    )
    monkeypatch.setattr(
        module,
        "persist_machine_truth_evaluation",
        lambda **_kwargs: evaluation_path,
    )
    monkeypatch.setattr(
        module,
        "_load_locked_selection",
        lambda **_kwargs: selection,
    )
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: "d" * 64,
    )
    monkeypatch.setattr(
        module,
        "load_selected_live_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(canonical_sha256="e" * 64),
        ),
    )

    class Gate:
        canonical_sha256 = "c" * 64

    class GateStore:
        def __init__(self, root: Path) -> None:
            assert root == data_root

        def publish(self, **kwargs: object) -> Gate:
            published.update(kwargs)
            return Gate()

    monkeypatch.setattr(module, "CurrentLockedGateAuthorityStore", GateStore)

    result = module._evaluate(
        SimpleNamespace(
            data_root=data_root,
            package_dir=package_dir,
            seal=seal_path,
            machine_result=machine_path,
            locked_selection=selection_path,
        )
    )

    assert result["current_locked_gate_sha256"] == "c" * 64
    assert published == {
        "locked_selection": selection,
        "package_dir": package_dir,
        "seal_path": seal_path,
        "evaluation_path": evaluation_path,
        "expected_current_build_sha256": "d" * 64,
        "expected_settlement_contract_sha256": "e" * 64,
    }


@pytest.mark.parametrize(
    ("changed_field", "expected_message"),
    (
        ("source_build_sha256", "current build"),
        ("pipeline_fingerprint", "pipeline"),
        ("contract_canonical_sha256", "active settlement contract"),
        ("contract_file_sha256", "active settlement contract"),
        ("contract_selection_sha256", "active settlement contract"),
    ),
)
def test_locked_selection_loader_rejects_stale_current_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_field: str,
    expected_message: str,
) -> None:
    data_root = _path(tmp_path, "data")
    selection_root = data_root / "loop9-formal-selections"
    selection_root.mkdir(parents=True)
    selection_sha = "a" * 64
    selection_path = selection_root / f"{selection_sha}.json"
    selection_path.write_text("{}\n", encoding="utf-8")
    expected = {
        "source_build_sha256": "b" * 64,
        "pipeline_fingerprint": "c" * 64,
        "contract_canonical_sha256": "d" * 64,
        "contract_file_sha256": "e" * 64,
        "contract_selection_sha256": "f" * 64,
    }
    actual = dict(expected)
    actual[changed_field] = "0" * 64
    selection = SimpleNamespace(
        canonical_sha256=selection_sha,
        batch_manifest=SimpleNamespace(**actual),
    )

    class SelectionStore:
        def __init__(self, root: Path) -> None:
            assert root == data_root

        def load_active_current_locked_manifest(
            self,
            digest: str,
        ) -> object:
            assert digest == selection_sha
            return selection

    selected_contract = SimpleNamespace(
        manifest=SimpleNamespace(
            canonical_sha256=expected["contract_canonical_sha256"],
        ),
        contract_file_sha256=expected["contract_file_sha256"],
        selection_sha256=expected["contract_selection_sha256"],
    )
    monkeypatch.setattr(
        module,
        "FormalShadowSelectionStore",
        SelectionStore,
    )
    monkeypatch.setattr(
        module,
        "load_selected_live_read_contract",
        lambda _root: selected_contract,
    )
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: expected["source_build_sha256"],
    )
    monkeypatch.setattr(
        module,
        "current_template_pipeline_build_fingerprint",
        lambda **_kwargs: expected["pipeline_fingerprint"],
    )

    with pytest.raises(
        Loop9MachineResultError,
        match=expected_message,
    ):
        module._load_locked_selection(
            data_root=data_root,
            path=selection_path,
        )


@pytest.mark.parametrize(
    ("target_kind", "expected_loader"),
    (
        (
            ShadowBatchTargetKind.CURRENT_LOCKED_50,
            "current_locked",
        ),
        (
            ShadowBatchTargetKind.REAL_SHADOW_30,
            "real_shadow",
        ),
    ),
)
def test_run_selection_loader_requires_exact_active_selection_and_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_kind: ShadowBatchTargetKind,
    expected_loader: str,
) -> None:
    data_root = _path(tmp_path, "data")
    selection_root = data_root / "loop9-formal-selections"
    selection_root.mkdir(parents=True)
    selection_sha = "a" * 64
    selection_path = selection_root / f"{selection_sha}.json"
    selection_path.write_text("{}\n", encoding="utf-8")
    batch = SimpleNamespace(
        target_kind=target_kind,
        canonical_sha256="b" * 64,
    )
    selection = SimpleNamespace(
        target_kind=target_kind,
        canonical_sha256=selection_sha,
        batch_manifest=SimpleNamespace(
            canonical_sha256=batch.canonical_sha256,
        ),
    )
    calls: list[str] = []

    class SelectionStore:
        def __init__(self, root: Path) -> None:
            assert root == data_root

        def load_active_current_locked_manifest(
            self,
            digest: str,
        ) -> object:
            assert digest == selection_sha
            calls.append("current_locked")
            return selection

        def load_active_real_shadow_manifest(
            self,
            digest: str,
            *,
            expected_current_build_sha256: str,
            expected_settlement_contract_sha256: str,
        ) -> object:
            assert digest == selection_sha
            assert expected_current_build_sha256 == "c" * 64
            assert expected_settlement_contract_sha256 == "d" * 64
            calls.append("real_shadow")
            return selection

    monkeypatch.setattr(
        module,
        "FormalShadowSelectionStore",
        SelectionStore,
    )
    monkeypatch.setattr(
        module,
        "_verify_current_selection_authority",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: "c" * 64,
    )
    monkeypatch.setattr(
        module,
        "load_selected_live_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(canonical_sha256="d" * 64),
        ),
    )

    loaded = module._load_active_run_selection(
        data_root=data_root,
        path=selection_path,
        batch=batch,
    )

    assert loaded is selection
    assert calls == [expected_loader]

    selection.batch_manifest.canonical_sha256 = "0" * 64
    with pytest.raises(
        Loop9MachineResultError,
        match="does not own",
    ):
        module._load_active_run_selection(
            data_root=data_root,
            path=selection_path,
            batch=batch,
        )


def test_current_locked_evaluate_requires_exact_selection_even_when_gate_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = _path(tmp_path, "data")
    data_root.mkdir()
    package_dir = _path(tmp_path, "package")
    package_dir.mkdir()
    seal_path = _path(tmp_path, "seal.json")
    seal_path.write_text("{}\n", encoding="utf-8")
    machine_path = _path(tmp_path, "machine.json")
    machine_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "evaluate_sealed_machine_results",
        lambda **_kwargs: {
            "canonical_sha256": "b" * 64,
            "gate_passed": False,
            "review_kind": "current_locked_50",
        },
    )

    with pytest.raises(
        Loop9MachineResultError,
        match="locked-selection",
    ):
        module._evaluate(
            SimpleNamespace(
                data_root=data_root,
                package_dir=package_dir,
                seal=seal_path,
                machine_result=machine_path,
                locked_selection=None,
            )
        )


def test_real_shadow_evaluate_rejects_locked_selection_argument(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = _path(tmp_path, "data")
    data_root.mkdir()
    package_dir = _path(tmp_path, "package")
    package_dir.mkdir()
    seal_path = _path(tmp_path, "seal.json")
    seal_path.write_text("{}\n", encoding="utf-8")
    machine_path = _path(tmp_path, "machine.json")
    machine_path.write_text("{}\n", encoding="utf-8")
    selection_path = _path(tmp_path, "selection.json")
    selection_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "evaluate_sealed_machine_results",
        lambda **_kwargs: {
            "canonical_sha256": "b" * 64,
            "gate_passed": True,
            "review_kind": "real_shadow_30",
        },
    )

    with pytest.raises(
        Loop9MachineResultError,
        match="only valid",
    ):
        module._evaluate(
            SimpleNamespace(
                data_root=data_root,
                package_dir=package_dir,
                seal=seal_path,
                machine_result=machine_path,
                locked_selection=selection_path,
            )
        )


def test_current_locked_run_rejects_missing_human_truth_seal_before_ocr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dahe.application.chengfeng.shadow_batch import (
        ShadowBatchTargetKind,
    )

    data_root = _path(tmp_path, "data")
    data_root.mkdir()
    batch = SimpleNamespace(
        target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
    )
    monkeypatch.setattr(
        module,
        "prepare_startup_environment",
        lambda config, root: data_root,
    )
    monkeypatch.setattr(
        module,
        "_load_batch",
        lambda **kwargs: batch,
    )

    with pytest.raises(Loop9MachineResultError, match="package-dir"):
        module._run(
            SimpleNamespace(
                data_root=data_root,
                source_batch=_path(tmp_path, "batch.json"),
                job_id="job-001",
                timeout_seconds=180.0,
                package_dir=None,
                seal=None,
            )
        )
