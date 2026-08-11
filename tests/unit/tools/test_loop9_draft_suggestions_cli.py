from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
TOOL_PATH = ROOT / "tools" / "loop9_draft_suggestions.py"


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "loop9_draft_suggestions_tool",
        TOOL_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_cli_requires_absolute_paths() -> None:
    tool = _load_tool()

    with pytest.raises(SystemExit):
        tool._parser().parse_args(
            [
                "init",
                "--data-root",
                "relative",
                "--formal-selection",
                "relative.json",
                "--source-batch",
                "relative.json",
                "--output",
                "relative.json",
            ]
        )


def test_cli_refuses_non_project_python(monkeypatch: pytest.MonkeyPatch) -> None:
    tool = _load_tool()
    monkeypatch.setattr(tool.sys, "executable", sys.executable)
    monkeypatch.setattr(
        tool,
        "EXPECTED_MAIN_PYTHON",
        (ROOT / "not-the-running-python.exe").resolve(),
    )

    with pytest.raises(SystemExit, match=r"project \.venv"):
        tool.main([])


def test_cli_init_and_seal_use_current_authority_and_refuse_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _load_tool()
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    selection_path = (tmp_path / "selection.json").resolve()
    selection_path.write_text("{}", encoding="utf-8")
    batch_path = (tmp_path / "batch.json").resolve()
    batch_path.write_text("{}", encoding="utf-8")
    draft_path = (tmp_path / "draft.json").resolve()
    auxiliary_path = (tmp_path / "auxiliary.json").resolve()
    selection = object()
    batch = object()
    blank = {"kind": "blank", "canonical_sha256": "a" * 64}
    sealed = {"kind": "sealed", "canonical_sha256": "b" * 64}

    monkeypatch.setattr(tool.sys, "executable", tool.EXPECTED_MAIN_PYTHON)
    monkeypatch.setattr(
        tool,
        "_load_current_locked_authority",
        lambda **kwargs: (selection, batch),
    )
    monkeypatch.setattr(
        tool,
        "build_blank_draft_template",
        lambda **kwargs: blank,
    )
    monkeypatch.setattr(
        tool,
        "seal_independent_draft_suggestions",
        lambda **kwargs: sealed,
    )
    monkeypatch.setattr(
        tool,
        "load_draft_document",
        lambda path: blank,
    )

    assert (
        tool.main(
            [
                "init",
                "--data-root",
                str(data_root),
                "--formal-selection",
                str(selection_path),
                "--source-batch",
                str(batch_path),
                "--output",
                str(draft_path),
            ]
        )
        == 0
    )
    assert draft_path.is_file()

    assert (
        tool.main(
            [
                "seal",
                "--data-root",
                str(data_root),
                "--formal-selection",
                str(selection_path),
                "--source-batch",
                str(batch_path),
                "--draft",
                str(draft_path),
                "--output",
                str(auxiliary_path),
            ]
        )
        == 0
    )
    assert auxiliary_path.is_file()

    with pytest.raises(SystemExit, match="already exists"):
        tool.main(
            [
                "init",
                "--data-root",
                str(data_root),
                "--formal-selection",
                str(selection_path),
                "--source-batch",
                str(batch_path),
                "--output",
                str(draft_path),
            ]
        )


def test_current_authority_loader_requires_active_selection_and_current_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = _load_tool()
    data_root = (tmp_path / "data").resolve()
    selection_root = data_root / "loop9-formal-selections"
    batch_root = data_root / "chengfeng-shadow-batches"
    selection_root.mkdir(parents=True)
    batch_root.mkdir()
    selection = SimpleNamespace(canonical_sha256="a" * 64)
    batch = SimpleNamespace(
        canonical_sha256="b" * 64,
        source_build_sha256="c" * 64,
        pipeline_fingerprint="d" * 64,
        contract_canonical_sha256="e" * 64,
        contract_file_sha256="f" * 64,
        contract_selection_sha256="1" * 64,
    )
    selection_path = selection_root / f"{selection.canonical_sha256}.json"
    selection_path.write_text("{}", encoding="utf-8")
    batch_path = batch_root / f"{batch.canonical_sha256}.json"
    batch_path.write_text("{}", encoding="utf-8")
    active_calls: list[str] = []

    class _SelectionStore:
        def __init__(self, root: Path) -> None:
            assert root == data_root

        def load_active_current_locked_manifest(self, value: str) -> object:
            active_calls.append(value)
            return selection

    class _BatchStore:
        def __init__(self, root: Path) -> None:
            assert root == batch_root

        def load(self, value: str) -> object:
            assert value == batch.canonical_sha256
            return batch

    selected_contract = SimpleNamespace(
        manifest=SimpleNamespace(
            canonical_sha256=batch.contract_canonical_sha256
        ),
        contract_file_sha256=batch.contract_file_sha256,
        selection_sha256=batch.contract_selection_sha256,
    )
    monkeypatch.setattr(tool, "FormalShadowSelectionStore", _SelectionStore)
    monkeypatch.setattr(tool, "ShadowBatchManifestStore", _BatchStore)
    monkeypatch.setattr(
        tool,
        "load_selected_live_read_contract",
        lambda root: selected_contract,
    )
    monkeypatch.setattr(
        tool,
        "current_loop9_build_sha256",
        lambda root: batch.source_build_sha256,
    )
    monkeypatch.setattr(
        tool,
        "current_template_pipeline_build_fingerprint",
        lambda **kwargs: batch.pipeline_fingerprint,
    )
    monkeypatch.setattr(
        tool,
        "verify_current_locked_source_binding",
        lambda **kwargs: None,
    )

    loaded_selection, loaded_batch = tool._load_current_locked_authority(
        data_root=data_root,
        formal_selection_path=selection_path,
        source_batch_path=batch_path,
    )

    assert loaded_selection is selection
    assert loaded_batch is batch
    assert active_calls == [selection.canonical_sha256]

    monkeypatch.setattr(
        tool,
        "current_loop9_build_sha256",
        lambda root: "0" * 64,
    )
    with pytest.raises(
        tool.Loop9DraftSuggestionError,
        match="current authority",
    ):
        tool._load_current_locked_authority(
            data_root=data_root,
            formal_selection_path=selection_path,
            source_batch_path=batch_path,
        )
