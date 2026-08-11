from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import loop9_human_review as module


def _path(tmp_path: Path, name: str) -> Path:
    return (tmp_path / name).resolve()


def test_prepare_cli_requires_absolute_inputs_and_delegates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs = {
        name: _path(tmp_path, f"{name}.json")
        for name in ("source", "dataset", "auxiliary")
    }
    for path in inputs.values():
        path.write_text("{}", encoding="utf-8")
    image_root = _path(tmp_path, "images")
    image_root.mkdir()
    output_dir = _path(tmp_path, "package")
    data_root = _path(tmp_path, "data")
    data_root.mkdir()
    formal_selection = _path(tmp_path, "selection.json")
    formal_selection.write_text("{}", encoding="utf-8")
    selection = object()
    received: dict[str, object] = {}

    def prepare(**values: object) -> object:
        received.update(values)
        output_dir.mkdir()
        return SimpleNamespace(
            payload={
                "canonical_sha256": "a" * 64,
                "review_kind": "current_locked_50",
            }
        )

    monkeypatch.setattr(module, "prepare_loop9_review_package", prepare)
    monkeypatch.setattr(
        module,
        "_load_active_selection",
        lambda **values: selection,
    )
    assert (
        module.main(
            [
                "prepare",
                "--data-root",
                str(data_root),
                "--source-batch",
                str(inputs["source"]),
                "--dataset-manifest",
                str(inputs["dataset"]),
                "--formal-selection",
                str(formal_selection),
                "--image-root",
                str(image_root),
                "--auxiliary",
                str(inputs["auxiliary"]),
                "--output-dir",
                str(output_dir),
            ]
        )
        == 0
    )
    assert received == {
        "source_batch_path": inputs["source"],
        "dataset_manifest_path": inputs["dataset"],
        "formal_selection": selection,
        "image_root": image_root,
        "auxiliary_path": inputs["auxiliary"],
        "output_dir": output_dir,
    }
    assert json.loads(capsys.readouterr().out) == {
        "canonical_sha256": "a" * 64,
        "output": "package",
        "review_kind": "current_locked_50",
    }

    relative = [
        "prepare",
        "--data-root",
        str(data_root),
        "--source-batch",
        "relative.json",
        "--dataset-manifest",
        str(inputs["dataset"]),
        "--formal-selection",
        str(formal_selection),
        "--image-root",
        str(image_root),
        "--auxiliary",
        str(inputs["auxiliary"]),
        "--output-dir",
        str(_path(tmp_path, "other")),
    ]
    with pytest.raises(SystemExit):
        module.main(relative)


def test_seal_and_replay_cli_write_exclusive_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    package_dir = _path(tmp_path, "package")
    package_dir.mkdir()
    data_root = _path(tmp_path, "data")
    data_root.mkdir()
    answers = _path(tmp_path, "answers.json")
    answers.write_text("{}", encoding="utf-8")
    seal_output = _path(tmp_path, "seal.json")
    calls: list[tuple[str, dict[str, object]]] = []

    def seal(**values: object) -> dict[str, object]:
        calls.append(("seal", values))
        payload = {
            "schema_version": 1,
            "kind": "loop9_human_review_seal",
            "canonical_sha256": "b" * 64,
        }
        seal_output.write_text(json.dumps(payload), encoding="utf-8")
        return payload

    monkeypatch.setattr(module, "seal_loop9_review", seal)
    verified: list[tuple[Path, Path]] = []
    monkeypatch.setattr(
        module,
        "_verify_active_package_authority",
        lambda *, data_root, package_dir: verified.append(
            (data_root, package_dir)
        ),
    )
    assert (
        module.main(
            [
                "seal",
                "--data-root",
                str(data_root),
                "--package-dir",
                str(package_dir),
                "--review-answers",
                str(answers),
                "--output",
                str(seal_output),
            ]
        )
        == 0
    )
    assert calls == [
        (
            "seal",
            {
                "package_dir": package_dir,
                "review_answers_path": answers,
                "output_path": seal_output,
            },
        )
    ]
    assert verified == [(data_root, package_dir)]
    assert json.loads(capsys.readouterr().out)["canonical_sha256"] == "b" * 64

    isolation = _path(tmp_path, "isolation.json")
    isolation.write_text("{}", encoding="utf-8")
    replay_output = _path(tmp_path, "replay.json")
    replay_payload = {
        "schema_version": 1,
        "kind": "loop9_human_review_replay",
        "canonical_sha256": "c" * 64,
    }

    def replay(**values: object) -> dict[str, object]:
        calls.append(("replay", values))
        return replay_payload

    written: dict[str, object] = {}

    def write(*, output_path: Path, payload: dict[str, object]) -> None:
        written["output_path"] = output_path
        written["payload"] = payload
        output_path.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(module, "replay_loop9_review", replay)
    monkeypatch.setattr(module, "write_loop9_review_evidence", write)
    assert (
        module.main(
            [
                "replay",
                "--data-root",
                str(data_root),
                "--package-dir",
                str(package_dir),
                "--seal",
                str(seal_output),
                "--isolation-evidence",
                str(isolation),
                "--output",
                str(replay_output),
            ]
        )
        == 0
    )
    assert calls[-1] == (
        "replay",
        {
            "package_dir": package_dir,
            "seal_path": seal_output,
            "isolation_evidence_path": isolation,
        },
    )
    assert verified == [
        (data_root, package_dir),
        (data_root, package_dir),
    ]
    assert written == {
        "output_path": replay_output,
        "payload": replay_payload,
    }
    assert json.loads(capsys.readouterr().out) == {
        "canonical_sha256": "c" * 64,
        "output": "replay.json",
        "replay_passed": True,
    }


def test_cli_rejects_abbreviated_options(
    tmp_path: Path,
) -> None:
    package_dir = _path(tmp_path, "package")
    package_dir.mkdir()
    answers = _path(tmp_path, "answers.json")
    answers.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit):
        module.main(
            [
                "seal",
                "--package",
                str(package_dir),
                "--review-answers",
                str(answers),
                "--output",
                str(_path(tmp_path, "seal.json")),
            ]
        )
