from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import loop7_candidate_template_seed as module


def _arguments(tmp_path: Path) -> list[str]:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    evidence = (tmp_path / "evidence.json").resolve()
    evidence.write_text("{}", encoding="utf-8")
    definition = (tmp_path / "definition.json").resolve()
    definition.write_text("{}", encoding="utf-8")
    return [
        "--data-root",
        str(data_root),
        "--evidence",
        str(evidence),
        "--evidence-sha256",
        "a" * 64,
        "--sample-id",
        "L7-002",
        "--submitted-slot",
        "loading",
        "--expected-role",
        "loading",
        "--definition",
        str(definition),
        "--actor-id",
        "developer-a",
        "--idempotency-key",
        "candidate-template-seed-1",
    ]


def test_cli_requires_explicit_absolute_paths(
    tmp_path: Path,
) -> None:
    arguments = _arguments(tmp_path)
    arguments[1] = "relative-data"

    with pytest.raises(SystemExit):
        module.main(arguments)


def test_cli_forwards_an_explicit_source_without_printing_ocr_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured: dict[str, object] = {}

    def fake_run(arguments: object) -> int:
        captured.update(vars(arguments))
        print(
            json.dumps(
                {
                    "created": True,
                    "family_id": "candidate-loading-family",
                    "origin_sha256": "b" * 64,
                    "role": "loading",
                    "version_id": "c" * 32,
                }
            )
        )
        return 0

    monkeypatch.setattr(module, "_run", fake_run)

    assert module.main(_arguments(tmp_path)) == 0
    output = capsys.readouterr().out
    assert captured["sample_id"] == "L7-002"
    assert captured["submitted_slot"] == "loading"
    assert captured["expected_role"] == "loading"
    assert "ordinary_net" not in output
    assert "text_lines" not in output
    assert "L7-002" not in output


def test_cli_rejects_abbreviated_options(
    tmp_path: Path,
) -> None:
    arguments = _arguments(tmp_path)
    arguments[0] = "--data"

    with pytest.raises(SystemExit):
        module.main(arguments)
