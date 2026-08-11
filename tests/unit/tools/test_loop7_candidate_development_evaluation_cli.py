from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import loop7_candidate_development_evaluation as module


def _arguments(
    *,
    review_data_root: Path,
    data_root: Path,
    output: Path,
) -> list[str]:
    return [
        "--review-data-root",
        str(review_data_root),
        "--data-root",
        str(data_root),
        "--reviewer-id",
        "operator-a",
        "--output",
        str(output),
    ]


def test_parser_requires_absolute_distinct_roots_and_new_json_output(
    tmp_path: Path,
) -> None:
    parser = module._parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--review-data-root",
                "relative-review",
                "--data-root",
                str((tmp_path / "target").resolve()),
                "--reviewer-id",
                "operator-a",
                "--output",
                str((tmp_path / "summary.json").resolve()),
            ]
        )

    review_root = (tmp_path / "review").resolve()
    review_root.mkdir()
    output = (tmp_path / "summary.json").resolve()
    output.write_text("existing", encoding="utf-8")
    with pytest.raises(
        module.CandidateDevelopmentEvaluationToolError,
        match="already exists",
    ):
        module._run(
            parser.parse_args(
                _arguments(
                    review_data_root=review_root,
                    data_root=(tmp_path / "target").resolve(),
                    output=output,
                )
            )
        )

    with pytest.raises(
        module.CandidateDevelopmentEvaluationToolError,
        match="independent",
    ):
        module._run(
            parser.parse_args(
                _arguments(
                    review_data_root=review_root,
                    data_root=review_root / "nested-target",
                    output=(tmp_path / "new-summary.json").resolve(),
                )
            )
        )


@pytest.mark.parametrize(
    ("evaluation_status", "expected_exit"),
    [
        ("completed_with_runtime_differences", 0),
        ("failed", 1),
    ],
)
def test_run_uses_both_instance_guards_factory_backend_and_exclusive_redacted_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    evaluation_status: str,
    expected_exit: int,
) -> None:
    review_root = (tmp_path / "review-data").resolve()
    review_root.mkdir()
    target_root = (tmp_path / "development-data").resolve()
    output = (tmp_path / "summary.json").resolve()
    arguments = module._parser().parse_args(
        _arguments(
            review_data_root=review_root,
            data_root=target_root,
            output=output,
        )
    )
    calls: dict[str, object] = {
        "guards": [],
        "closed": False,
        "runtime_closed": False,
    }

    def prepare(config: object, repository_root: Path) -> Path:
        del config, repository_root
        target_root.mkdir()
        return target_root

    class Guard:
        def __init__(
            self,
            data_root: Path,
            port: int,
            application_version: str,
        ) -> None:
            del port, application_version
            self.data_root = data_root
            self.instance_id = f"instance-{len(calls['guards'])}"

        def __enter__(self) -> Guard:
            guards = calls["guards"]
            assert isinstance(guards, list)
            guards.append(self.data_root)
            return self

        def __exit__(self, *args: object) -> None:
            del args

    context = SimpleNamespace(
        package=SimpleNamespace(
            review_root=review_root / "locked-set-review",
        ),
        authority=object(),
        review_export=object(),
    )
    backend = SimpleNamespace(close=lambda: calls.__setitem__("closed", True))

    class Runtime:
        def __init__(self, **kwargs: object) -> None:
            calls["runtime"] = kwargs

        def close(self) -> None:
            calls["runtime_closed"] = True

    class RunRepository:
        def __init__(self, *, runtime: object) -> None:
            calls["run_repository_runtime"] = runtime

    def build_context(**kwargs: object) -> object:
        calls["context"] = kwargs
        return context

    def build_backend(**kwargs: object) -> object:
        calls["backend"] = kwargs
        return backend

    summary = {
        "schema_version": 1,
        "kind": "candidate_review_development_ocr_summary",
        "status": evaluation_status,
        "development_only": True,
        "formal_accuracy_claim": False,
        "formal_release_eligible": False,
        "image_count": 100,
        "runtime_execution_count": 200,
        "technical_failure_count": (1 if evaluation_status == "failed" else 0),
        "evidence_sha256": "a" * 64,
    }

    def run_evaluation(**kwargs: object) -> object:
        calls["evaluation"] = kwargs
        return SimpleNamespace(
            status=evaluation_status,
            summary_payload=summary,
            evidence_path=(
                target_root
                / "development"
                / "protected-candidate-review-ocr"
                / "records"
                / "sha256"
                / "aa"
                / "aa"
                / f"{'a' * 64}.json"
            ),
        )

    def record_authority(
        repository: object,
        **kwargs: object,
    ) -> object:
        calls["authority"] = {
            "repository": repository,
            **kwargs,
        }
        return object(), True

    monkeypatch.setattr(module, "prepare_startup_environment", prepare)
    monkeypatch.setattr(module, "SingleInstanceGuard", Guard)
    monkeypatch.setattr(module, "SqliteRuntime", Runtime)
    monkeypatch.setattr(
        module,
        "SqliteCandidateDevelopmentOcrRunRepository",
        RunRepository,
    )
    monkeypatch.setattr(module, "_build_review_context", build_context)
    monkeypatch.setattr(module, "build_ocr_execution_backend", build_backend)
    monkeypatch.setattr(
        module,
        "run_candidate_development_ocr_evaluation",
        run_evaluation,
    )
    monkeypatch.setattr(
        module,
        "record_candidate_development_ocr_terminal_attempt",
        record_authority,
    )

    assert module._run(arguments) == expected_exit
    assert calls["guards"] == [review_root, target_root]
    assert calls["closed"] is True
    assert calls["runtime_closed"] is True
    assert output.is_file()
    assert json.loads(output.read_text(encoding="utf-8")) == summary
    context_call = calls["context"]
    assert isinstance(context_call, dict)
    assert context_call["review_data_root"] == review_root
    assert context_call["configured_reviewer_id"] == "operator-a"
    evaluation_call = calls["evaluation"]
    assert isinstance(evaluation_call, dict)
    assert evaluation_call["data_root"] == target_root
    assert evaluation_call["reviewer_id"] == "operator-a"
    runtime_call = calls["runtime"]
    assert isinstance(runtime_call, dict)
    assert runtime_call["data_root"] == target_root
    authority_call = calls["authority"]
    assert isinstance(authority_call, dict)
    assert authority_call["data_root"] == target_root

    with pytest.raises(
        module.CandidateDevelopmentEvaluationToolError,
        match="already exists",
    ):
        module._run(arguments)


def test_tool_does_not_import_or_evaluate_the_formal_locked_set() -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")

    assert "locked_set_runner" not in source
    assert "locked_set_acceptance" not in source
    assert "SqliteLockedSetRepository" not in source
    assert "register_locked" not in source
    assert "Chengfeng" not in source
    assert "formal_accuracy_claim" not in source
