from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import loop7_candidate_role_evaluation as module


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _arguments(
    *,
    data_root: Path,
    evidence: Path,
    output: Path,
) -> list[str]:
    return [
        "--data-root",
        str(data_root),
        "--ocr-evidence",
        str(evidence),
        "--candidate-version",
        "candidate-loading",
        "--candidate-version",
        "candidate-unloading",
        "--output",
        str(output),
    ]


def test_parser_requires_absolute_paths_and_candidate_versions(
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit) as relative_error:
        module._parser().parse_args(
            [
                "--data-root",
                "relative",
                "--ocr-evidence",
                str((tmp_path / "evidence.json").resolve()),
                "--candidate-version",
                "candidate",
                "--output",
                str((tmp_path / "out.json").resolve()),
            ]
        )
    with pytest.raises(SystemExit) as missing_candidate:
        module._parser().parse_args(
            [
                "--data-root",
                str((tmp_path / "data").resolve()),
                "--ocr-evidence",
                str((tmp_path / "evidence.json").resolve()),
                "--output",
                str((tmp_path / "out.json").resolve()),
            ]
        )

    assert relative_error.value.code == 2
    assert missing_candidate.value.code == 2


def test_evidence_must_be_a_content_addressed_protected_record(
    tmp_path: Path,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    evidence = (tmp_path / "outside.json").resolve()
    evidence.write_text("{}\n", encoding="utf-8")

    with pytest.raises(
        module.CandidateRoleEvaluationToolError,
        match="protected",
    ):
        module._validate_evidence_path(
            evidence,
            data_root=data_root,
        )


def test_runtime_contract_requires_qualified_cpu_and_gpu() -> None:
    identities = {
        "cpu": SimpleNamespace(
            profile_id="cpu-profile",
            runtime_fingerprint=_sha256("cpu-runtime"),
            runtime_kind="cpu",
        ),
        "gpu": SimpleNamespace(
            profile_id="gpu-profile",
            runtime_fingerprint=_sha256("gpu-runtime"),
            runtime_kind="gpu",
        ),
    }

    class FakeBackend:
        def __init__(self, available: set[str]) -> None:
            self.available = available

        def has_runtime(self, runtime_kind: str) -> bool:
            return runtime_kind in self.available

        def identity_for(self, runtime_kind: str) -> object:
            return identities[runtime_kind]

    expected = module.current_template_ocr_runtime_set_fingerprint(
        [
            {
                "profile_id": identity.profile_id,
                "runtime_fingerprint": identity.runtime_fingerprint,
                "runtime_kind": identity.runtime_kind,
            }
            for identity in identities.values()
        ]
    )

    assert (
        module._qualified_runtime_fingerprint(
            FakeBackend({"cpu", "gpu"})
        )
        == expected
    )
    with pytest.raises(
        module.CandidateRoleEvaluationToolError,
        match="CPU and GPU",
    ):
        module._qualified_runtime_fingerprint(FakeBackend({"cpu"}))


def test_run_loads_templates_under_one_guard_and_writes_exclusive_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_root = (tmp_path / "data").resolve()
    evidence_sha256 = _sha256("ocr-evidence")
    evidence = (
        data_root
        / "development"
        / "protected-candidate-review-ocr"
        / "records"
        / "sha256"
        / evidence_sha256[:2]
        / evidence_sha256[2:4]
        / f"{evidence_sha256}.json"
    )
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")
    output = (tmp_path / "output" / "evaluation.json").resolve()
    calls: list[str] = []
    build_sha256 = _sha256("role-evaluator-build")
    runtime_sha256 = _sha256("runtime-set")
    manifest_sha256 = _sha256("authorizing-manifest")
    matcher_sha256 = _sha256("matcher")
    policy_sha256 = _sha256("policy")

    class FakeGuard:
        instance_id = "guard-instance"

        def __init__(
            self,
            root: Path,
            port: int,
            version: str,
        ) -> None:
            del port, version
            assert root == data_root

        def __enter__(self) -> FakeGuard:
            calls.append("guard-enter")
            return self

        def __exit__(
            self,
            exc_type: object,
            exc_value: object,
            traceback: object,
        ) -> None:
            del exc_type, exc_value, traceback
            calls.append("guard-exit")

    class FakeRuntime:
        def __init__(
            self,
            *,
            data_root: Path,
            project_root: Path,
            instance_id: str,
        ) -> None:
            del project_root
            assert data_root == globals_data_root
            assert instance_id == "guard-instance"
            calls.append("runtime-open")

        def close(self) -> None:
            calls.append("runtime-close")

    globals_data_root = data_root

    class FakeBackend:
        def close(self) -> None:
            calls.append("backend-close")

    class FakeRepository:
        def __init__(
            self,
            *,
            runtime: object,
            accepted_build_fingerprint: str,
            accepted_runtime_fingerprint: str,
            accepted_development_manifest_sha256: str,
            accepted_matcher_fingerprint: str,
            accepted_policy_fingerprint: str,
        ) -> None:
            del runtime
            assert accepted_build_fingerprint == build_sha256
            assert accepted_runtime_fingerprint == runtime_sha256
            assert (
                accepted_development_manifest_sha256
                == manifest_sha256
            )
            assert accepted_matcher_fingerprint == matcher_sha256
            assert accepted_policy_fingerprint == policy_sha256

        def get_version(self, version_id: str) -> object:
            calls.append(f"candidate:{version_id}")
            return SimpleNamespace(version_id=version_id)

        def list_current_eligible_shadow_versions(
            self,
        ) -> tuple[object, ...]:
            calls.append("shadows")
            return ()

    report_payload: dict[str, object] = {
        "authorizing_lifecycle_evidence": False,
        "cpu_gpu_role_consistency": {
            "agreement_rate": "1",
            "match_count": 100,
            "mismatch_count": 0,
            "mismatches": [],
            "sample_count": 100,
        },
        "development_only": True,
        "evaluation_sha256": _sha256("evaluation"),
        "formal_accuracy_claim": False,
        "formal_release_eligible": False,
        "kind": "candidate_review_development_role_template_evaluation",
        "runtimes": {
            "cpu": {"sample_count": 100},
            "gpu": {"sample_count": 100},
        },
        "schema_version": 1,
        "source": {
            "ocr_evidence_sha256": evidence_sha256,
        },
        "status": "completed",
        "template_contract": {
            "candidate_count": 2,
        },
    }

    def evaluate(
        path: Path,
        *,
        data_root: Path,
        candidates: tuple[object, ...],
        current_shadow: tuple[object, ...],
        role_evaluator_build_sha256: str,
    ) -> object:
        assert path == evidence
        assert data_root == globals_data_root
        assert tuple(candidate.version_id for candidate in candidates) == (
            "candidate-loading",
            "candidate-unloading",
        )
        assert current_shadow == ()
        assert len(role_evaluator_build_sha256) == 64
        calls.append("evaluate")
        return SimpleNamespace(
            payload=report_payload,
            evaluation_sha256=report_payload["evaluation_sha256"],
        )

    monkeypatch.setattr(module, "SingleInstanceGuard", FakeGuard)
    monkeypatch.setattr(
        module,
        "prepare_startup_environment",
        lambda config, root: Path(config.data_root),
    )
    monkeypatch.setattr(module, "SqliteRuntime", FakeRuntime)
    monkeypatch.setattr(module, "SqliteTemplateRepository", FakeRepository)
    monkeypatch.setattr(
        module,
        "build_ocr_execution_backend",
        lambda **kwargs: calls.append("backend-open")
        or FakeBackend(),
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "_qualified_runtime_fingerprint",
        lambda backend: runtime_sha256,
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "current_template_pipeline_build_fingerprint",
        lambda **kwargs: build_sha256,
    )
    monkeypatch.setattr(
        module,
        "load_approved_authorizing_development_dataset",
        lambda path: SimpleNamespace(
            manifest_sha256=manifest_sha256
        ),
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "development_matcher_fingerprint",
        lambda: matcher_sha256,
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "development_policy_fingerprint",
        lambda: policy_sha256,
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "evaluate_candidate_development_roles_from_path",
        evaluate,
    )

    assert (
        module.main(
            _arguments(
                data_root=data_root,
                evidence=evidence,
                output=output,
            )
        )
        == 0
    )

    assert calls == [
        "guard-enter",
        "runtime-open",
        "backend-open",
        "candidate:candidate-loading",
        "candidate:candidate-unloading",
        "shadows",
        "evaluate",
        "runtime-close",
        "backend-close",
        "guard-exit",
    ]
    assert json.loads(output.read_text(encoding="utf-8")) == (report_payload)
    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "cpu_gpu_role_agreement_rate": "1",
        "development_only": True,
        "evaluation_sha256": _sha256("evaluation"),
        "formal_release_eligible": False,
        "runtime_sample_count": {
            "cpu": 100,
            "gpu": 100,
        },
        "status": "completed",
    }

    with pytest.raises(
        module.CandidateRoleEvaluationToolError,
        match="already exists",
    ):
        module._run(
            module._parser().parse_args(
                _arguments(
                    data_root=data_root,
                    evidence=evidence,
                    output=output,
                )
            )
        )


def test_tool_cannot_enter_formal_or_human_review_paths() -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")

    for forbidden in (
        "formal_locked_set_release",
        "locked_set_acceptance",
        "record_frozen_development_evaluation",
        "SqliteLockedSetRepository",
        "waiting_user",
        "awaiting_review",
        "web_weight",
        "platform_weight",
    ):
        assert forbidden not in source
