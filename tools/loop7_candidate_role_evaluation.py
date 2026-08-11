from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

from dahe import __version__
from dahe.adapters.ocr.runtime_factory import build_ocr_execution_backend
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplatePersistenceError,
)
from dahe.application.template_studio.authorizing_registry import (
    approved_authorizing_development_dataset_path,
    load_approved_authorizing_development_dataset,
)
from dahe.application.template_studio.candidate_development_ocr import (
    CANDIDATE_DEVELOPMENT_OCR_PROTECTED_ROOT_NAME,
)
from dahe.application.template_studio.candidate_role_evaluation import (
    CandidateRoleEvaluationError,
    evaluate_candidate_development_roles_from_path,
)
from dahe.application.template_studio.development_evaluation import (
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.fingerprints import (
    current_template_ocr_runtime_set_fingerprint,
    current_template_pipeline_build_fingerprint,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    RuntimeKindName,
)
from dahe.system.instance_lock import SingleInstanceGuard

ROOT = Path(__file__).resolve().parents[1]
_RUNTIME_KINDS: tuple[RuntimeKindName, ...] = ("cpu", "gpu")


class CandidateRoleEvaluationToolError(RuntimeError):
    """Raised when the development-only role evaluator is unsafe."""


def _absolute_path(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(candidate)))


def _version_id(value: str) -> str:
    normalized = value.strip()
    if not normalized or normalized != value or len(normalized) > 32:
        raise argparse.ArgumentTypeError("candidate version ID is invalid")
    return normalized


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the completed candidate-review development OCR "
            "against explicit local template candidates."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--ocr-evidence",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--candidate-version",
        action="append",
        dest="candidate_versions",
        type=_version_id,
        required=True,
    )
    parser.add_argument(
        "--output",
        type=_absolute_path,
        required=True,
    )
    return parser


def _same_or_descendant(
    path: Path,
    root: Path,
) -> bool:
    try:
        common = os.path.commonpath((os.fspath(path), os.fspath(root)))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(os.fspath(root))


def _validate_evidence_path(
    path: Path,
    *,
    data_root: Path,
) -> Path:
    try:
        resolved_root = data_root.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateRoleEvaluationToolError("protected OCR evidence is unavailable") from exc
    protected_root = (
        resolved_root
        / "development"
        / CANDIDATE_DEVELOPMENT_OCR_PROTECTED_ROOT_NAME
        / "records"
        / "sha256"
    )
    if (
        data_root != resolved_root
        or path != resolved
        or not resolved.is_file()
        or not _same_or_descendant(
            resolved,
            protected_root,
        )
    ):
        raise CandidateRoleEvaluationToolError(
            "OCR evidence must be a protected development record"
        )
    digest = resolved.stem
    if (
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or resolved.suffix.lower() != ".json"
        or resolved.parent != protected_root / digest[:2] / digest[2:4]
    ):
        raise CandidateRoleEvaluationToolError(
            "protected OCR evidence path is not content-addressed"
        )
    return resolved


def _validate_output(
    path: Path,
    *,
    data_root: Path,
) -> Path:
    if not path.is_absolute():
        raise CandidateRoleEvaluationToolError("output path must be absolute")
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise CandidateRoleEvaluationToolError("output path cannot be resolved safely") from exc
    if resolved.suffix.lower() != ".json":
        raise CandidateRoleEvaluationToolError("output path must use the .json extension")
    if resolved.exists() or resolved.is_symlink():
        raise CandidateRoleEvaluationToolError("output already exists; choose a new JSON path")
    if _same_or_descendant(resolved, data_root):
        raise CandidateRoleEvaluationToolError("output must stay outside application data")
    return resolved


def _write_exclusive_json(
    path: Path,
    payload: dict[str, object],
    *,
    data_root: Path,
) -> None:
    target = _validate_output(
        path,
        data_root=data_root,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    staged = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        with staged.open(
            "x",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            json.dump(
                payload,
                handle,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, target)
        except FileExistsError as exc:
            raise CandidateRoleEvaluationToolError(
                "output appeared during write; no file was replaced"
            ) from exc
        except OSError as exc:
            raise CandidateRoleEvaluationToolError(
                "output could not be committed atomically"
            ) from exc
    except (TypeError, ValueError) as exc:
        raise CandidateRoleEvaluationToolError("evaluation contains invalid JSON") from exc
    finally:
        staged.unlink(missing_ok=True)


def _summary(
    payload: dict[str, object],
) -> dict[str, object]:
    runtimes = payload["runtimes"]
    consistency = payload["cpu_gpu_role_consistency"]
    assert isinstance(runtimes, dict)
    assert isinstance(consistency, dict)
    return {
        "cpu_gpu_role_agreement_rate": consistency["agreement_rate"],
        "development_only": payload["development_only"],
        "evaluation_sha256": payload["evaluation_sha256"],
        "formal_release_eligible": payload["formal_release_eligible"],
        "runtime_sample_count": {
            runtime_kind: runtime_payload["sample_count"]
            for runtime_kind, runtime_payload in sorted(runtimes.items())
        },
        "status": payload["status"],
    }


def _qualified_runtime_fingerprint(
    backend: AsyncOcrExecutionBackend,
) -> str:
    identities: list[dict[str, str]] = []
    missing: list[str] = []
    for runtime_kind in _RUNTIME_KINDS:
        if not backend.has_runtime(runtime_kind):
            missing.append(runtime_kind)
            continue
        identity = backend.identity_for(runtime_kind)
        identities.append(
            {
                "profile_id": identity.profile_id,
                "runtime_fingerprint": identity.runtime_fingerprint,
                "runtime_kind": identity.runtime_kind,
            }
        )
    if missing:
        raise CandidateRoleEvaluationToolError(
            "candidate role evaluation requires qualified CPU and GPU "
            "runtimes"
        )
    return current_template_ocr_runtime_set_fingerprint(identities)


def _run(arguments: argparse.Namespace) -> int:
    requested_root = arguments.data_root
    if not requested_root.is_dir() or requested_root.resolve(strict=True) != requested_root:
        raise CandidateRoleEvaluationToolError("data root must be an existing resolved directory")
    if len(arguments.candidate_versions) != len(set(arguments.candidate_versions)):
        raise CandidateRoleEvaluationToolError("candidate version IDs contain a duplicate")
    evidence_path = _validate_evidence_path(
        arguments.ocr_evidence,
        data_root=requested_root,
    )
    output = _validate_output(
        arguments.output,
        data_root=requested_root,
    )
    config = AppConfig(
        runtime_profile=RuntimeProfile.DEVELOPMENT,
        data_root=requested_root,
    )
    data_root = prepare_startup_environment(
        config,
        ROOT,
    )
    if data_root != requested_root:
        raise CandidateRoleEvaluationToolError("prepared data root changed identity")
    evidence_path = _validate_evidence_path(
        evidence_path,
        data_root=data_root,
    )
    output = _validate_output(
        output,
        data_root=data_root,
    )
    with SingleInstanceGuard(
        data_root,
        config.port,
        __version__,
    ) as guard:
        runtime = SqliteRuntime(
            data_root=data_root,
            project_root=ROOT,
            instance_id=guard.instance_id,
        )
        backend: AsyncOcrExecutionBackend | None = None
        try:
            backend = build_ocr_execution_backend(
                config=config,
                repository_root=ROOT,
            )
            role_evaluator_build_sha256 = (
                current_template_pipeline_build_fingerprint(
                    application_version=__version__,
                )
            )
            runtime_set_sha256 = _qualified_runtime_fingerprint(
                backend
            )
            authorizing_dataset = (
                load_approved_authorizing_development_dataset(
                    approved_authorizing_development_dataset_path()
                )
            )
            repository = SqliteTemplateRepository(
                runtime=runtime,
                accepted_build_fingerprint=(
                    role_evaluator_build_sha256
                ),
                accepted_runtime_fingerprint=runtime_set_sha256,
                accepted_development_manifest_sha256=(
                    authorizing_dataset.manifest_sha256
                ),
                accepted_matcher_fingerprint=(
                    development_matcher_fingerprint()
                ),
                accepted_policy_fingerprint=(
                    development_policy_fingerprint()
                ),
            )
            candidates = tuple(
                repository.get_version(version_id) for version_id in arguments.candidate_versions
            )
            current_shadow = repository.list_current_eligible_shadow_versions()
            report = evaluate_candidate_development_roles_from_path(
                evidence_path,
                data_root=data_root,
                candidates=candidates,
                current_shadow=current_shadow,
                role_evaluator_build_sha256=(
                    role_evaluator_build_sha256
                ),
            )
        finally:
            runtime.close()
            if backend is not None:
                backend.close()
        _write_exclusive_json(
            output,
            report.payload,
            data_root=data_root,
        )
    print(
        json.dumps(
            _summary(report.payload),
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        return _run(arguments)
    except (
        CandidateRoleEvaluationError,
        CandidateRoleEvaluationToolError,
        TemplatePersistenceError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
