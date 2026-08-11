from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

from dahe import __version__
from dahe.adapters.ocr.runtime_factory import build_ocr_execution_backend
from dahe.adapters.sqlite.candidate_development_ocr import (
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_evaluation import (
    CompositeLifecyclePersistenceError,
    persist_composite_lifecycle_evaluation,
    prepare_composite_lifecycle_attempt_scope,
    prepare_composite_lifecycle_evaluation,
)
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
from dahe.application.template_studio.candidate_development_ocr_run_authority import (
    CandidateDevelopmentOcrRunAuthorityError,
)
from dahe.application.template_studio.candidate_role_evaluation import (
    CandidateRoleEvaluationError,
)
from dahe.application.template_studio.composite_lifecycle_evaluation import (
    CompositeLifecycleEvaluationError,
)
from dahe.application.template_studio.development_evaluation import (
    FrozenDevelopmentFixtureError,
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


class CompositeLifecycleToolError(RuntimeError):
    """Raised when the local composite lifecycle tool is unsafe."""


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
            "Run and persist the conjoined Loop 7 ticket-role lifecycle "
            "evaluation from protected OCR evidence."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
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
    parser.add_argument("--output", type=_absolute_path, required=True)
    return parser


def _same_or_descendant(path: Path, root: Path) -> bool:
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
        raise CompositeLifecycleToolError(
            "protected OCR evidence is unavailable"
        ) from exc
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
        or not _same_or_descendant(resolved, protected_root)
    ):
        raise CompositeLifecycleToolError(
            "OCR evidence must be a protected development record"
        )
    digest = resolved.stem
    if (
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or resolved.suffix.lower() != ".json"
        or resolved.parent
        != protected_root / digest[:2] / digest[2:4]
    ):
        raise CompositeLifecycleToolError(
            "protected OCR evidence path is not content-addressed"
        )
    return resolved


def _validate_output(path: Path, *, data_root: Path) -> Path:
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise CompositeLifecycleToolError(
            "output path cannot be resolved safely"
        ) from exc
    if resolved.suffix.lower() != ".json":
        raise CompositeLifecycleToolError(
            "output path must use the .json extension"
        )
    if resolved.exists() or resolved.is_symlink():
        raise CompositeLifecycleToolError(
            "output already exists; choose a new JSON path"
        )
    if _same_or_descendant(resolved, data_root):
        raise CompositeLifecycleToolError(
            "output must stay outside application data"
        )
    return resolved


def _write_exclusive_json(
    path: Path,
    payload: dict[str, object],
    *,
    data_root: Path,
) -> None:
    target = _validate_output(path, data_root=data_root)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CompositeLifecycleToolError(
            "output directory could not be prepared"
        ) from exc
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
            raise CompositeLifecycleToolError(
                "output appeared during write; no file was replaced"
            ) from exc
        except OSError as exc:
            raise CompositeLifecycleToolError(
                "output could not be committed atomically"
            ) from exc
    except OSError as exc:
        raise CompositeLifecycleToolError(
            "output could not be written safely"
        ) from exc
    finally:
        try:
            staged.unlink(missing_ok=True)
        except OSError as exc:
            raise CompositeLifecycleToolError(
                "staged output could not be cleaned safely"
            ) from exc


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
        raise CompositeLifecycleToolError(
            "composite lifecycle evaluation requires qualified CPU and GPU "
            "runtimes"
        )
    return current_template_ocr_runtime_set_fingerprint(identities)


def _run(arguments: argparse.Namespace) -> int:
    requested_root = arguments.data_root
    if (
        not requested_root.is_dir()
        or requested_root.resolve(strict=True) != requested_root
    ):
        raise CompositeLifecycleToolError(
            "data root must be an existing resolved directory"
        )
    candidate_versions = tuple(arguments.candidate_versions)
    if len(candidate_versions) != len(set(candidate_versions)):
        raise CompositeLifecycleToolError(
            "candidate version IDs contain a duplicate"
        )
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
    data_root = prepare_startup_environment(config, ROOT)
    if data_root != requested_root:
        raise CompositeLifecycleToolError(
            "prepared data root changed identity"
        )
    evidence_path = _validate_evidence_path(
        evidence_path,
        data_root=data_root,
    )
    output = _validate_output(output, data_root=data_root)
    role_evaluator_build_sha256 = (
        current_template_pipeline_build_fingerprint(
            application_version=__version__,
        )
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
        backend = build_ocr_execution_backend(
            config=config,
            repository_root=ROOT,
        )
        try:
            runtime_set_sha256 = _qualified_runtime_fingerprint(
                backend
            )
            authorizing_manifest_path = (
                approved_authorizing_development_dataset_path()
            )
            authorizing_dataset = (
                load_approved_authorizing_development_dataset(
                    authorizing_manifest_path
                )
            )
            candidate_repository = SqliteTemplateRepository(
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
            ocr_run_repository = (
                SqliteCandidateDevelopmentOcrRunRepository(
                    runtime=runtime
                )
            )
            attempt_scope = prepare_composite_lifecycle_attempt_scope(
                candidate_repository,
                candidate_ocr_run_repository=ocr_run_repository,
                manifest_path=authorizing_manifest_path,
                candidate_ocr_evidence_path=evidence_path,
                candidate_version_ids=candidate_versions,
                role_evaluator_build_sha256=(
                    role_evaluator_build_sha256
                ),
                runtime_set_sha256=runtime_set_sha256,
            )
            try:
                prepared = prepare_composite_lifecycle_evaluation(
                    candidate_repository,
                    candidate_ocr_run_repository=ocr_run_repository,
                    manifest_path=authorizing_manifest_path,
                    candidate_ocr_evidence_path=evidence_path,
                    candidate_ocr_data_root=data_root,
                    candidate_version_ids=candidate_versions,
                    role_evaluator_build_sha256=(
                        role_evaluator_build_sha256
                    ),
                    runtime_set_sha256=runtime_set_sha256,
                )
                authorizing_repository = SqliteTemplateRepository(
                    runtime=runtime,
                    accepted_build_fingerprint=(
                        role_evaluator_build_sha256
                    ),
                    accepted_runtime_fingerprint=runtime_set_sha256,
                    accepted_development_manifest_sha256=(
                        prepared.composite.dataset_manifest_sha256
                    ),
                    accepted_matcher_fingerprint=(
                        prepared.synthetic_component.matcher_fingerprint
                    ),
                    accepted_policy_fingerprint=(
                        prepared.synthetic_component.policy_fingerprint
                    ),
                )
                persisted = persist_composite_lifecycle_evaluation(
                    authorizing_repository,
                    prepared,
                    actor_id="loop7-composite-lifecycle-evaluator",
                )
                evidence_payload: dict[str, object] = {
                    "composite": prepared.composite.payload,
                    "kind": "loop7_composite_lifecycle_evidence",
                    "persisted": {
                        "evaluation_id": persisted.evaluation_id,
                        "verification_source": (
                            persisted.verification_source
                        ),
                    },
                    "real_component": prepared.real_component.payload,
                    "schema_version": 1,
                    "synthetic_component_stable_outcome_sha256": (
                        prepared.synthetic_component.stable_outcome_sha256
                    ),
                }
                _write_exclusive_json(
                    output,
                    evidence_payload,
                    data_root=data_root,
                )
            except (
                CandidateDevelopmentOcrRunAuthorityError,
                CandidateRoleEvaluationError,
                CompositeLifecycleEvaluationError,
                CompositeLifecyclePersistenceError,
                CompositeLifecycleToolError,
                FrozenDevelopmentFixtureError,
                TemplatePersistenceError,
            ) as exc:
                terminal_status = (
                    "business_failed"
                    if isinstance(
                        exc,
                        CompositeLifecyclePersistenceError,
                    )
                    and "gate did not pass" in str(exc)
                    else "technical_failed"
                )
                candidate_repository.record_composite_lifecycle_failure(
                    scope=attempt_scope,
                    terminal_status=terminal_status,
                    failure_code=(
                        "LOOP7-COMPOSITE-BUSINESS-GATE"
                        if terminal_status == "business_failed"
                        else "LOOP7-COMPOSITE-TECHNICAL-FAILURE"
                    ),
                    actor_id=(
                        "loop7-composite-lifecycle-evaluator"
                    ),
                )
                raise
            except Exception:
                candidate_repository.record_composite_lifecycle_failure(
                    scope=attempt_scope,
                    terminal_status="technical_failed",
                    failure_code=(
                        "LOOP7-COMPOSITE-UNEXPECTED-FAILURE"
                    ),
                    actor_id=(
                        "loop7-composite-lifecycle-evaluator"
                    ),
                )
                raise
        finally:
            runtime.close()
            backend.close()
    print(
        json.dumps(
            {
                "authorization_scope": "ticket_role_evidence",
                "evaluation_id": prepared.composite.evaluation_id,
                "gate_passed": persisted.gate_passed,
                "output": os.fspath(output),
            },
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
        CandidateDevelopmentOcrRunAuthorityError,
        CandidateRoleEvaluationError,
        CompositeLifecycleEvaluationError,
        CompositeLifecyclePersistenceError,
        CompositeLifecycleToolError,
        FrozenDevelopmentFixtureError,
        TemplatePersistenceError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
