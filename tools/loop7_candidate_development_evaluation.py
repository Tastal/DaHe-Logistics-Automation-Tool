from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from dahe import __version__
from dahe.adapters.ocr.runtime_factory import (
    build_ocr_execution_backend,
)
from dahe.adapters.sqlite.candidate_development_ocr import (
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewAuthoritySnapshot,
    SqliteLockedSetReviewRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.candidate_development_ocr import (
    CandidateDevelopmentOcrError,
    run_candidate_development_ocr_evaluation,
)
from dahe.application.template_studio.candidate_development_ocr_run_authority import (
    CandidateDevelopmentOcrRunAuthorityError,
    record_candidate_development_ocr_terminal_attempt,
)
from dahe.application.template_studio.candidate_review_export import (
    CandidateReviewFormalExport,
    build_candidate_review_formal_export,
)
from dahe.application.template_studio.fingerprints import (
    current_template_pipeline_build_fingerprint,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.system.instance_lock import SingleInstanceGuard
from dahe.verification.locked_set_review_package import (
    LockedSetReviewPackage,
    load_locked_set_review_package,
)

ROOT = Path(__file__).resolve().parents[1]


class CandidateDevelopmentEvaluationToolError(RuntimeError):
    """Raised when the development-only candidate OCR tool is unsafe."""


@dataclass(frozen=True, slots=True)
class _ReviewContext:
    package: LockedSetReviewPackage
    authority: LockedSetReviewAuthoritySnapshot
    review_export: CandidateReviewFormalExport


def _absolute_path(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    try:
        return candidate.resolve(strict=False)
    except OSError as exc:
        raise argparse.ArgumentTypeError("path cannot be resolved safely") from exc


def _required_text(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise argparse.ArgumentTypeError("value must not be blank")
    return normalized


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run CPU and GPU OCR on the completed candidate review as "
            "development-only local evidence."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--review-data-root",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--reviewer-id",
        type=_required_text,
        required=True,
    )
    parser.add_argument(
        "--output",
        type=_absolute_path,
        required=True,
    )
    return parser


def _same_or_descendant(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.fspath(path), os.fspath(root)))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(os.fspath(root))


def _validate_independent_roots(
    review_data_root: Path,
    data_root: Path,
) -> None:
    if _same_or_descendant(
        review_data_root,
        data_root,
    ) or _same_or_descendant(data_root, review_data_root):
        raise CandidateDevelopmentEvaluationToolError(
            "review and development data roots must be independent"
        )


def _validate_output_target(
    output: Path,
    *,
    protected_roots: tuple[Path, ...],
) -> Path:
    if not output.is_absolute():
        raise CandidateDevelopmentEvaluationToolError("output path must be absolute")
    try:
        resolved = output.resolve(strict=False)
    except OSError as exc:
        raise CandidateDevelopmentEvaluationToolError(
            "output path cannot be resolved safely"
        ) from exc
    if resolved.suffix.lower() != ".json":
        raise CandidateDevelopmentEvaluationToolError("output path must use the .json extension")
    if resolved.exists() or resolved.is_symlink():
        raise CandidateDevelopmentEvaluationToolError(
            "output already exists; choose a new JSON path"
        )
    for root in protected_roots:
        if _same_or_descendant(resolved, root):
            raise CandidateDevelopmentEvaluationToolError(
                "output path overlaps a protected data root"
            )
    return resolved


def _write_json_exclusive_atomic(
    output: Path,
    payload: dict[str, object],
) -> None:
    target = _validate_output_target(
        output,
        protected_roots=(),
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
            raise CandidateDevelopmentEvaluationToolError(
                "output appeared during write; no file was replaced"
            ) from exc
        except OSError as exc:
            raise CandidateDevelopmentEvaluationToolError(
                "output could not be committed atomically"
            ) from exc
    except (TypeError, ValueError) as exc:
        raise CandidateDevelopmentEvaluationToolError("summary contains invalid JSON") from exc
    finally:
        staged.unlink(missing_ok=True)


def _build_review_context(
    *,
    review_data_root: Path,
    instance_id: str,
    configured_reviewer_id: str,
) -> _ReviewContext:
    package = load_locked_set_review_package(
        review_data_root,
    )
    runtime = SqliteRuntime(
        data_root=review_data_root,
        project_root=ROOT,
        instance_id=instance_id,
    )
    try:
        authority = SqliteLockedSetReviewRepository(
            runtime=runtime,
            package_sha256=package.canonical_sha256,
        ).build_authority_snapshot()
    finally:
        runtime.close()
    review_export = build_candidate_review_formal_export(
        package=package,
        records=authority.latest_records,
        configured_reviewer_id=configured_reviewer_id,
        dataset_id=(f"candidate-review-development-source-{package.canonical_sha256[:16]}"),
    )
    return _ReviewContext(
        package=package,
        authority=authority,
        review_export=review_export,
    )


def _run(arguments: argparse.Namespace) -> int:
    review_data_root = arguments.review_data_root
    data_root_request = arguments.data_root
    if not review_data_root.is_dir() or review_data_root.resolve(strict=True) != review_data_root:
        raise CandidateDevelopmentEvaluationToolError(
            "review data root must be an existing resolved directory"
        )
    _validate_independent_roots(
        review_data_root,
        data_root_request,
    )
    output = _validate_output_target(
        arguments.output,
        protected_roots=(
            review_data_root,
            data_root_request,
        ),
    )
    config = AppConfig(
        runtime_profile=RuntimeProfile.DEVELOPMENT,
        data_root=data_root_request,
    )
    data_root = prepare_startup_environment(config, ROOT)
    _validate_independent_roots(
        review_data_root,
        data_root,
    )
    output = _validate_output_target(
        output,
        protected_roots=(review_data_root, data_root),
    )

    with ExitStack() as stack:
        review_guard = stack.enter_context(
            SingleInstanceGuard(
                review_data_root,
                config.port,
                __version__,
            )
        )
        development_guard = stack.enter_context(
            SingleInstanceGuard(
                data_root,
                config.port,
                __version__,
            )
        )
        context = _build_review_context(
            review_data_root=review_data_root,
            instance_id=review_guard.instance_id,
            configured_reviewer_id=arguments.reviewer_id,
        )
        runtime = SqliteRuntime(
            data_root=data_root,
            project_root=ROOT,
            instance_id=development_guard.instance_id,
        )
        try:
            backend = build_ocr_execution_backend(
                config=config,
                repository_root=ROOT,
            )
            try:
                result = run_candidate_development_ocr_evaluation(
                    package=context.package,
                    authority=context.authority,
                    review_export=context.review_export,
                    backend=backend,
                    data_root=data_root,
                    reviewer_id=arguments.reviewer_id,
                    application_build_sha256=(
                        current_template_pipeline_build_fingerprint(
                            application_version=__version__,
                        )
                    ),
                    timeout_seconds=180,
                )
            finally:
                backend.close()
            record_candidate_development_ocr_terminal_attempt(
                SqliteCandidateDevelopmentOcrRunRepository(
                    runtime=runtime
                ),
                data_root=data_root,
                evidence_path=result.evidence_path,
            )
            _write_json_exclusive_atomic(
                output,
                result.summary_payload,
            )
        finally:
            runtime.close()

    print(
        json.dumps(
            result.summary_payload,
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 1 if result.status == "failed" else 0


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        return _run(arguments)
    except (
        CandidateDevelopmentEvaluationToolError,
        CandidateDevelopmentOcrError,
        CandidateDevelopmentOcrRunAuthorityError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
