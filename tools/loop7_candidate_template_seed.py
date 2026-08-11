from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dahe import __version__
from dahe.adapters.sqlite.candidate_development_ocr import (
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplatePersistenceError,
)
from dahe.application.template_studio.candidate_template_seed import (
    CandidateTemplateSeedError,
    load_candidate_development_template_source,
    load_template_definition,
    seed_candidate_development_template,
)
from dahe.application.template_studio.fingerprints import (
    current_template_pipeline_build_fingerprint,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.system.instance_lock import SingleInstanceGuard

ROOT = Path(__file__).resolve().parents[1]


class CandidateTemplateSeedToolError(RuntimeError):
    """Raised when the template-seed CLI cannot mutate its isolated root."""


def _absolute_path(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    try:
        return candidate.resolve(strict=False)
    except OSError as exc:
        raise argparse.ArgumentTypeError(
            "path cannot be resolved safely"
        ) from exc


def _required_text(value: str) -> str:
    normalized = value.strip()
    if not normalized or normalized != value:
        raise argparse.ArgumentTypeError(
            "value must be non-blank canonical text"
        )
    return normalized


def _sha256(value: str) -> str:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise argparse.ArgumentTypeError(
            "value must be a lowercase SHA-256"
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create one development-only ticket-template draft from a "
            "protected, human-confirmed candidate OCR record."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--evidence",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--evidence-sha256",
        type=_sha256,
        required=True,
    )
    parser.add_argument(
        "--sample-id",
        type=_required_text,
        required=True,
    )
    parser.add_argument(
        "--submitted-slot",
        choices=("loading", "unloading"),
        required=True,
    )
    parser.add_argument(
        "--expected-role",
        choices=("loading", "unloading"),
        required=True,
    )
    parser.add_argument(
        "--definition",
        type=_absolute_path,
        required=True,
    )
    parser.add_argument(
        "--actor-id",
        type=_required_text,
        required=True,
    )
    parser.add_argument(
        "--idempotency-key",
        type=_required_text,
        required=True,
    )
    return parser


def _existing_resolved_directory(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CandidateTemplateSeedToolError(
            "data root is unavailable"
        ) from exc
    if path != resolved or not resolved.is_dir():
        raise CandidateTemplateSeedToolError(
            "data root must be an existing resolved directory"
        )
    return resolved


def _run(arguments: argparse.Namespace) -> int:
    requested_root = _existing_resolved_directory(
        arguments.data_root
    )
    definition = load_template_definition(arguments.definition)
    if definition.role.value != arguments.expected_role:
        raise CandidateTemplateSeedToolError(
            "template definition role does not match --expected-role"
        )
    config = AppConfig(
        runtime_profile=RuntimeProfile.DEVELOPMENT,
        data_root=requested_root,
    )
    data_root = prepare_startup_environment(config, ROOT)
    if data_root != requested_root:
        raise CandidateTemplateSeedToolError(
            "prepared data root changed identity"
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
        try:
            source = load_candidate_development_template_source(
                run_repository=(
                    SqliteCandidateDevelopmentOcrRunRepository(
                        runtime=runtime
                    )
                ),
                data_root=data_root,
                evidence_path=arguments.evidence,
                expected_evidence_sha256=(
                    arguments.evidence_sha256
                ),
                sample_id=arguments.sample_id,
                submitted_slot=arguments.submitted_slot,
                expected_role=arguments.expected_role,
            )
            repository = SqliteTemplateRepository(
                runtime=runtime,
                accepted_build_fingerprint=(
                    current_template_pipeline_build_fingerprint(
                        application_version=__version__,
                    )
                ),
            )
            result = seed_candidate_development_template(
                repository,
                definition=definition,
                source=source,
                actor_id=arguments.actor_id,
                idempotency_key=arguments.idempotency_key,
            )
        finally:
            runtime.close()
    print(
        json.dumps(
            {
                "created": result.created,
                "family_id": result.version.definition.family_id,
                "origin_sha256": result.origin.origin_sha256,
                "role": result.version.definition.role.value,
                "version_id": result.version.version_id,
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
        CandidateTemplateSeedError,
        CandidateTemplateSeedToolError,
        TemplatePersistenceError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
