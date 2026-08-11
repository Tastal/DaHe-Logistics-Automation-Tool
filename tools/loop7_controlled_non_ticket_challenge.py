from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path

from dahe import __version__
from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.ocr.locked_set_evaluator import (
    LocalOcrLockedImageEvaluator,
)
from dahe.adapters.ocr.runtime_factory import build_ocr_execution_backend
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.development_authority_rollover import (
    DevelopmentAuthorityRolloverError,
    load_development_authority_rollover,
    validate_development_authority_rollover,
)
from dahe.application.template_studio.fingerprints import (
    current_template_pipeline_build_manifest,
)
from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthorityError,
    build_current_formal_development_authority,
    load_formal_development_authority,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.system.instance_lock import SingleInstanceGuard
from dahe.verification.controlled_non_ticket_challenge import (
    ControlledNonTicketChallenge,
    ControlledNonTicketChallengeError,
    RedactionRectangle,
    create_controlled_non_ticket_challenge,
    load_controlled_challenge_context,
    load_controlled_non_ticket_challenge,
)
from dahe.verification.controlled_non_ticket_gate import (
    ControlledNonTicketGateError,
    evaluate_controlled_non_ticket_gate,
    write_controlled_non_ticket_gate_result,
)
from dahe.verification.locked_set_runner import IndependentLockedImage

ROOT = Path(__file__).resolve().parents[1]


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return path


def _required_text(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise argparse.ArgumentTypeError("value must not be blank")
    return normalized


def _aware_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("time must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("time must include a timezone")
    return parsed.isoformat(timespec="seconds")


def _redaction(value: str) -> RedactionRectangle:
    fields = value.split(",")
    if len(fields) != 4:
        raise argparse.ArgumentTypeError("redaction must be x1,y1,x2,y2")
    try:
        coordinates = tuple(int(field.strip()) for field in fields)
        return RedactionRectangle(*coordinates)
    except (ControlledNonTicketChallengeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("redaction must be x1,y1,x2,y2") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create or verify one offline, redacted Loop 7 non-ticket "
            "challenge artifact."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser(
        "create",
        help="Redact, compare, and atomically seal one local source image.",
        allow_abbrev=False,
    )
    create.add_argument("--source-image", type=_absolute_path, required=True)
    create.add_argument("--output-root", type=_absolute_path, required=True)
    create.add_argument(
        "--development-authority",
        type=_absolute_path,
        required=True,
    )
    create.add_argument(
        "--package-data-root",
        type=_absolute_path,
        required=True,
    )
    create.add_argument("--operator", type=_required_text, required=True)
    create.add_argument("--created-at", type=_aware_timestamp, required=True)
    create.add_argument(
        "--redact",
        action="append",
        type=_redaction,
        required=True,
        help="Opaque half-open pixel rectangle x1,y1,x2,y2; repeat as needed.",
    )

    verify = commands.add_parser(
        "verify",
        help="Recompute source, redaction, authority, package, and novelty evidence.",
        allow_abbrev=False,
    )
    verify.add_argument("--manifest", type=_absolute_path, required=True)
    verify.add_argument(
        "--source-image",
        type=_absolute_path,
        help="Optional original image for a full redaction replay.",
    )
    verify.add_argument(
        "--development-authority",
        type=_absolute_path,
        required=True,
    )
    verify.add_argument(
        "--package-data-root",
        type=_absolute_path,
        required=True,
    )

    evaluate = commands.add_parser(
        "evaluate",
        help=(
            "Run the redacted challenge through the qualified CPU/GPU "
            "formal role pipeline."
        ),
        allow_abbrev=False,
    )
    evaluate.add_argument("--manifest", type=_absolute_path, required=True)
    evaluate.add_argument(
        "--development-authority",
        type=_absolute_path,
        required=True,
        help="The sealed source development authority.",
    )
    evaluate.add_argument(
        "--package-data-root",
        type=_absolute_path,
        required=True,
    )
    evaluate.add_argument(
        "--development-data-root",
        type=_absolute_path,
        required=True,
    )
    evaluate.add_argument(
        "--formal-data-root",
        type=_absolute_path,
        required=True,
    )
    evaluate.add_argument(
        "--development-authority-rollover",
        type=_absolute_path,
        required=True,
    )
    return parser


def _result_payload(
    artifact: ControlledNonTicketChallenge,
    *,
    action: str,
) -> dict[str, object]:
    return {
        "action": action,
        "canonical_sha256": artifact.payload["canonical_sha256"],
        "development_authority_sha256": (
            artifact.payload["development_authority_sha256"]
        ),
        "manifest_path": str(artifact.manifest_path),
        "package_sha256": artifact.payload["package_sha256"],
        "redacted_sha256": artifact.payload["redacted_sha256"],
        "source_sha256": artifact.payload["source_sha256"],
        "verified": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "evaluate":
        return _evaluate(args, parser=parser)
    try:
        context = load_controlled_challenge_context(
            development_authority_path=args.development_authority,
            package_data_root=args.package_data_root,
        )
        if args.command == "create":
            artifact = create_controlled_non_ticket_challenge(
                source_image=args.source_image,
                output_root=args.output_root,
                redactions=tuple(args.redact),
                operator_id=args.operator,
                created_at=args.created_at,
                context=context,
            )
        else:
            artifact = load_controlled_non_ticket_challenge(
                manifest_path=args.manifest,
                context=context,
                source_image=args.source_image,
            )
    except ControlledNonTicketChallengeError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            _result_payload(artifact, action=args.command),
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        common = os.path.commonpath((os.fspath(left), os.fspath(right)))
    except ValueError:
        return False
    normalized = os.path.normcase(common)
    return normalized in {
        os.path.normcase(os.fspath(left)),
        os.path.normcase(os.fspath(right)),
    }


def _evaluate(
    args: argparse.Namespace,
    *,
    parser: argparse.ArgumentParser,
) -> int:
    try:
        development_root = args.development_data_root.resolve(strict=True)
        formal_requested = args.formal_data_root
        package_root = args.package_data_root.resolve(strict=True)
        source_authority = load_formal_development_authority(
            args.development_authority,
        )
        rollover = load_development_authority_rollover(
            args.development_authority_rollover,
        )
        context = load_controlled_challenge_context(
            development_authority_path=args.development_authority,
            package_data_root=package_root,
        )
        challenge = load_controlled_non_ticket_challenge(
            manifest_path=args.manifest,
            context=context,
        )
        if (
            not development_root.is_dir()
            or not package_root.is_dir()
            or _paths_overlap(development_root, formal_requested)
        ):
            raise ControlledNonTicketGateError(
                "development and formal data roots must be independent"
            )
        configs = {
            "development": AppConfig(
                runtime_profile=RuntimeProfile.DEVELOPMENT,
                data_root=development_root,
            ),
            "formal": AppConfig(
                runtime_profile=RuntimeProfile.DEVELOPMENT,
                data_root=formal_requested,
            ),
        }
        prepared: dict[str, Path] = {
            label: prepare_startup_environment(config, ROOT)
            for label, config in configs.items()
        }
        runtimes: dict[str, SqliteRuntime] = {}
        with ExitStack() as stack:
            for label in sorted(
                prepared,
                key=lambda item: os.path.normcase(
                    os.fspath(prepared[item])
                ),
            ):
                data_root = prepared[label]
                config = configs[label]
                guard = stack.enter_context(
                    SingleInstanceGuard(
                        data_root,
                        config.port,
                        __version__,
                    )
                )
                runtime = SqliteRuntime(
                    data_root=data_root,
                    project_root=ROOT,
                    instance_id=guard.instance_id,
                )
                stack.callback(runtime.close)
                runtimes[label] = runtime
            execution_authority = (
                build_current_formal_development_authority(
                    runtimes["development"],
                    frozen_exclusion_snapshot_sha256=(
                        source_authority.exclusion_snapshot.canonical_sha256
                    ),
                )
            )
            validate_development_authority_rollover(
                rollover,
                source_authority=source_authority,
                execution_authority=execution_authority,
            )
            formal_root = runtimes["formal"].data_root
            evidence_store = ContentAddressedEvidenceStore(
                formal_root / "evidence"
            )
            redacted_bytes = challenge.redacted_image_path.read_bytes()
            stored = evidence_store.put_bytes(
                redacted_bytes,
                media_type="image/png",
            )
            if stored.sha256 != challenge.payload["redacted_sha256"]:
                raise ControlledNonTicketGateError(
                    "redacted challenge changed during formal staging"
                )
            backend = build_ocr_execution_backend(
                config=configs["formal"],
                repository_root=ROOT,
            )
            stack.callback(backend.close)
            build_manifest = current_template_pipeline_build_manifest(
                application_version=__version__,
            )
            evaluator = LocalOcrLockedImageEvaluator(
                backend=backend,
                templates=execution_authority.shadow_templates,
                application_build_sha256=(
                    build_manifest.canonical_sha256
                ),
                application_build_manifest=build_manifest,
                timeout_seconds=180.0,
            )
            prediction = evaluator(
                IndependentLockedImage(
                    image_sha256=stored.sha256,
                    relative_path=(
                        f"evidence/{stored.relative_path}"
                    ),
                )
            )
            result = evaluate_controlled_non_ticket_gate(
                challenge=challenge,
                prediction=prediction,
                source_authority_sha256=(
                    source_authority.authority_sha256
                ),
                execution_authority_sha256=(
                    execution_authority.authority_sha256
                ),
                development_authority_rollover_sha256=(
                    rollover.rollover_sha256
                ),
            )
            result_root = (
                formal_root
                / "controlled-non-ticket-results"
                / result.result_sha256[:2]
            )
            result_path = write_controlled_non_ticket_gate_result(
                result_root / f"{result.result_sha256}.json",
                result,
            )
    except (
        ControlledNonTicketChallengeError,
        ControlledNonTicketGateError,
        DevelopmentAuthorityRolloverError,
        FormalDevelopmentAuthorityError,
        OSError,
    ) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "action": "evaluate",
                "passed": True,
                "result_path": os.fspath(result_path),
                "result_sha256": result.result_sha256,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
