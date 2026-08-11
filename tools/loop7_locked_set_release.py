from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from dahe import __version__
from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.ocr.runtime_factory import build_ocr_execution_backend
from dahe.adapters.sqlite.locked_set import (
    LOCKED_SET_INFLUENCE_KINDS,
    SqliteLockedSetRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.candidate_review_seal import (
    validate_candidate_review_seal,
)
from dahe.application.template_studio.development_authority_rollover import (
    load_development_authority_rollover,
)
from dahe.application.template_studio.formal_development_authority import (
    build_current_formal_development_authority,
    load_formal_development_authority,
    load_persisted_formal_development_authority,
    write_formal_development_authority,
)
from dahe.application.template_studio.formal_locked_set_release import (
    complete_existing_exclusion_fingerprints,
    evaluate_formal_locked_set_release,
    prepare_candidate_review_formal_release,
    prepare_formal_locked_set_release,
    validate_formal_locked_set_review,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.system.instance_lock import SingleInstanceGuard
from dahe.verification.locked_set_acceptance import (
    DERIVED_ADVERSARIAL_GENERATOR_VERSION,
    REQUIRED_NATURAL_QUALITY_CONDITIONS,
    locked_set_quality_coverage_sha256,
    quality_review_evidence_sha256,
)

ROOT = Path(__file__).resolve().parents[1]


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _absolute_path(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return candidate.resolve()


def _required_text(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise argparse.ArgumentTypeError("value must not be blank")
    return normalized


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed


def _lowercase_sha256(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("value must be a lowercase SHA-256")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare, bind, validate, evaluate, or permanently invalidate "
            "the offline Loop 7 locked-set gate."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    export_development = commands.add_parser(
        "export-development-authority",
        help=(
            "Revalidate the development root and export its current "
            "formal authority."
        ),
        allow_abbrev=False,
    )
    export_development.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    export_development.add_argument(
        "--output",
        type=Path,
        required=True,
    )

    prepare = commands.add_parser(
        "prepare",
        help="Seal the locked set and produce one bound human-review package.",
        allow_abbrev=False,
    )
    prepare.add_argument("--data-root", type=_absolute_path, required=True)
    prepare.add_argument("--manifest", type=Path, required=True)
    prepare.add_argument("--dataset-root", type=Path, required=True)
    prepare.add_argument("--actor", type=_required_text, required=True)
    prepare.add_argument("--review-output", type=Path, required=True)

    prepare_candidate = commands.add_parser(
        "prepare-candidate",
        help=("Prepare a formal review package only from an immutable candidate-review seal."),
        allow_abbrev=False,
    )
    prepare_candidate.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    prepare_candidate.add_argument(
        "--candidate-review-root",
        type=_absolute_path,
        required=True,
    )
    prepare_candidate.add_argument(
        "--development-data-root",
        type=_absolute_path,
        required=True,
    )
    prepare_candidate.add_argument(
        "--development-authority-sha256",
        type=_lowercase_sha256,
        required=True,
    )
    prepare_candidate.add_argument(
        "--source-development-authority-sha256",
        type=_lowercase_sha256,
        required=True,
    )
    prepare_candidate.add_argument(
        "--development-authority-rollover",
        type=_absolute_path,
        required=True,
    )
    prepare_candidate.add_argument(
        "--seal-sha256",
        type=_lowercase_sha256,
        required=True,
    )
    prepare_candidate.add_argument(
        "--actor",
        type=_required_text,
        required=True,
    )
    prepare_candidate.add_argument(
        "--review-output",
        type=Path,
        required=True,
    )

    evaluate = commands.add_parser(
        "evaluate",
        help="Run local OCR and atomically commit the formal gate report.",
        allow_abbrev=False,
    )
    evaluate.add_argument("--data-root", type=_absolute_path, required=True)
    evaluate.add_argument(
        "--development-data-root",
        type=_absolute_path,
        required=True,
    )
    evaluate.add_argument("--dataset-id", type=_required_text, required=True)
    evaluate.add_argument(
        "--review-package",
        type=Path,
        required=True,
    )
    evaluate.add_argument("--actor", type=_required_text, required=True)
    evaluate.add_argument(
        "--idempotency-key",
        type=_required_text,
        required=True,
    )
    evaluate.add_argument("--report-output", type=Path, required=True)

    validate = commands.add_parser(
        "validate",
        help="Validate the completed review package without starting OCR.",
        allow_abbrev=False,
    )
    validate.add_argument("--data-root", type=_absolute_path, required=True)
    validate.add_argument("--dataset-id", type=_required_text, required=True)
    validate.add_argument("--review-package", type=Path, required=True)
    validate.add_argument("--output", type=Path, required=True)

    bind_review = commands.add_parser(
        "bind-review",
        help=(
            "Bind operator-completed decisions and validate the complete package "
            "against the prepared dataset without starting OCR."
        ),
        allow_abbrev=False,
    )
    bind_review.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    bind_review.add_argument("--review-package", type=Path, required=True)
    bind_review.add_argument("--output", type=Path, required=True)

    invalidate = commands.add_parser(
        "invalidate",
        help=("Permanently convert a result-influenced locked set into development evidence."),
        allow_abbrev=False,
    )
    invalidate.add_argument("--data-root", type=_absolute_path, required=True)
    invalidate.add_argument("--dataset-id", type=_required_text, required=True)
    invalidate.add_argument(
        "--expected-record-version",
        type=_positive_integer,
        required=True,
    )
    invalidate.add_argument(
        "--influence-kind",
        choices=sorted(LOCKED_SET_INFLUENCE_KINDS),
        required=True,
    )
    invalidate.add_argument("--reason", type=_required_text, required=True)
    invalidate.add_argument("--actor", type=_required_text, required=True)
    invalidate.add_argument(
        "--idempotency-key",
        type=_required_text,
        required=True,
    )
    invalidate.add_argument("--output", type=Path, required=True)
    return parser


def _read_json_object(path: Path, *, label: str) -> dict[str, object]:
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise OSError
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise RuntimeError(f"{label} is not a readable JSON file") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must contain a JSON object")
    return value


def _validate_output_target(
    path: Path,
    *,
    protected_roots: tuple[Path, ...] = (),
) -> Path:
    output = path.resolve()
    if output.suffix.lower() != ".json":
        raise RuntimeError("output path must use the .json extension")
    for protected_root in protected_roots:
        root = protected_root.resolve()
        if output == root or output.is_relative_to(root):
            raise RuntimeError("output path overlaps protected input or application data")
    if output.exists() and output.is_dir():
        raise RuntimeError("output path must identify a JSON file")
    if output.exists():
        raise RuntimeError("output already exists; choose a new JSON path")
    return output


def _write_json_atomic(
    path: Path,
    payload: Mapping[str, object],
    *,
    protected_roots: tuple[Path, ...] = (),
) -> Path:
    output = _validate_output_target(
        path,
        protected_roots=protected_roots,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    staged = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(
                payload,
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, output)
        except FileExistsError as exc:
            raise RuntimeError("output appeared during the write; no file was replaced") from exc
        except OSError as exc:
            raise RuntimeError("output could not be committed atomically") from exc
    finally:
        staged.unlink(missing_ok=True)
    return output


def _config(data_root: Path) -> AppConfig:
    return AppConfig(
        runtime_profile=RuntimeProfile.DEVELOPMENT,
        data_root=data_root,
    )


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        common = os.path.commonpath(
            (
                os.fspath(left.resolve()),
                os.fspath(right.resolve()),
            )
        )
    except ValueError:
        return False
    normalized_common = os.path.normcase(common)
    return normalized_common in {
        os.path.normcase(os.fspath(left.resolve())),
        os.path.normcase(os.fspath(right.resolve())),
    }


@contextmanager
def _guarded_runtimes(
    roots: Mapping[str, Path],
) -> Iterator[dict[str, SqliteRuntime]]:
    if not roots:
        raise RuntimeError("at least one application data root is required")
    prepared: dict[str, tuple[Path, AppConfig]] = {}
    normalized_paths: set[str] = set()
    for label, requested in roots.items():
        config = _config(requested)
        data_root = prepare_startup_environment(config, ROOT)
        normalized = os.path.normcase(os.fspath(data_root.resolve()))
        if normalized in normalized_paths:
            raise RuntimeError("application data roots must be independent")
        normalized_paths.add(normalized)
        prepared[label] = (data_root, config)
    runtimes: dict[str, SqliteRuntime] = {}
    with ExitStack() as stack:
        for label, (data_root, config) in sorted(
            prepared.items(),
            key=lambda item: os.path.normcase(
                os.fspath(item[1][0].resolve())
            ),
        ):
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
        yield runtimes


def _committed_locked_set_gate_passed(
    *,
    evaluation: object,
    committed_report: Mapping[str, object],
) -> bool:
    observed_gate = committed_report.get("observed_locked_set_gate")
    derived_gate = committed_report.get("derived_adversarial_gate")
    return bool(
        getattr(evaluation, "gate_passed", False) is True
        and getattr(evaluation, "formal_report", False) is True
        and getattr(evaluation, "formal_accuracy_claim", False) is True
        and getattr(evaluation, "formal_accuracy_claim_scope", None)
        == "observed_real_locked_set_only"
        and getattr(
            evaluation,
            "derived_scenario_accuracy_claim",
            None,
        )
        is False
        and getattr(evaluation, "derived_prevalence_claim", None) is False
        and committed_report.get("gate_passed") is True
        and committed_report.get("formal_report") is True
        and committed_report.get("formal_accuracy_claim") is True
        and committed_report.get("formal_accuracy_claim_scope") == "observed_real_locked_set_only"
        and isinstance(observed_gate, Mapping)
        and observed_gate.get("passed") is True
        and isinstance(derived_gate, Mapping)
        and derived_gate.get("passed") is True
        and committed_report.get("derived_scenario_accuracy_claim") is False
        and committed_report.get("derived_prevalence_claim") is False
    )


def _export_development_authority(args: argparse.Namespace) -> int:
    try:
        development_root = args.data_root.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError(
            "--data-root must identify an existing development data directory"
        ) from exc
    if not development_root.is_dir():
        raise RuntimeError(
            "--data-root must identify an existing development data directory"
        )
    output = _validate_output_target(
        args.output,
        protected_roots=(development_root,),
    )
    with _guarded_runtimes(
        {"development": development_root}
    ) as runtimes:
        runtime = runtimes["development"]
        complete_existing_exclusion_fingerprints(
            repository=SqliteLockedSetRepository(runtime=runtime),
            evidence_store=ContentAddressedEvidenceStore(
                runtime.data_root / "evidence"
            ),
        )
        authority = build_current_formal_development_authority(
            runtime
        )
        write_formal_development_authority(
            output,
            authority,
        )
    print(
        json.dumps(
            {
                "authority_sha256": authority.authority_sha256,
                "image_identity_count": len(authority.image_sha256s),
                "output": os.fspath(output),
                "shadow_template_count": len(authority.shadow_templates),
                "source_inventory_high_watermark": (
                    authority.inventory_high_watermark
                ),
                "waybill_identity_count": len(
                    authority.waybill_identity_sha256s
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _prepare(args: argparse.Namespace) -> int:
    manifest_path = args.manifest.resolve(strict=True)
    dataset_root = args.dataset_root.resolve(strict=True)
    if not manifest_path.is_file():
        raise RuntimeError("--manifest must identify a JSON file")
    if not dataset_root.is_dir():
        raise RuntimeError("--dataset-root must identify a directory")
    config = _config(args.data_root)
    data_root = prepare_startup_environment(config, ROOT)
    _validate_output_target(
        args.review_output,
        protected_roots=(data_root, dataset_root),
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
            prepared = prepare_formal_locked_set_release(
                repository=SqliteLockedSetRepository(runtime=runtime),
                manifest_path=manifest_path,
                dataset_root=dataset_root,
                actor_id=args.actor,
            )
        finally:
            runtime.close()

    payload: dict[str, object] = {
        "schema_version": 1,
        "command": "prepare",
        "generated_at": datetime.now(UTC).isoformat(),
        "offline": True,
        "platform_access": False,
        "source_data_classification": "operator_supplied_locked_set",
        "classification_authority": "operator_declared",
        "dataset_id": prepared.dataset_id,
        "dataset_record_version": prepared.dataset_record_version,
        "manifest_sha256": prepared.manifest_sha256,
        "exclusion_snapshot_sha256": (prepared.exclusion_snapshot_sha256),
        "inventory_high_watermark": prepared.inventory_high_watermark,
        "scan_fingerprint": prepared.scan.scan_fingerprint,
        "status": prepared.status,
        "formal_accuracy_claim": False,
        "candidates": [item.to_payload() for item in prepared.scan.candidate_entries],
        "decisions": [],
        "scan": prepared.scan.to_payload(),
        "quality_coverage": dict(prepared.quality_coverage),
        "review_contract": {
            "similarity_entry_fields": [
                "candidate_id",
                "verdict",
                "reviewer_id",
                "decided_at",
                "reason",
            ],
            "quality_image_entry_fields": [
                "condition",
                "image_sha256",
                "reviewer_id",
                "reviewed_at",
                "review_evidence_sha256",
            ],
            "derived_adversarial_suite_editable": False,
            "quality_coverage_editable": False,
            "tuning_prohibited": True,
        },
    }
    output = _write_json_atomic(
        args.review_output,
        payload,
        protected_roots=(data_root, dataset_root),
    )
    print(
        json.dumps(
            {
                "candidate_count": len(prepared.scan.candidate_entries),
                "dataset_id": prepared.dataset_id,
                "formal_accuracy_claim": False,
                "output": os.fspath(output),
                "status": prepared.status,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _prepare_candidate(args: argparse.Namespace) -> int:
    try:
        candidate_review_root = args.candidate_review_root.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("--candidate-review-root must identify an existing directory") from exc
    if not candidate_review_root.is_dir():
        raise RuntimeError("--candidate-review-root must identify an existing directory")
    try:
        development_data_root = args.development_data_root.resolve(
            strict=True
        )
    except OSError as exc:
        raise RuntimeError(
            "--development-data-root must identify an existing directory"
        ) from exc
    if not development_data_root.is_dir():
        raise RuntimeError(
            "--development-data-root must identify an existing directory"
        )
    requested_data_root = args.data_root.resolve()
    protected_roots = (
        requested_data_root,
        candidate_review_root,
        development_data_root,
    )
    if any(
        _paths_overlap(left, right)
        for index, left in enumerate(protected_roots)
        for right in protected_roots[index + 1 :]
    ):
        raise RuntimeError(
            "formal, development, and candidate-review roots must be independent"
        )
    _validate_output_target(
        args.review_output,
        protected_roots=protected_roots,
    )
    candidate_review_seal = validate_candidate_review_seal(
        review_data_root=candidate_review_root,
        seal_sha256=args.seal_sha256,
    )
    source_development_authority = load_formal_development_authority(
        candidate_review_seal.seal_root
        / "development-authority.json",
        expected_sha256=(
            args.source_development_authority_sha256
        ),
    )
    development_authority_rollover = (
        load_development_authority_rollover(
            args.development_authority_rollover,
        )
    )

    with _guarded_runtimes(
        {
            "development": development_data_root,
            "formal": requested_data_root,
        }
    ) as runtimes:
        live_development_authority = (
            build_current_formal_development_authority(
                runtimes["development"],
                frozen_exclusion_snapshot_sha256=(
                    source_development_authority.exclusion_snapshot.canonical_sha256
                ),
            )
        )
        if (
            live_development_authority.authority_sha256
            != args.development_authority_sha256
        ):
            raise RuntimeError(
                "live development authority does not match the expected SHA-256"
            )
        prepared = prepare_candidate_review_formal_release(
            repository=SqliteLockedSetRepository(
                runtime=runtimes["formal"]
            ),
            candidate_review_seal=candidate_review_seal,
            source_development_authority=(
                source_development_authority
            ),
            live_development_authority=live_development_authority,
            development_authority_rollover=(
                development_authority_rollover
            ),
            expected_source_development_authority_sha256=(
                args.source_development_authority_sha256
            ),
            expected_execution_development_authority_sha256=(
                args.development_authority_sha256
            ),
            actor_id=args.actor,
        )

    source_authority = prepared.candidate_review_source_authority
    if (
        not isinstance(source_authority, Mapping)
        or source_authority.get("seal_sha256") != args.seal_sha256
    ):
        raise RuntimeError("prepared candidate-review source authority is missing")
    payload: dict[str, object] = {
        "schema_version": 1,
        "command": "prepare-candidate",
        "generated_at": datetime.now(UTC).isoformat(),
        "offline": True,
        "platform_access": False,
        "source_data_classification": ("sealed_human_reviewed_candidate"),
        "classification_authority": ("immutable_candidate_review_seal"),
        "dataset_id": prepared.dataset_id,
        "dataset_record_version": prepared.dataset_record_version,
        "manifest_sha256": prepared.manifest_sha256,
        "seal_sha256": args.seal_sha256,
        "development_authority_sha256": (
            prepared.development_authority_sha256
        ),
        "source_development_authority_sha256": (
            prepared.source_development_authority_sha256
        ),
        "execution_development_authority_sha256": (
            prepared.execution_development_authority_sha256
        ),
        "development_authority_rollover_sha256": (
            prepared.development_authority_rollover_sha256
        ),
        "candidate_review_source_authority": dict(source_authority),
        "exclusion_snapshot_sha256": (prepared.exclusion_snapshot_sha256),
        "inventory_high_watermark": (prepared.inventory_high_watermark),
        "scan_fingerprint": prepared.scan.scan_fingerprint,
        "status": prepared.status,
        "formal_accuracy_claim": False,
        "candidates": [item.to_payload() for item in prepared.scan.candidate_entries],
        "decisions": [],
        "scan": prepared.scan.to_payload(),
        "quality_coverage": dict(prepared.quality_coverage),
        "review_contract": {
            "similarity_entry_fields": [
                "candidate_id",
                "verdict",
                "reviewer_id",
                "decided_at",
                "reason",
            ],
            "quality_image_entry_fields": [
                "condition",
                "image_sha256",
                "reviewer_id",
                "reviewed_at",
                "review_evidence_sha256",
            ],
            "derived_adversarial_suite_editable": False,
            "tuning_prohibited": True,
        },
    }
    output = _write_json_atomic(
        args.review_output,
        payload,
        protected_roots=protected_roots,
    )
    print(
        json.dumps(
            {
                "candidate_count": len(prepared.scan.candidate_entries),
                "dataset_id": prepared.dataset_id,
                "formal_accuracy_claim": False,
                "output": os.fspath(output),
                "seal_sha256": args.seal_sha256,
                "development_authority_sha256": (
                    prepared.development_authority_sha256
                ),
                "status": prepared.status,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    review_package = _read_json_object(
        args.review_package,
        label="review package",
    )
    try:
        development_data_root = args.development_data_root.resolve(
            strict=True
        )
    except OSError as exc:
        raise RuntimeError(
            "--development-data-root must identify an existing directory"
        ) from exc
    if not development_data_root.is_dir():
        raise RuntimeError(
            "--development-data-root must identify an existing directory"
        )
    requested_data_root = args.data_root.resolve()
    if _paths_overlap(requested_data_root, development_data_root):
        raise RuntimeError(
            "formal and development data roots must be independent"
        )
    protected_roots = (
        requested_data_root,
        development_data_root,
    )
    _validate_output_target(
        args.report_output,
        protected_roots=protected_roots,
    )

    with _guarded_runtimes(
        {
            "development": development_data_root,
            "formal": requested_data_root,
        }
    ) as runtimes:
        source_authority_sha256 = review_package.get(
            "source_development_authority_sha256"
        )
        if not isinstance(source_authority_sha256, str):
            raise RuntimeError(
                "review package source development authority is invalid"
            )
        source_development_authority = (
            load_persisted_formal_development_authority(
                development_data_root,
                authority_sha256=source_authority_sha256,
            )
        )
        live_development_authority = (
            build_current_formal_development_authority(
                runtimes["development"],
                frozen_exclusion_snapshot_sha256=(
                    source_development_authority.exclusion_snapshot.canonical_sha256
                ),
            )
        )
        if (
            review_package.get("development_authority_sha256")
            != live_development_authority.authority_sha256
        ):
            raise RuntimeError(
                "live development authority changed after review preparation"
            )
        repository = SqliteLockedSetRepository(
            runtime=runtimes["formal"]
        )
        validate_formal_locked_set_review(
            locked_repository=repository,
            dataset_id=args.dataset_id,
            review_package=review_package,
        )
        config = _config(runtimes["formal"].data_root)
        backend = build_ocr_execution_backend(
            config=config,
            repository_root=ROOT,
        )
        try:
            result = evaluate_formal_locked_set_release(
                locked_repository=repository,
                ocr_backend=backend,
                live_development_authority=(
                    live_development_authority
                ),
                dataset_id=args.dataset_id,
                review_package=review_package,
                actor_id=args.actor,
                idempotency_key=args.idempotency_key,
            )
            dataset = repository.get_dataset(args.dataset_id)
        finally:
            backend.close()

    evaluation = result.evaluation
    locked_set_gate_passed = _committed_locked_set_gate_passed(
        evaluation=evaluation,
        committed_report=result.committed_report,
    )
    payload: dict[str, object] = {
        "schema_version": 1,
        "command": "evaluate",
        "generated_at": datetime.now(UTC).isoformat(),
        "offline": True,
        "platform_access": False,
        "source_data_classification": "operator_supplied_locked_set",
        "classification_authority": "operator_declared",
        "dataset_id": evaluation.dataset_id,
        "dataset_state": dataset.state,
        "dataset_record_version": dataset.record_version,
        "evaluation_id": evaluation.evaluation_id,
        "idempotency_key": evaluation.idempotency_key,
        "replayed": result.replayed,
        "gate_passed": evaluation.gate_passed,
        "formal_report": evaluation.formal_report,
        "formal_accuracy_claim": evaluation.formal_accuracy_claim,
        "locked_set_gate_passed": locked_set_gate_passed,
        "loop_7_accepted": False,
        "committed_report_sha256": evaluation.committed_report_sha256,
        "committed_report": result.committed_report,
    }
    output = _write_json_atomic(
        args.report_output,
        payload,
        protected_roots=protected_roots,
    )
    print(
        json.dumps(
            {
                "dataset_id": evaluation.dataset_id,
                "evaluation_id": evaluation.evaluation_id,
                "formal_accuracy_claim": (evaluation.formal_accuracy_claim),
                "locked_set_gate_passed": locked_set_gate_passed,
                "loop_7_accepted": False,
                "output": os.fspath(output),
                "replayed": result.replayed,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if locked_set_gate_passed else 1


def _is_lowercase_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _require_prepared_derived_suite(
    quality: Mapping[str, object],
) -> dict[str, object]:
    suite = quality.get("derived_adversarial_suite")
    if not isinstance(suite, dict):
        raise RuntimeError("derived adversarial suite is required")
    expected_suite_fields = {
        "schema_version",
        "generator_version",
        "source_truth_sha256",
        "scenarios",
        "suite_sha256",
    }
    scenarios = suite.get("scenarios")
    expected_issues = {
        "swapped_slots": "suspected_swapped",
        "both_loading": "both_loading",
        "both_unloading": "both_unloading",
        "exact_duplicate_image": "duplicate_image",
    }
    if (
        set(suite) != expected_suite_fields
        or suite.get("schema_version") != 1
        or suite.get("generator_version") != DERIVED_ADVERSARIAL_GENERATOR_VERSION
        or not _is_lowercase_sha256(suite.get("source_truth_sha256"))
        or not isinstance(scenarios, list)
        or len(scenarios) != len(expected_issues)
        or not _is_lowercase_sha256(suite.get("suite_sha256"))
        or suite.get("suite_sha256")
        != _canonical_sha256({key: value for key, value in suite.items() if key != "suite_sha256"})
    ):
        raise RuntimeError("derived adversarial suite integrity is invalid")
    seen: set[str] = set()
    expected_scenario_fields = {
        "scenario_id",
        "source_sample_ids",
        "loading_slot_image_sha256",
        "unloading_slot_image_sha256",
        "expected_automatic_outcome",
        "expected_role_issue",
    }
    for raw_scenario in scenarios:
        if not isinstance(raw_scenario, dict):
            raise RuntimeError("derived adversarial suite scenario is invalid")
        scenario_id = raw_scenario.get("scenario_id")
        source_sample_ids = raw_scenario.get("source_sample_ids")
        if (
            set(raw_scenario) != expected_scenario_fields
            or not isinstance(scenario_id, str)
            or scenario_id in seen
            or expected_issues.get(scenario_id) != raw_scenario.get("expected_role_issue")
            or raw_scenario.get("expected_automatic_outcome") != "awaiting_review"
            or not isinstance(source_sample_ids, list)
            or not source_sample_ids
            or any(
                not isinstance(sample_id, str) or not sample_id.strip()
                for sample_id in source_sample_ids
            )
            or not _is_lowercase_sha256(raw_scenario.get("loading_slot_image_sha256"))
            or not _is_lowercase_sha256(raw_scenario.get("unloading_slot_image_sha256"))
        ):
            raise RuntimeError("derived adversarial suite scenario is invalid")
        seen.add(scenario_id)
    if seen != set(expected_issues):
        raise RuntimeError("derived adversarial suite scenarios are incomplete")
    return suite


def _bind_review(args: argparse.Namespace) -> int:
    review_package = _read_json_object(
        args.review_package,
        label="review package",
    )
    dataset_id = review_package.get("dataset_id")
    manifest_sha256 = review_package.get("manifest_sha256")
    if not isinstance(dataset_id, str) or not dataset_id.strip():
        raise RuntimeError("review package dataset ID is required")
    if not isinstance(manifest_sha256, str):
        raise RuntimeError("review package manifest SHA-256 is required")
    quality = review_package.get("quality_coverage")
    if not isinstance(quality, dict):
        raise RuntimeError("review package quality coverage must be an object")
    candidate_route = review_package.get("command") == "prepare-candidate"
    if candidate_route and not isinstance(
        review_package.get("candidate_review_source_authority"),
        Mapping,
    ):
        raise RuntimeError("candidate review package source authority is missing")
    if (
        set(quality)
        != {
            "schema_version",
            "dataset_id",
            "manifest_sha256",
            "required_conditions",
            "entries",
            "derived_adversarial_suite",
            "quality_coverage_sha256",
        }
        or quality.get("schema_version") != 2
        or quality.get("dataset_id") != dataset_id
        or quality.get("manifest_sha256") != manifest_sha256
    ):
        raise RuntimeError("review package quality coverage contract is invalid")
    _require_prepared_derived_suite(quality)
    if candidate_route and (
        quality.get("quality_coverage_sha256") != locked_set_quality_coverage_sha256(quality)
    ):
        raise RuntimeError("sealed candidate-review quality coverage changed")
    raw_required = quality.get("required_conditions")
    if (
        not isinstance(raw_required, list)
        or len(raw_required) != len(REQUIRED_NATURAL_QUALITY_CONDITIONS)
        or any(not isinstance(item, str) for item in raw_required)
        or set(raw_required) != set(REQUIRED_NATURAL_QUALITY_CONDITIONS)
    ):
        raise RuntimeError("review package quality conditions are incomplete")
    raw_entries = quality.get("entries")
    if not isinstance(raw_entries, list) or len(raw_entries) != len(
        REQUIRED_NATURAL_QUALITY_CONDITIONS
    ):
        raise RuntimeError("review package requires exactly 10 observed image entries")
    bound_entries: list[dict[str, object]] = []
    seen_conditions: set[str] = set()
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict):
            raise RuntimeError("review package quality entry must be an object")
        entry = dict(raw_entry)
        if not candidate_route:
            entry.pop("review_evidence_sha256", None)
        condition = entry.get("condition")
        if (
            not isinstance(condition, str)
            or condition in seen_conditions
            or condition not in REQUIRED_NATURAL_QUALITY_CONDITIONS
        ):
            raise RuntimeError("review package requires 10 unique observed conditions")
        seen_conditions.add(condition)
        if not candidate_route:
            entry["review_evidence_sha256"] = quality_review_evidence_sha256(
                dataset_id=dataset_id,
                manifest_sha256=manifest_sha256,
                entry=entry,
            )
        bound_entries.append(entry)
    if seen_conditions != set(REQUIRED_NATURAL_QUALITY_CONDITIONS):
        raise RuntimeError("review package requires 10 unique observed conditions")
    bound_quality = dict(quality)
    if not candidate_route:
        bound_quality["entries"] = bound_entries
        bound_quality["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(bound_quality)
    bound_package = dict(review_package)
    bound_package["quality_coverage"] = bound_quality
    bound_package["review_binding"] = {
        "bound_at": datetime.now(UTC).isoformat(),
        "entry_count": len(bound_entries),
        "formal_accuracy_claim": False,
        "manifest_authority_validated": True,
        "schema_version": 2,
    }
    _validate_output_target(
        args.output,
        protected_roots=(args.data_root,),
    )
    config = _config(args.data_root)
    data_root = prepare_startup_environment(config, ROOT)
    _validate_output_target(
        args.output,
        protected_roots=(data_root,),
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
            validation = validate_formal_locked_set_review(
                locked_repository=SqliteLockedSetRepository(runtime=runtime),
                dataset_id=dataset_id,
                review_package=bound_package,
            )
        finally:
            runtime.close()
    output = _write_json_atomic(
        args.output,
        bound_package,
        protected_roots=(data_root,),
    )
    print(
        json.dumps(
            {
                "dataset_id": dataset_id,
                "derived_adversarial_scenario_count": (
                    validation.derived_adversarial_scenario_count
                ),
                "derived_adversarial_suite_sha256": (validation.derived_adversarial_suite_sha256),
                "entry_count": len(bound_entries),
                "formal_accuracy_claim": False,
                "output": os.fspath(output),
                "status": "review_entries_bound_and_validated",
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _validate(args: argparse.Namespace) -> int:
    review_package = _read_json_object(
        args.review_package,
        label="review package",
    )
    config = _config(args.data_root)
    data_root = prepare_startup_environment(config, ROOT)
    _validate_output_target(
        args.output,
        protected_roots=(data_root,),
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
            result = validate_formal_locked_set_review(
                locked_repository=SqliteLockedSetRepository(runtime=runtime),
                dataset_id=args.dataset_id,
                review_package=review_package,
            )
        finally:
            runtime.close()

    payload: dict[str, object] = {
        "schema_version": 1,
        "command": "validate",
        "generated_at": datetime.now(UTC).isoformat(),
        "offline": True,
        "platform_access": False,
        "source_data_classification": "operator_supplied_locked_set",
        "classification_authority": "operator_declared",
        "dataset_id": result.dataset_id,
        "manifest_sha256": result.manifest_sha256,
        "dataset_state": result.dataset_state,
        "dataset_record_version": result.dataset_record_version,
        "scan_fingerprint": result.scan_fingerprint,
        "candidate_count": result.candidate_count,
        "decision_count": result.decision_count,
        "quality_entry_count": result.quality_entry_count,
        "derived_adversarial_scenario_count": (result.derived_adversarial_scenario_count),
        "derived_adversarial_suite_sha256": (result.derived_adversarial_suite_sha256),
        "status": result.status,
        "ready_for_ocr_evaluation": True,
        "formal_accuracy_claim": False,
        "loop_7_accepted": False,
    }
    output = _write_json_atomic(
        args.output,
        payload,
        protected_roots=(data_root,),
    )
    print(
        json.dumps(
            {
                "dataset_id": result.dataset_id,
                "formal_accuracy_claim": False,
                "loop_7_accepted": False,
                "output": os.fspath(output),
                "status": result.status,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _invalidate(args: argparse.Namespace) -> int:
    config = _config(args.data_root)
    data_root = prepare_startup_environment(config, ROOT)
    _validate_output_target(
        args.output,
        protected_roots=(data_root,),
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
            result = SqliteLockedSetRepository(runtime=runtime).invalidate_locked_set(
                dataset_id=args.dataset_id,
                expected_record_version=args.expected_record_version,
                influence_kind=args.influence_kind,
                reason=args.reason,
                actor_id=args.actor,
                idempotency_key=args.idempotency_key,
            )
        finally:
            runtime.close()

    payload: dict[str, object] = {
        "schema_version": 1,
        "command": "invalidate",
        "generated_at": datetime.now(UTC).isoformat(),
        "offline": True,
        "platform_access": False,
        "source_data_classification": "operator_supplied_locked_set",
        "classification_authority": "operator_declared",
        "dataset_id": result.dataset.dataset_id,
        "dataset_state": result.dataset.state,
        "record_version": result.dataset.record_version,
        "invalidation_id": result.invalidation.invalidation_id,
        "influence_kind": result.invalidation.influence_kind,
        "reason": result.invalidation.reason,
        "actor_id": result.invalidation.actor_id,
        "idempotency_key": result.invalidation.idempotency_key,
        "created_at": result.invalidation.created_at,
        "applied": result.applied,
        "formal_accuracy_claim": False,
    }
    output = _write_json_atomic(
        args.output,
        payload,
        protected_roots=(data_root,),
    )
    print(
        json.dumps(
            {
                "applied": result.applied,
                "dataset_id": result.dataset.dataset_id,
                "dataset_state": result.dataset.state,
                "formal_accuracy_claim": False,
                "output": os.fspath(output),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "export-development-authority":
        return _export_development_authority(args)
    if args.command == "prepare":
        return _prepare(args)
    if args.command == "prepare-candidate":
        return _prepare_candidate(args)
    if args.command == "evaluate":
        return _evaluate(args)
    if args.command == "bind-review":
        return _bind_review(args)
    if args.command == "validate":
        return _validate(args)
    if args.command == "invalidate":
        return _invalidate(args)
    raise RuntimeError("unsupported locked-set command")


if __name__ == "__main__":
    sys.exit(main())
