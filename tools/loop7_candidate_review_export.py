from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from dahe import __version__
from dahe.adapters.sqlite.locked_set_review import (
    LockedSetReviewAuthoritySnapshot,
    SqliteLockedSetReviewRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.template_studio.candidate_review_export import (
    CandidateReviewFormalExport,
    build_candidate_review_formal_export,
)
from dahe.application.template_studio.candidate_review_seal import (
    CandidateReviewSeal,
    create_candidate_review_seal,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.system.instance_lock import SingleInstanceGuard
from dahe.verification.locked_set_review_package import (
    LockedSetReviewPackage,
    load_locked_set_review_package,
)

ROOT = Path(__file__).resolve().parents[1]
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class CandidateReviewExportToolError(RuntimeError):
    """Raised when the candidate-review export CLI cannot proceed safely."""


@dataclass(frozen=True, slots=True)
class _ExportContext:
    package: LockedSetReviewPackage
    authority: LockedSetReviewAuthoritySnapshot
    formal_export: CandidateReviewFormalExport


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CandidateReviewExportToolError("development snapshot contains invalid JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _absolute_path(value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    try:
        return candidate.resolve()
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
            "Export the completed offline Loop 7 candidate review without "
            "running OCR or accessing the platform."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    seal_formal = commands.add_parser(
        "seal-formal",
        help="Validate and publish one immutable formal review seal.",
        allow_abbrev=False,
    )
    _add_authority_arguments(seal_formal)

    snapshot_development = commands.add_parser(
        "snapshot-development",
        help="Write a new development-only evidence snapshot outside application data.",
        allow_abbrev=False,
    )
    _add_authority_arguments(snapshot_development)
    snapshot_development.add_argument(
        "--reason",
        type=_required_text,
        required=True,
    )
    snapshot_development.add_argument(
        "--output",
        type=_absolute_path,
        required=True,
    )
    return parser


def _add_authority_arguments(parser: argparse.ArgumentParser) -> None:
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
        "--dataset-id",
        type=_required_text,
        required=True,
    )


def _same_or_descendant(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath(
            (
                os.fspath(path),
                os.fspath(root),
            )
        )
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(os.fspath(root))


def _validate_output_target(
    path: Path,
    *,
    protected_roots: tuple[Path, ...] = (),
) -> Path:
    if not path.is_absolute():
        raise CandidateReviewExportToolError("output path must be absolute")
    try:
        lexical_output = Path(os.path.abspath(os.fspath(path)))
        resolved_output = path.resolve(strict=False)
    except OSError as exc:
        raise CandidateReviewExportToolError("output path cannot be resolved safely") from exc
    if resolved_output.suffix.lower() != ".json":
        raise CandidateReviewExportToolError("output path must use the .json extension")
    for raw_root in protected_roots:
        try:
            lexical_root = Path(os.path.abspath(os.fspath(raw_root)))
            resolved_root = raw_root.resolve(strict=False)
        except OSError as exc:
            raise CandidateReviewExportToolError(
                "protected root cannot be resolved safely"
            ) from exc
        if _same_or_descendant(
            lexical_output,
            lexical_root,
        ) or _same_or_descendant(
            resolved_output,
            resolved_root,
        ):
            raise CandidateReviewExportToolError(
                "output path overlaps a protected application data root"
            )
    if resolved_output.exists() or resolved_output.is_symlink():
        raise CandidateReviewExportToolError("output already exists; choose a new JSON path")
    return resolved_output


def _write_json_exclusive_atomic(
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
    staging = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        with staging.open(
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
            os.link(staging, output)
        except FileExistsError as exc:
            raise CandidateReviewExportToolError(
                "output appeared during the write; no file was replaced"
            ) from exc
        except OSError as exc:
            raise CandidateReviewExportToolError(
                "output could not be committed atomically"
            ) from exc
    except (TypeError, ValueError) as exc:
        raise CandidateReviewExportToolError("development snapshot contains invalid JSON") from exc
    finally:
        staging.unlink(missing_ok=True)
    return output


def _config(data_root: Path) -> AppConfig:
    return AppConfig(
        runtime_profile=RuntimeProfile.DEVELOPMENT,
        data_root=data_root,
    )


def _build_export_context(
    *,
    data_root: Path,
    instance_id: str,
    configured_reviewer_id: str,
    dataset_id: str,
) -> _ExportContext:
    package = load_locked_set_review_package(data_root)
    runtime = SqliteRuntime(
        data_root=data_root,
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
    formal_export = build_candidate_review_formal_export(
        package=package,
        records=authority.latest_records,
        configured_reviewer_id=configured_reviewer_id,
        dataset_id=dataset_id,
    )
    _validate_export_bindings(
        package=package,
        authority=authority,
        formal_export=formal_export,
        dataset_id=dataset_id,
    )
    return _ExportContext(
        package=package,
        authority=authority,
        formal_export=formal_export,
    )


def _lowercase_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise CandidateReviewExportToolError(f"{label} must be a lowercase SHA-256")
    return value


def _count(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CandidateReviewExportToolError(f"{label} must be a non-negative integer")
    return value


def _validate_export_bindings(
    *,
    package: LockedSetReviewPackage,
    authority: LockedSetReviewAuthoritySnapshot,
    formal_export: CandidateReviewFormalExport,
    dataset_id: str,
) -> None:
    source = formal_export.source_authority_payload
    package_sha256 = _lowercase_sha256(
        package.canonical_sha256,
        label="package SHA-256",
    )
    _lowercase_sha256(
        authority.canonical_sha256,
        label="review history authority SHA-256",
    )
    if (
        authority.package_sha256 != package_sha256
        or authority.payload.get("package_sha256") != package_sha256
        or source.get("package_sha256") != package_sha256
        or formal_export.manifest.dataset_id != dataset_id
        or source.get("dataset_id") != dataset_id
        or source.get("manifest_sha256") != formal_export.manifest_sha256
        or source.get("record_set_sha256") != formal_export.record_set_sha256
    ):
        raise CandidateReviewExportToolError(
            "candidate-review export authority bindings do not reconcile"
        )
    _lowercase_sha256(
        formal_export.manifest_sha256,
        label="manifest SHA-256",
    )
    _lowercase_sha256(
        formal_export.record_set_sha256,
        label="record-set SHA-256",
    )
    _lowercase_sha256(
        formal_export.source_authority_sha256,
        label="source authority SHA-256",
    )
    _lowercase_sha256(
        formal_export.quality_coverage_sha256,
        label="quality coverage SHA-256",
    )
    _lowercase_sha256(
        source.get("verified_image_set_sha256"),
        label="verified-image-set SHA-256",
    )
    if (
        _count(
            source.get("record_count"),
            label="source record count",
        )
        != len(authority.latest_records)
        or _count(
            source.get("verified_image_count"),
            label="verified image count",
        )
        != 100
        or authority.payload.get("latest_record_count") != len(authority.latest_records)
        or authority.payload.get("history_record_count") != len(authority.history_records)
        or authority.payload.get("idempotency_record_count") != len(authority.idempotency_records)
    ):
        raise CandidateReviewExportToolError("candidate-review export counts do not reconcile")


def _summary(
    context: _ExportContext,
    *,
    status: str,
    seal: CandidateReviewSeal | None = None,
    snapshot_sha256: str | None = None,
) -> dict[str, object]:
    source = context.formal_export.source_authority_payload
    summary: dict[str, object] = {
        "status": status,
        "latest_record_count": len(context.authority.latest_records),
        "history_record_count": len(context.authority.history_records),
        "record_set_sha256": (context.formal_export.record_set_sha256),
        "review_history_authority_sha256": (context.authority.canonical_sha256),
        "verified_image_count": _count(
            source.get("verified_image_count"),
            label="verified image count",
        ),
        "verified_image_set_sha256": _lowercase_sha256(
            source.get("verified_image_set_sha256"),
            label="verified-image-set SHA-256",
        ),
        "manifest_sha256": (context.formal_export.manifest_sha256),
        "quality_coverage_sha256": (context.formal_export.quality_coverage_sha256),
    }
    if seal is not None:
        summary["seal_sha256"] = _lowercase_sha256(
            seal.seal_sha256,
            label="seal SHA-256",
        )
    if snapshot_sha256 is not None:
        summary["snapshot_sha256"] = _lowercase_sha256(
            snapshot_sha256,
            label="snapshot SHA-256",
        )
    return summary


def _development_snapshot(
    context: _ExportContext,
    *,
    reason: str,
) -> dict[str, object]:
    source = context.formal_export.source_authority_payload
    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "candidate_review_development_snapshot",
        "development_only": True,
        "formal_release_eligible": False,
        "reason": reason,
        "dataset_id": context.formal_export.manifest.dataset_id,
        "package_sha256": context.package.canonical_sha256,
        "record_count": _count(
            source.get("record_count"),
            label="source record count",
        ),
        "record_set_sha256": (context.formal_export.record_set_sha256),
        "history_record_count": len(context.authority.history_records),
        "review_history_authority_sha256": (context.authority.canonical_sha256),
        "verified_image_count": _count(
            source.get("verified_image_count"),
            label="verified image count",
        ),
        "verified_image_set_sha256": _lowercase_sha256(
            source.get("verified_image_set_sha256"),
            label="verified-image-set SHA-256",
        ),
        "manifest_sha256": (context.formal_export.manifest_sha256),
        "quality_coverage_sha256": (context.formal_export.quality_coverage_sha256),
        "source_authority_sha256": (context.formal_export.source_authority_sha256),
    }
    payload["snapshot_sha256"] = _canonical_sha256(payload)
    return payload


def _seal_formal(arguments: argparse.Namespace) -> int:
    config = _config(arguments.data_root)
    data_root = prepare_startup_environment(config, ROOT)
    with SingleInstanceGuard(
        data_root,
        config.port,
        __version__,
    ) as guard:
        context = _build_export_context(
            data_root=data_root,
            instance_id=guard.instance_id,
            configured_reviewer_id=arguments.reviewer_id,
            dataset_id=arguments.dataset_id,
        )
        seal = create_candidate_review_seal(
            review_data_root=context.package.review_root,
            formal_export=context.formal_export,
            review_history_authority_payload=(context.authority.payload),
            review_history_authority_sha256=(context.authority.canonical_sha256),
        )
    print(
        json.dumps(
            _summary(
                context,
                status="formal_seal_validated",
                seal=seal,
            ),
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _snapshot_development(arguments: argparse.Namespace) -> int:
    requested_output = _validate_output_target(
        arguments.output,
        protected_roots=(arguments.data_root,),
    )
    config = _config(arguments.data_root)
    data_root = prepare_startup_environment(config, ROOT)
    requested_output = _validate_output_target(
        requested_output,
        protected_roots=(data_root,),
    )
    with SingleInstanceGuard(
        data_root,
        config.port,
        __version__,
    ) as guard:
        context = _build_export_context(
            data_root=data_root,
            instance_id=guard.instance_id,
            configured_reviewer_id=arguments.reviewer_id,
            dataset_id=arguments.dataset_id,
        )
        requested_output = _validate_output_target(
            requested_output,
            protected_roots=(
                data_root,
                context.package.review_root,
            ),
        )
        payload = _development_snapshot(
            context,
            reason=arguments.reason,
        )
        _write_json_exclusive_atomic(
            requested_output,
            payload,
            protected_roots=(
                data_root,
                context.package.review_root,
            ),
        )
    print(
        json.dumps(
            _summary(
                context,
                status="development_snapshot_created",
                snapshot_sha256=str(payload["snapshot_sha256"]),
            ),
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "seal-formal":
        return _seal_formal(arguments)
    if arguments.command == "snapshot-development":
        return _snapshot_development(arguments)
    raise CandidateReviewExportToolError("unsupported candidate-review export command")


if __name__ == "__main__":
    sys.exit(main())
