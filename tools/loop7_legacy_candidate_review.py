from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from PIL import Image, ImageDraw, ImageOps

from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthority,
    FormalDevelopmentAuthorityError,
    load_formal_development_authority,
)
from dahe.verification.legacy_locked_set_candidates import (
    SUPPORTED_IMAGE_SUFFIXES,
    CandidateContractError,
    LegacyCandidateIndex,
    LegacyCandidateWaybill,
    build_candidate_index,
    stage_review_package,
)
from dahe.verification.locked_set import source_waybill_identity_sha256
from dahe.verification.locked_set_review_package import (
    LockedSetReviewPackageError,
    load_locked_set_review_package,
)

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SKIPPED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".npm-cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "browser-profile",
        "cache",
        "caches",
        "models",
        "node_modules",
        "portable-cache",
        "runtime",
        "wheelhouse",
    }
)


class LegacyReviewToolError(RuntimeError):
    """Raised when the one-way legacy review preparation is unsafe."""


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _skip_directory(name: str) -> bool:
    lowered = name.casefold()
    return lowered.startswith(".venv") or lowered in SKIPPED_DIRECTORY_NAMES


def _image_hashes(root: Path) -> set[str]:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise LegacyReviewToolError("exclusion image root must be a directory")
    hashes: set[str] = set()
    for current, directories, files in os.walk(resolved, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if not _skip_directory(name) and not (Path(current) / name).is_symlink()
        )
        current_path = Path(current)
        for name in sorted(files):
            path = current_path / name
            if path.is_symlink() or path.suffix.lower() not in SUPPORTED_IMAGE_SUFFIXES:
                continue
            hashes.add(_file_sha256(path))
    return hashes


def _json_object(path: Path) -> object:
    resolved = path.resolve(strict=True)
    if resolved.suffix.lower() != ".json" or not resolved.is_file():
        raise LegacyReviewToolError("waybill exclusion source must be a JSON file")
    try:
        return json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LegacyReviewToolError("waybill exclusion JSON is not readable") from exc


def _waybill_ids(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "waybill_no" and isinstance(item, str) and item.strip():
                found.add(item.strip())
            else:
                found.update(_waybill_ids(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_waybill_ids(item))
    return found


def _explicit_hashes(path: Path) -> set[str]:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise LegacyReviewToolError("explicit hash source must be a file")
    hashes: set[str] = set()
    for raw_line in resolved.read_text(encoding="utf-8").splitlines():
        value = raw_line.strip().lower()
        if not value:
            continue
        if SHA256_PATTERN.fullmatch(value) is None:
            raise LegacyReviewToolError("explicit hash source contains an invalid SHA-256")
        hashes.add(value)
    return hashes


@dataclass(frozen=True, slots=True)
class ExternalExclusionSnapshot:
    image_hashes: frozenset[str]
    waybill_identity_hashes: frozenset[str]
    source_file_sha256s: tuple[str, ...]

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(
            {
                "image_sha256s": sorted(self.image_hashes),
                "schema_version": 1,
                "source_file_sha256s": list(self.source_file_sha256s),
                "waybill_identity_sha256s": sorted(self.waybill_identity_hashes),
            }
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "image_identity_count": len(self.image_hashes),
            "waybill_identity_count": len(self.waybill_identity_hashes),
            "source_file_sha256s": list(self.source_file_sha256s),
            "canonical_sha256": self.canonical_sha256,
        }

    def to_full_payload(self) -> dict[str, object]:
        return {
            **self.to_payload(),
            "image_sha256s": sorted(self.image_hashes),
            "waybill_identity_sha256s": sorted(self.waybill_identity_hashes),
        }


def collect_external_exclusions(
    *,
    image_roots: tuple[Path, ...],
    waybill_jsons: tuple[Path, ...],
    explicit_hash_files: tuple[Path, ...],
    review_data_roots: tuple[Path, ...] = (),
) -> ExternalExclusionSnapshot:
    image_hashes: set[str] = set()
    for root in image_roots:
        image_hashes.update(_image_hashes(root))
    identities: set[str] = set()
    source_files: list[str] = []
    resolved_review_roots: list[Path] = []
    seen_review_roots: set[str] = set()
    for root in review_data_roots:
        try:
            resolved = root.resolve(strict=True)
        except OSError as exc:
            raise LegacyReviewToolError("published review package is invalid") from exc
        normalized = os.path.normcase(os.fspath(resolved))
        if normalized in seen_review_roots:
            raise LegacyReviewToolError("review data roots must be unique")
        seen_review_roots.add(normalized)
        resolved_review_roots.append(resolved)
    for resolved in resolved_review_roots:
        try:
            package = load_locked_set_review_package(resolved)
            package_path = package.review_root / "review-package.json"
            external_exclusion_path = package.review_root / "external-exclusion-snapshot.json"
            inherited_exclusions = _json_object(external_exclusion_path)
            if not isinstance(inherited_exclusions, dict):
                raise LegacyReviewToolError("published review package is invalid")
            inherited_image_hashes = inherited_exclusions.get("image_sha256s")
            inherited_waybill_hashes = inherited_exclusions.get("waybill_identity_sha256s")
            if (
                not isinstance(inherited_image_hashes, list)
                or not isinstance(inherited_waybill_hashes, list)
                or any(
                    not isinstance(value, str) or SHA256_PATTERN.fullmatch(value.lower()) is None
                    for value in (
                        *inherited_image_hashes,
                        *inherited_waybill_hashes,
                    )
                )
            ):
                raise LegacyReviewToolError("published review package is invalid")
            normalized_inherited_image_hashes = [
                cast(str, value).lower() for value in inherited_image_hashes
            ]
            normalized_inherited_waybill_hashes = [
                cast(str, value).lower() for value in inherited_waybill_hashes
            ]
            source_files.extend(
                (
                    _file_sha256(package_path),
                    _file_sha256(external_exclusion_path),
                )
            )
        except (LockedSetReviewPackageError, OSError) as exc:
            raise LegacyReviewToolError("published review package is invalid") from exc
        image_hashes.update(package.images_by_sha256)
        image_hashes.update(normalized_inherited_image_hashes)
        identities.update(item.waybill_identity_sha256 for item in package.items)
        identities.update(normalized_inherited_waybill_hashes)
    for path in waybill_jsons:
        resolved = path.resolve(strict=True)
        source_files.append(_file_sha256(resolved))
        for raw_waybill_id in _waybill_ids(_json_object(resolved)):
            identities.add(
                source_waybill_identity_sha256(
                    source_namespace="chengfeng_waybill_no",
                    source_id=raw_waybill_id,
                )
            )
    for path in explicit_hash_files:
        resolved = path.resolve(strict=True)
        source_files.append(_file_sha256(resolved))
        image_hashes.update(_explicit_hashes(resolved))
    return ExternalExclusionSnapshot(
        image_hashes=frozenset(image_hashes),
        waybill_identity_hashes=frozenset(identities),
        source_file_sha256s=tuple(sorted(set(source_files))),
    )


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return path.resolve()


def _new_output_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    path = Path(os.path.abspath(os.fspath(path)))
    if path.exists():
        raise argparse.ArgumentTypeError("output path must not already exist")
    return path


def _same_or_descendant(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.fspath(path), os.fspath(root)))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(os.fspath(root))


def _require_output_outside_legacy(
    output_path: Path,
    *,
    legacy_data_root: Path,
) -> None:
    try:
        legacy_lexical = Path(os.path.abspath(os.fspath(legacy_data_root)))
        legacy_resolved = legacy_data_root.resolve(strict=True)
        output_lexical = Path(os.path.abspath(os.fspath(output_path)))
        output_resolved = output_path.resolve(strict=False)
    except OSError as exc:
        raise LegacyReviewToolError(
            "legacy data root or output path cannot be resolved safely"
        ) from exc
    if not legacy_resolved.is_dir():
        raise LegacyReviewToolError("legacy data root must be a directory")
    if _same_or_descendant(
        output_lexical,
        legacy_lexical,
    ) or _same_or_descendant(output_resolved, legacy_resolved):
        raise LegacyReviewToolError("output must stay outside the legacy data root")


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--legacy-data-root", type=_absolute_path, required=True)
    parser.add_argument("--acquisition-root", type=_absolute_path, required=True)
    parser.add_argument(
        "--development-authority",
        type=_absolute_path,
        required=True,
        help=(
            "Canonical authority exported from the isolated development "
            "data root and revalidated during formal preparation."
        ),
    )
    parser.add_argument(
        "--result-root",
        type=_absolute_path,
        action="append",
        default=[],
    )
    parser.add_argument(
        "--exclude-image-root",
        type=_absolute_path,
        action="append",
        default=[],
    )
    parser.add_argument(
        "--exclude-waybill-json",
        type=_absolute_path,
        action="append",
        default=[],
    )
    parser.add_argument(
        "--explicit-excluded-image-hashes",
        type=_absolute_path,
        action="append",
        default=[],
    )
    parser.add_argument(
        "--exclude-review-data-root",
        type=_absolute_path,
        action="append",
        default=[],
        help=(
            "Absolute application data root containing one published "
            "locked-set-review candidate package to exclude."
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a de-identified, offline Loop 7 review package from "
            "immutable legacy evidence without opening a legacy database."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    discover = commands.add_parser("discover", allow_abbrev=False)
    _add_source_arguments(discover)
    discover.add_argument("--output", type=_new_output_path, required=True)
    discover.add_argument("--recommend", type=int, default=120)

    create_selection = commands.add_parser(
        "create-selection",
        help=(
            "Freeze exactly 50 candidate IDs from one discovery JSON into "
            "the snapshot-bound selection contract used by stage."
        ),
        allow_abbrev=False,
    )
    create_selection.add_argument(
        "--legacy-data-root",
        type=_absolute_path,
        required=True,
        help="Absolute legacy root used only to enforce the output boundary.",
    )
    create_selection.add_argument(
        "--discovery",
        type=_absolute_path,
        required=True,
        help="Absolute path to the unchanged discover output JSON.",
    )
    create_selection.add_argument(
        "--candidate-ids-file",
        type=_absolute_path,
        required=True,
        help="UTF-8 text with exactly one candidate ID per non-empty line.",
    )
    create_selection.add_argument(
        "--output",
        type=_new_output_path,
        required=True,
        help="New absolute path for the generated selection JSON.",
    )

    sheets = commands.add_parser("contact-sheets", allow_abbrev=False)
    _add_source_arguments(sheets)
    sheets.add_argument("--selection", type=_absolute_path, required=True)
    sheets.add_argument("--output-root", type=_new_output_path, required=True)
    sheets.add_argument("--pairs-per-page", type=int, default=8)

    stage = commands.add_parser("stage", allow_abbrev=False)
    _add_source_arguments(stage)
    stage.add_argument("--selection", type=_absolute_path, required=True)
    stage.add_argument("--output-root", type=_new_output_path, required=True)
    stage.add_argument("--package-id", required=True)
    return parser


def _build_index(
    arguments: argparse.Namespace,
) -> tuple[
    LegacyCandidateIndex,
    ExternalExclusionSnapshot,
    FormalDevelopmentAuthority,
]:
    try:
        authority = load_formal_development_authority(arguments.development_authority)
    except FormalDevelopmentAuthorityError as exc:
        raise LegacyReviewToolError("development exclusion authority is invalid") from exc
    declared = collect_external_exclusions(
        image_roots=tuple(arguments.exclude_image_root),
        waybill_jsons=tuple(arguments.exclude_waybill_json),
        explicit_hash_files=tuple(arguments.explicit_excluded_image_hashes),
        review_data_roots=tuple(arguments.exclude_review_data_root),
    )
    if not declared.image_hashes.issubset(
        authority.image_sha256s
    ) or not declared.waybill_identity_hashes.issubset(authority.waybill_identity_sha256s):
        raise LegacyReviewToolError(
            "caller exclusions are not contained in the development authority"
        )
    exclusions = ExternalExclusionSnapshot(
        image_hashes=authority.image_sha256s,
        waybill_identity_hashes=authority.waybill_identity_sha256s,
        source_file_sha256s=(authority.authority_sha256,),
    )
    index = build_candidate_index(
        legacy_data_root=arguments.legacy_data_root,
        acquisition_root=arguments.acquisition_root,
        excluded_image_hashes=exclusions.image_hashes,
        excluded_waybill_identity_hashes=exclusions.waybill_identity_hashes,
        legacy_result_roots=tuple(arguments.result_root),
    )
    return index, exclusions, authority


def _candidate_score(waybill: LegacyCandidateWaybill) -> tuple[int, str]:
    clues = set(waybill.selection_clues)
    score = 0
    if "historical_hash_reuse_hint" in clues:
        score += 1000
    if any(clue.startswith("rotation_") and clue != "rotation_0_hint" for clue in clues):
        score += 800
    if "legacy_review_hint" in clues:
        score += 500
    dimensions = {(image.width // 250, image.height // 250) for image in waybill.images}
    score += len(dimensions) * 10
    score += int(waybill.waybill_identity_sha256[:4], 16) % 97
    return score, waybill.candidate_id


def recommend_candidate_ids(
    index: LegacyCandidateIndex,
    *,
    limit: int,
) -> list[str]:
    if limit < 1:
        raise LegacyReviewToolError("recommendation count must be positive")
    ordered = sorted(
        index.waybills,
        key=lambda item: (-_candidate_score(item)[0], _candidate_score(item)[1]),
    )
    return [waybill.candidate_id for waybill in ordered[:limit]]


def _write_json_new(path: Path, payload: object) -> Path:
    resolved = path.resolve()
    if resolved.exists():
        raise LegacyReviewToolError("output JSON must not already exist")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    temporary = resolved.with_name(f".{resolved.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, resolved)
        except FileExistsError as exc:
            raise LegacyReviewToolError(
                "output JSON appeared during atomic publish"
            ) from exc
        except OSError as exc:
            raise LegacyReviewToolError(
                "output JSON could not be committed atomically"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)
    return resolved


class _SelectionIndexBinding(Protocol):
    @property
    def source_manifest_sha256s(self) -> tuple[str, ...]: ...

    @property
    def exclusion_snapshot_sha256(self) -> str: ...

    def to_payload(self) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class _FrozenSelectionIndex:
    source_manifest_sha256s: tuple[str, ...]
    exclusion_snapshot_sha256: str
    candidate_index_sha256: str

    def to_payload(self) -> dict[str, object]:
        return {"canonical_sha256": self.candidate_index_sha256}


def _discovery_candidate_index(path: Path) -> dict[str, object]:
    discovery = _json_object(path)
    if not isinstance(discovery, dict):
        raise LegacyReviewToolError("discovery must be a JSON object")
    if (
        discovery.get("schema_version") != 1
        or discovery.get("kind") != "legacy_locked_set_discovery"
        or discovery.get("offline") is not True
        or discovery.get("legacy_database_opened") is not False
    ):
        raise LegacyReviewToolError("discovery contract is unsupported")
    raw_index = discovery.get("candidate_index")
    if not isinstance(raw_index, dict):
        raise LegacyReviewToolError("discovery candidate index must be an object")
    index = cast(dict[str, object], raw_index)
    if index.get("schema_version") != 1 or index.get("kind") != "legacy_locked_set_candidate_index":
        raise LegacyReviewToolError("discovery candidate index contract is unsupported")
    declared_hash = index.get("canonical_sha256")
    if not isinstance(declared_hash, str) or SHA256_PATTERN.fullmatch(declared_hash) is None:
        raise LegacyReviewToolError("discovery candidate index canonical SHA-256 is invalid")
    without_hash = {key: value for key, value in index.items() if key != "canonical_sha256"}
    if _canonical_sha256(without_hash) != declared_hash:
        raise LegacyReviewToolError("discovery candidate index canonical SHA-256 does not match")
    manifest_hashes = index.get("source_manifest_sha256s")
    if (
        not isinstance(manifest_hashes, list)
        or not manifest_hashes
        or any(
            not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None
            for value in manifest_hashes
        )
        or len(manifest_hashes) != len(set(manifest_hashes))
    ):
        raise LegacyReviewToolError("discovery source manifest SHA-256 contract is invalid")
    exclusion_hash = index.get("exclusion_snapshot_sha256")
    if not isinstance(exclusion_hash, str) or SHA256_PATTERN.fullmatch(exclusion_hash) is None:
        raise LegacyReviewToolError("discovery exclusion snapshot SHA-256 is invalid")
    return index


def _discovery_development_authority_sha256(path: Path) -> str:
    discovery = _json_object(path)
    if not isinstance(discovery, dict):
        raise LegacyReviewToolError("discovery must be a JSON object")
    value = discovery.get("development_authority_sha256")
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise LegacyReviewToolError("discovery development authority SHA-256 is invalid")
    return value


def _frozen_candidate_ids(path: Path) -> list[str]:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LegacyReviewToolError("candidate ID file does not exist") from exc
    if not resolved.is_file():
        raise LegacyReviewToolError("candidate ID source must be a file")
    try:
        values = [
            line.strip()
            for line in resolved.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError) as exc:
        raise LegacyReviewToolError("candidate ID source must be readable UTF-8 text") from exc
    if len(values) != 50:
        raise LegacyReviewToolError("candidate ID source must contain exactly 50 non-empty lines")
    if len(values) != len(set(values)):
        raise LegacyReviewToolError("candidate IDs must be unique")
    if any(len(value) > 200 for value in values):
        raise LegacyReviewToolError("candidate ID is too long")
    return values


def create_selection_file(
    *,
    legacy_data_root: Path,
    discovery_path: Path,
    candidate_ids_path: Path,
    output_path: Path,
) -> Path:
    """Freeze operator-selected IDs against one unchanged discovery snapshot."""

    _require_output_outside_legacy(
        output_path,
        legacy_data_root=legacy_data_root,
    )
    resolved_output = output_path.resolve(strict=False)
    if resolved_output.exists():
        raise LegacyReviewToolError("output JSON must not already exist")
    index = _discovery_candidate_index(discovery_path)
    raw_waybills = index.get("waybills")
    if not isinstance(raw_waybills, list):
        raise LegacyReviewToolError("discovery candidate waybills must be an array")
    available_ids: set[str] = set()
    for raw_waybill in raw_waybills:
        if not isinstance(raw_waybill, dict):
            raise LegacyReviewToolError("discovery candidate waybill must be an object")
        candidate_id = raw_waybill.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id.strip():
            raise LegacyReviewToolError("discovery candidate ID contract is invalid")
        normalized = candidate_id.strip()
        if normalized in available_ids:
            raise LegacyReviewToolError("discovery candidate IDs must be unique")
        available_ids.add(normalized)
    candidate_ids = _frozen_candidate_ids(candidate_ids_path)
    if any(candidate_id not in available_ids for candidate_id in candidate_ids):
        raise LegacyReviewToolError("candidate ID is not present in the frozen discovery")
    manifest_hashes = cast(list[str], index["source_manifest_sha256s"])
    candidate_index_hash = cast(str, index["canonical_sha256"])
    exclusion_hash = cast(str, index["exclusion_snapshot_sha256"])
    development_authority_sha256 = _discovery_development_authority_sha256(discovery_path)
    payload = {
        "schema_version": 1,
        "kind": "locked_set_candidate_selection",
        "candidate_index_sha256": candidate_index_hash,
        "source_manifest_sha256s": manifest_hashes,
        "exclusion_snapshot_sha256": exclusion_hash,
        "development_authority_sha256": (development_authority_sha256),
        "candidate_ids": candidate_ids,
    }
    binding = _FrozenSelectionIndex(
        source_manifest_sha256s=tuple(manifest_hashes),
        exclusion_snapshot_sha256=exclusion_hash,
        candidate_index_sha256=candidate_index_hash,
    )
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    temporary = resolved_output.with_name(f".{resolved_output.name}.{uuid4().hex}.tmp.json")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if (
            _selection(
                temporary,
                binding,
                development_authority_sha256=(development_authority_sha256),
            )
            != candidate_ids
        ):
            raise LegacyReviewToolError("selection round-trip changed candidate IDs")
        if resolved_output.exists():
            raise LegacyReviewToolError("output JSON must not already exist")
        temporary.rename(resolved_output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return resolved_output


def _selection(
    path: Path,
    index: _SelectionIndexBinding,
    *,
    development_authority_sha256: str,
) -> list[str]:
    payload = _json_object(path)
    if not isinstance(payload, dict):
        raise LegacyReviewToolError("selection must be a JSON object")
    if (
        payload.get("schema_version") != 1
        or payload.get("kind") != "locked_set_candidate_selection"
        or payload.get("candidate_index_sha256") != index.to_payload()["canonical_sha256"]
        or payload.get("source_manifest_sha256s") != list(index.source_manifest_sha256s)
        or payload.get("exclusion_snapshot_sha256") != index.exclusion_snapshot_sha256
        or payload.get("development_authority_sha256") != development_authority_sha256
    ):
        raise LegacyReviewToolError("selection candidate index snapshot does not match")
    raw = payload.get("candidate_ids")
    if not isinstance(raw, list) or any(
        not isinstance(value, str) or not value.strip() for value in raw
    ):
        raise LegacyReviewToolError("selection candidate_ids must be a text array")
    values = cast(list[str], raw)
    if len(values) != len(set(values)):
        raise LegacyReviewToolError("selection candidate IDs must be unique")
    return values


def _fit_image(path: Path, size: tuple[int, int]) -> Image.Image:
    with Image.open(path) as source:
        source.load()
        normalized = ImageOps.exif_transpose(source).convert("RGB")
    contained = ImageOps.contain(normalized, size, Image.Resampling.LANCZOS)
    canvas = Image.new("RGB", size, "white")
    left = (size[0] - contained.width) // 2
    top = (size[1] - contained.height) // 2
    canvas.paste(contained, (left, top))
    return canvas


def create_contact_sheets(
    *,
    index: LegacyCandidateIndex,
    candidate_ids: list[str],
    output_root: Path,
    pairs_per_page: int,
) -> list[Path]:
    if pairs_per_page < 1 or pairs_per_page > 12:
        raise LegacyReviewToolError("pairs per page must be between 1 and 12")
    resolved_output = output_root.resolve()
    if resolved_output.exists():
        raise LegacyReviewToolError("contact-sheet output must not already exist")
    candidates = {waybill.candidate_id: waybill for waybill in index.waybills}
    try:
        selected = [candidates[candidate_id] for candidate_id in candidate_ids]
    except KeyError as exc:
        raise LegacyReviewToolError("contact-sheet selection is stale") from exc
    resolved_output.mkdir(parents=True)
    image_size = (680, 320)
    row_height = 382
    page_width = 1440
    pages: list[Path] = []
    for page_index, offset in enumerate(
        range(0, len(selected), pairs_per_page),
        start=1,
    ):
        page_items = selected[offset : offset + pairs_per_page]
        page = Image.new(
            "RGB",
            (page_width, 44 + row_height * len(page_items)),
            "#f4f4f5",
        )
        draw = ImageDraw.Draw(page)
        draw.text((20, 14), f"Loop 7 candidate sheet {page_index}", fill="#111827")
        for row, waybill in enumerate(page_items):
            top = 44 + row * row_height
            draw.rectangle(
                (12, top + 2, page_width - 12, top + row_height - 8),
                fill="white",
                outline="#cbd5e1",
            )
            clue_text = ", ".join(waybill.selection_clues) or "coverage sample"
            draw.text(
                (24, top + 12),
                f"{waybill.candidate_id} | {clue_text}",
                fill="#111827",
            )
            for column, image in enumerate(waybill.images):
                preview = _fit_image(image.source_path, image_size)
                left = 24 + column * 704
                page.paste(preview, (left, top + 40))
                draw.text(
                    (left, top + 364),
                    f"submitted {image.submitted_slot}",
                    fill="#334155",
                )
        page_path = resolved_output / f"candidate-sheet-{page_index:02d}.jpg"
        page.save(page_path, format="JPEG", quality=88, optimize=True)
        pages.append(page_path)
    return pages


def _discover(arguments: argparse.Namespace) -> int:
    _require_output_outside_legacy(
        arguments.output,
        legacy_data_root=arguments.legacy_data_root,
    )
    index, exclusions, authority = _build_index(arguments)
    payload = {
        "schema_version": 1,
        "kind": "legacy_locked_set_discovery",
        "offline": True,
        "legacy_database_opened": False,
        "exclusions": exclusions.to_payload(),
        "development_authority_sha256": (authority.authority_sha256),
        "candidate_index": index.to_payload(),
        "recommended_candidate_ids": recommend_candidate_ids(
            index,
            limit=arguments.recommend,
        ),
    }
    output = _write_json_new(arguments.output, payload)
    print(
        json.dumps(
            {
                "eligible_waybills": index.eligible_waybill_count,
                "excluded_waybills": index.excluded_waybill_count,
                "exclusion_images": len(exclusions.image_hashes),
                "output": os.fspath(output),
                "next_command": "create-selection",
                "candidate_ids_file_contract": (
                    "exactly 50 unique candidate IDs, one per non-empty UTF-8 line"
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _create_selection(arguments: argparse.Namespace) -> int:
    output = create_selection_file(
        legacy_data_root=arguments.legacy_data_root,
        discovery_path=arguments.discovery,
        candidate_ids_path=arguments.candidate_ids_file,
        output_path=arguments.output,
    )
    payload = cast(dict[str, object], _json_object(output))
    print(
        json.dumps(
            {
                "candidate_count": len(cast(list[str], payload["candidate_ids"])),
                "candidate_index_sha256": payload["candidate_index_sha256"],
                "output": os.fspath(output),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _contact_sheets(arguments: argparse.Namespace) -> int:
    _require_output_outside_legacy(
        arguments.output_root,
        legacy_data_root=arguments.legacy_data_root,
    )
    index, _, authority = _build_index(arguments)
    pages = create_contact_sheets(
        index=index,
        candidate_ids=_selection(
            arguments.selection,
            index,
            development_authority_sha256=authority.authority_sha256,
        ),
        output_root=arguments.output_root,
        pairs_per_page=arguments.pairs_per_page,
    )
    print(
        json.dumps(
            {
                "output_root": os.fspath(arguments.output_root),
                "page_count": len(pages),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _stage(arguments: argparse.Namespace) -> int:
    _require_output_outside_legacy(
        arguments.output_root,
        legacy_data_root=arguments.legacy_data_root,
    )
    index, exclusions, authority = _build_index(arguments)
    package = stage_review_package(
        index=index,
        selected_candidate_ids=_selection(
            arguments.selection,
            index,
            development_authority_sha256=authority.authority_sha256,
        ),
        output_root=arguments.output_root,
        package_id=arguments.package_id,
        external_exclusion_snapshot=exclusions.to_full_payload(),
        development_authority=authority.payload,
    )
    print(
        json.dumps(
            {
                "output_root": os.fspath(arguments.output_root),
                "package_id": package["package_id"],
                "status": package["status"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "discover":
            return _discover(arguments)
        if arguments.command == "create-selection":
            return _create_selection(arguments)
        if arguments.command == "contact-sheets":
            return _contact_sheets(arguments)
        if arguments.command == "stage":
            return _stage(arguments)
        raise LegacyReviewToolError("unsupported command")
    except (CandidateContractError, LegacyReviewToolError, OSError) as exc:
        print(f"legacy review preparation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
