from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import cast
from uuid import uuid4

from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthority,
)

SCHEMA_VERSION = 1
KIND = "loop7_development_authority_rollover"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class DevelopmentAuthorityRolloverError(ValueError):
    """Raised when reviewed evidence cannot follow a development build rollover."""


@dataclass(frozen=True, slots=True)
class DevelopmentAuthorityRollover:
    payload: dict[str, object]
    rollover_sha256: str
    source_authority_sha256: str
    execution_authority_sha256: str


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise DevelopmentAuthorityRolloverError(
            "authority rollover is not canonical JSON"
        ) from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise DevelopmentAuthorityRolloverError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _authority_payload(
    authority: FormalDevelopmentAuthority,
    *,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(authority, FormalDevelopmentAuthority):
        raise DevelopmentAuthorityRolloverError(
            f"{label} must be a formal development authority"
        )
    payload = authority.payload
    if not isinstance(payload, Mapping):
        raise DevelopmentAuthorityRolloverError(
            f"{label} payload is invalid"
        )
    if payload.get("authority_sha256") != authority.authority_sha256:
        raise DevelopmentAuthorityRolloverError(
            f"{label} identity is inconsistent"
        )
    return payload


def _semantic_contract(
    authority: FormalDevelopmentAuthority,
    *,
    label: str,
) -> dict[str, object]:
    payload = _authority_payload(authority, label=label)
    contract = payload.get("eligibility_contract")
    if not isinstance(contract, Mapping):
        raise DevelopmentAuthorityRolloverError(
            f"{label} eligibility contract is invalid"
        )
    required = (
        "matcher_fingerprint",
        "policy_fingerprint",
        "runtime_fingerprint",
    )
    result: dict[str, object] = {
        field: _sha256(contract.get(field), label=f"{label} {field}")
        for field in required
    }
    publications = payload.get("shadow_publications")
    if not isinstance(publications, list) or not publications:
        raise DevelopmentAuthorityRolloverError(
            f"{label} shadow publications are unavailable"
        )
    development_fields = (
        "dataset_manifest_sha256",
        "ocr_evidence_sha256",
        "package_sha256",
        "review_history_authority_sha256",
        "source_authority_sha256",
    )
    observed: dict[str, set[str]] = {
        field: set() for field in development_fields
    }
    for publication in publications:
        attempt = (
            publication.get("lifecycle_attempt")
            if isinstance(publication, Mapping)
            else None
        )
        if not isinstance(attempt, Mapping):
            raise DevelopmentAuthorityRolloverError(
                f"{label} lifecycle attempt is unavailable"
            )
        for field in development_fields:
            observed[field].add(
                _sha256(
                    attempt.get(field),
                    label=f"{label} approved development {field}",
                )
            )
    for field, values in observed.items():
        if len(values) != 1:
            raise DevelopmentAuthorityRolloverError(
                f"{label} approved development {field} is inconsistent"
            )
        result[f"approved_development_{field}"] = next(iter(values))
    return result


def _template_semantics(
    authority: FormalDevelopmentAuthority,
    *,
    label: str,
) -> dict[str, dict[str, object]]:
    payload = _authority_payload(authority, label=label)
    publications = payload.get("shadow_publications")
    if not isinstance(publications, list) or not publications:
        raise DevelopmentAuthorityRolloverError(
            f"{label} shadow publications are unavailable"
        )
    result: dict[str, dict[str, object]] = {}
    for raw in publications:
        if not isinstance(raw, Mapping):
            raise DevelopmentAuthorityRolloverError(
                f"{label} shadow publication is invalid"
            )
        family_id = raw.get("family_id")
        version_id = raw.get("version_id")
        content_sha256 = raw.get("content_sha256")
        definition = raw.get("definition")
        version_number = raw.get("version_number")
        parent_version_id = raw.get("parent_version_id")
        if (
            not isinstance(family_id, str)
            or not family_id
            or family_id in result
            or not isinstance(version_id, str)
            or not version_id
            or not isinstance(definition, Mapping)
            or isinstance(version_number, bool)
            or not isinstance(version_number, int)
            or version_number < 1
            or (
                parent_version_id is not None
                and not isinstance(parent_version_id, str)
            )
        ):
            raise DevelopmentAuthorityRolloverError(
                f"{label} shadow publication identity is invalid"
            )
        result[family_id] = {
            "content_sha256": _sha256(
                content_sha256,
                label=f"{label} template content",
            ),
            "definition": dict(definition),
            "parent_version_id": parent_version_id,
            "version_id": version_id,
            "version_number": version_number,
        }
    return result


def _require_unchanged_evidence(
    source: FormalDevelopmentAuthority,
    execution: FormalDevelopmentAuthority,
) -> None:
    source_payload = _authority_payload(source, label="source authority")
    execution_payload = _authority_payload(
        execution,
        label="execution authority",
    )
    exact_fields = (
        "source_exclusion_snapshot_sha256",
        "source_inventory_high_watermark",
        "exclusion_categories",
        "image_identity_count",
        "waybill_identity_count",
        "fingerprint_algorithm_versions",
        "perceptual_fingerprints",
    )
    changed = [
        field
        for field in exact_fields
        if source_payload.get(field) != execution_payload.get(field)
    ]
    if changed:
        raise DevelopmentAuthorityRolloverError(
            "development evidence changed during rollover: "
            + ", ".join(changed)
        )
    if _semantic_contract(
        source,
        label="source authority",
    ) != _semantic_contract(
        execution,
        label="execution authority",
    ):
        raise DevelopmentAuthorityRolloverError(
            "development eligibility semantics changed during rollover"
        )


def build_development_authority_rollover(
    *,
    source_authority: FormalDevelopmentAuthority,
    execution_authority: FormalDevelopmentAuthority,
    reference_evidence_by_family: Mapping[str, Mapping[str, str]],
    version_lineage_by_family: Mapping[
        str,
        tuple[Mapping[str, object], ...],
    ]
    | None = None,
) -> DevelopmentAuthorityRollover:
    """Bind an immutable reviewed source authority to one same-content rebuild."""

    _require_unchanged_evidence(source_authority, execution_authority)
    if source_authority.authority_sha256 == execution_authority.authority_sha256:
        raise DevelopmentAuthorityRolloverError(
            "rollover requires distinct source and execution authorities"
        )
    source_templates = _template_semantics(
        source_authority,
        label="source authority",
    )
    execution_templates = _template_semantics(
        execution_authority,
        label="execution authority",
    )
    if set(source_templates) != set(execution_templates):
        raise DevelopmentAuthorityRolloverError(
            "shadow template families changed during rollover"
        )
    if set(reference_evidence_by_family) != set(source_templates):
        raise DevelopmentAuthorityRolloverError(
            "reference evidence does not cover every shadow family"
        )

    mappings: list[dict[str, object]] = []
    for family_id in sorted(source_templates):
        source = source_templates[family_id]
        execution = execution_templates[family_id]
        source_version_number = source["version_number"]
        execution_version_number = execution["version_number"]
        if (
            not isinstance(source_version_number, int)
            or isinstance(source_version_number, bool)
            or not isinstance(execution_version_number, int)
            or isinstance(execution_version_number, bool)
        ):
            raise DevelopmentAuthorityRolloverError(
                f"shadow template {family_id} version is invalid"
            )
        if (
            source["definition"] != execution["definition"]
            or source["content_sha256"] != execution["content_sha256"]
            or execution["version_id"] == source["version_id"]
            or execution_version_number <= source_version_number
        ):
            raise DevelopmentAuthorityRolloverError(
                f"shadow template {family_id} is not an identical revision"
            )
        raw_lineage = (
            None
            if version_lineage_by_family is None
            else version_lineage_by_family.get(family_id)
        )
        if raw_lineage is None:
            raw_lineage = (
                {
                    "content_sha256": source["content_sha256"],
                    "parent_version_id": source["parent_version_id"],
                    "version_id": source["version_id"],
                    "version_number": source_version_number,
                },
                {
                    "content_sha256": execution["content_sha256"],
                    "parent_version_id": execution["parent_version_id"],
                    "version_id": execution["version_id"],
                    "version_number": execution_version_number,
                },
            )
        lineage: list[dict[str, object]] = []
        for raw_version in raw_lineage:
            if not isinstance(raw_version, Mapping):
                raise DevelopmentAuthorityRolloverError(
                    f"template lineage for {family_id} is invalid"
                )
            version_id = raw_version.get("version_id")
            parent_version_id = raw_version.get("parent_version_id")
            version_number = raw_version.get("version_number")
            if (
                set(raw_version)
                != {
                    "content_sha256",
                    "parent_version_id",
                    "version_id",
                    "version_number",
                }
                or not isinstance(version_id, str)
                or not version_id
                or (
                    parent_version_id is not None
                    and not isinstance(parent_version_id, str)
                )
                or isinstance(version_number, bool)
                or not isinstance(version_number, int)
            ):
                raise DevelopmentAuthorityRolloverError(
                    f"template lineage for {family_id} is invalid"
                )
            lineage.append(
                {
                    "content_sha256": _sha256(
                        raw_version.get("content_sha256"),
                        label=f"{family_id} lineage content",
                    ),
                    "parent_version_id": parent_version_id,
                    "version_id": version_id,
                    "version_number": version_number,
                }
            )
        lineage_invalid = False
        for previous, current in pairwise(lineage):
            previous_number = previous["version_number"]
            current_number = current["version_number"]
            if (
                not isinstance(previous_number, int)
                or isinstance(previous_number, bool)
                or not isinstance(current_number, int)
                or isinstance(current_number, bool)
                or current["content_sha256"]
                != source["content_sha256"]
                or current["parent_version_id"]
                != previous["version_id"]
                or current_number != previous_number + 1
            ):
                lineage_invalid = True
                break
        if (
            len(lineage)
            != execution_version_number - source_version_number + 1
            or lineage[0]["version_id"] != source["version_id"]
            or lineage[0]["version_number"] != source_version_number
            or lineage[-1]["version_id"] != execution["version_id"]
            or lineage[-1]["version_number"] != execution_version_number
            or lineage_invalid
        ):
            raise DevelopmentAuthorityRolloverError(
                f"template lineage for {family_id} is not consecutive and identical"
            )
        raw_reference = reference_evidence_by_family[family_id]
        expected_reference_keys = {
            "source_reference_image_sha256",
            "source_reference_mask_sha256",
            "source_alignment_fingerprint",
            "execution_reference_image_sha256",
            "execution_reference_mask_sha256",
            "execution_alignment_fingerprint",
        }
        if set(raw_reference) != expected_reference_keys:
            raise DevelopmentAuthorityRolloverError(
                f"reference evidence for {family_id} is incomplete"
            )
        reference = {
            key: _sha256(value, label=f"{family_id} {key}")
            for key, value in raw_reference.items()
        }
        for suffix in (
            "reference_image_sha256",
            "reference_mask_sha256",
            "alignment_fingerprint",
        ):
            if (
                reference[f"source_{suffix}"]
                != reference[f"execution_{suffix}"]
            ):
                raise DevelopmentAuthorityRolloverError(
                    f"reference evidence for {family_id} changed"
                )
        mappings.append(
            {
                "content_sha256": source["content_sha256"],
                "definition_sha256": _canonical_sha256(
                    source["definition"]
                ),
                "execution_version_id": execution["version_id"],
                "family_id": family_id,
                "reference_evidence": reference,
                "source_version_id": source["version_id"],
                "version_lineage": lineage,
            }
        )

    source_payload = _authority_payload(
        source_authority,
        label="source authority",
    )
    execution_payload = _authority_payload(
        execution_authority,
        label="execution authority",
    )
    payload: dict[str, object] = {
        "execution_authority_sha256": (
            execution_authority.authority_sha256
        ),
        "execution_build_fingerprint": _sha256(
            execution_payload["eligibility_contract"]["build_fingerprint"],  # type: ignore[index]
            label="execution build fingerprint",
        ),
        "kind": KIND,
        "preserved_contract": _semantic_contract(
            execution_authority,
            label="execution authority",
        ),
        "schema_version": SCHEMA_VERSION,
        "source_authority_sha256": source_authority.authority_sha256,
        "source_build_fingerprint": _sha256(
            source_payload["eligibility_contract"]["build_fingerprint"],  # type: ignore[index]
            label="source build fingerprint",
        ),
        "template_mappings": mappings,
    }
    payload["rollover_sha256"] = _canonical_sha256(payload)
    return parse_development_authority_rollover(payload)


def parse_development_authority_rollover(
    value: Mapping[str, object],
) -> DevelopmentAuthorityRollover:
    payload = json.loads(_canonical_json(dict(value)))
    expected_fields = {
        "execution_authority_sha256",
        "execution_build_fingerprint",
        "kind",
        "preserved_contract",
        "rollover_sha256",
        "schema_version",
        "source_authority_sha256",
        "source_build_fingerprint",
        "template_mappings",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_fields
        or payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("kind") != KIND
    ):
        raise DevelopmentAuthorityRolloverError(
            "authority rollover contract is unsupported"
        )
    rollover_sha256 = _sha256(
        payload.get("rollover_sha256"),
        label="authority rollover SHA-256",
    )
    without_hash = dict(payload)
    without_hash.pop("rollover_sha256")
    if _canonical_sha256(without_hash) != rollover_sha256:
        raise DevelopmentAuthorityRolloverError(
            "authority rollover SHA-256 does not match"
        )
    source_sha256 = _sha256(
        payload.get("source_authority_sha256"),
        label="source authority SHA-256",
    )
    execution_sha256 = _sha256(
        payload.get("execution_authority_sha256"),
        label="execution authority SHA-256",
    )
    _sha256(
        payload.get("source_build_fingerprint"),
        label="source build fingerprint",
    )
    _sha256(
        payload.get("execution_build_fingerprint"),
        label="execution build fingerprint",
    )
    contract = payload.get("preserved_contract")
    mappings = payload.get("template_mappings")
    if (
        not isinstance(contract, dict)
        or not isinstance(mappings, list)
        or not mappings
    ):
        raise DevelopmentAuthorityRolloverError(
            "authority rollover evidence is incomplete"
        )
    return DevelopmentAuthorityRollover(
        payload=payload,
        rollover_sha256=rollover_sha256,
        source_authority_sha256=source_sha256,
        execution_authority_sha256=execution_sha256,
    )


def validate_development_authority_rollover(
    rollover: DevelopmentAuthorityRollover,
    *,
    source_authority: FormalDevelopmentAuthority,
    execution_authority: FormalDevelopmentAuthority,
) -> None:
    reparsed = parse_development_authority_rollover(rollover.payload)
    if reparsed != rollover:
        raise DevelopmentAuthorityRolloverError(
            "authority rollover changed after parsing"
        )
    if (
        rollover.source_authority_sha256
        != source_authority.authority_sha256
        or rollover.execution_authority_sha256
        != execution_authority.authority_sha256
    ):
        raise DevelopmentAuthorityRolloverError(
            "authority rollover does not bind the supplied authorities"
        )
    raw_mappings = rollover.payload.get("template_mappings")
    if not isinstance(raw_mappings, list):
        raise DevelopmentAuthorityRolloverError(
            "authority rollover template mappings are invalid"
        )
    mappings = cast(list[object], raw_mappings)
    reference_evidence: dict[str, dict[str, str]] = {}
    version_lineage: dict[
        str,
        tuple[Mapping[str, object], ...],
    ] = {}
    for raw in mappings:
        if not isinstance(raw, Mapping):
            raise DevelopmentAuthorityRolloverError(
                "authority rollover template mapping is invalid"
            )
        family_id = raw.get("family_id")
        evidence = raw.get("reference_evidence")
        lineage = raw.get("version_lineage")
        if (
            not isinstance(family_id, str)
            or not isinstance(evidence, Mapping)
            or not isinstance(lineage, list)
        ):
            raise DevelopmentAuthorityRolloverError(
                "authority rollover reference evidence is invalid"
            )
        reference_evidence[family_id] = {
            str(key): str(value) for key, value in evidence.items()
        }
        version_lineage[family_id] = tuple(
            dict(item)
            for item in lineage
            if isinstance(item, Mapping)
        )
        if len(version_lineage[family_id]) != len(lineage):
            raise DevelopmentAuthorityRolloverError(
                "authority rollover template lineage is invalid"
            )
    rebuilt = build_development_authority_rollover(
        source_authority=source_authority,
        execution_authority=execution_authority,
        reference_evidence_by_family=reference_evidence,
        version_lineage_by_family=version_lineage,
    )
    if rebuilt != rollover:
        raise DevelopmentAuthorityRolloverError(
            "authority rollover cannot be reproduced"
        )


def write_development_authority_rollover(
    path: Path,
    rollover: DevelopmentAuthorityRollover,
    *,
    failpoint: Callable[[str], None] | None = None,
) -> Path:
    output = path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        existing = load_development_authority_rollover(
            output,
            expected_sha256=rollover.rollover_sha256,
        )
        if existing != rollover:
            raise DevelopmentAuthorityRolloverError(
                "authority rollover output conflicts"
            )
        return output
    content = (_canonical_json(rollover.payload) + "\n").encode("utf-8")
    staged = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if failpoint is not None:
            failpoint("after_rollover_staged_fsync")
        try:
            os.link(staged, output)
        except FileExistsError:
            existing = load_development_authority_rollover(
                output,
                expected_sha256=rollover.rollover_sha256,
            )
            if existing != rollover:
                raise DevelopmentAuthorityRolloverError(
                    "authority rollover output conflicts"
                ) from None
        except OSError as exc:
            raise DevelopmentAuthorityRolloverError(
                "authority rollover could not be published atomically"
            ) from exc
        return output
    finally:
        staged.unlink(missing_ok=True)


def load_development_authority_rollover(
    path: Path,
    *,
    expected_sha256: str | None = None,
) -> DevelopmentAuthorityRollover:
    try:
        resolved = path.resolve(strict=True)
        content = resolved.read_bytes()
        payload = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DevelopmentAuthorityRolloverError(
            "authority rollover is not a readable JSON file"
        ) from exc
    if (
        not resolved.is_file()
        or resolved.is_symlink()
        or not isinstance(payload, dict)
        or content != (_canonical_json(payload) + "\n").encode("utf-8")
    ):
        raise DevelopmentAuthorityRolloverError(
            "authority rollover file is invalid"
        )
    rollover_payload: Mapping[str, object] = payload
    if payload.get("kind") == "loop7_shadow_authority_rollover_result":
        declared_result_sha256 = payload.get("result_sha256")
        without_result_hash = dict(payload)
        without_result_hash.pop("result_sha256", None)
        nested = payload.get("rollover")
        if (
            payload.get("schema_version") != 1
            or not isinstance(declared_result_sha256, str)
            or _canonical_sha256(without_result_hash)
            != declared_result_sha256
            or not isinstance(nested, Mapping)
        ):
            raise DevelopmentAuthorityRolloverError(
                "shadow authority rollover result is invalid"
            )
        rollover_payload = nested
    rollover = parse_development_authority_rollover(
        rollover_payload
    )
    if payload.get("kind") == "loop7_shadow_authority_rollover_result" and (
        payload.get("source_authority_sha256")
        != rollover.source_authority_sha256
        or payload.get("execution_authority_sha256")
        != rollover.execution_authority_sha256
    ):
        raise DevelopmentAuthorityRolloverError(
            "shadow authority rollover result binding is invalid"
        )
    if (
        expected_sha256 is not None
        and rollover.rollover_sha256 != expected_sha256
    ):
        raise DevelopmentAuthorityRolloverError(
            "authority rollover does not match the expected SHA-256"
        )
    return rollover


def persist_development_authority_rollover(
    data_root: Path,
    rollover: DevelopmentAuthorityRollover,
) -> Path:
    root = data_root.resolve(strict=True)
    if not root.is_dir():
        raise DevelopmentAuthorityRolloverError(
            "formal data root is unavailable"
        )
    output_root = root / "development-authority-rollovers"
    output_root.mkdir(exist_ok=True)
    return write_development_authority_rollover(
        output_root / f"{rollover.rollover_sha256}.json",
        rollover,
    )


def load_persisted_development_authority_rollover(
    data_root: Path,
    *,
    rollover_sha256: str,
) -> DevelopmentAuthorityRollover:
    root = data_root.resolve(strict=True)
    return load_development_authority_rollover(
        root
        / "development-authority-rollovers"
        / f"{rollover_sha256}.json",
        expected_sha256=rollover_sha256,
    )
