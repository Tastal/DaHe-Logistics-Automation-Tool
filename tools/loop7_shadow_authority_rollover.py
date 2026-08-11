from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

from dahe import __version__
from dahe.adapters.ocr.runtime_factory import build_ocr_execution_backend
from dahe.adapters.sqlite.locked_set import SqliteLockedSetRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_studio import (
    SqliteTemplateRepository,
    TemplateFamilyCurrent,
    TemplatePersistenceError,
)
from dahe.application.template_studio.development_authority_rollover import (
    DevelopmentAuthorityRolloverError,
    build_development_authority_rollover,
    persist_development_authority_rollover,
)
from dahe.application.template_studio.development_evaluation import (
    development_matcher_fingerprint,
    development_policy_fingerprint,
)
from dahe.application.template_studio.fingerprints import (
    current_template_ocr_runtime_set_fingerprint,
    current_template_pipeline_build_fingerprint,
)
from dahe.application.template_studio.formal_development_authority import (
    FormalDevelopmentAuthority,
    FormalDevelopmentAuthorityError,
    build_current_formal_development_authority,
    build_formal_development_authority,
    load_persisted_formal_development_authority,
    persist_formal_development_authority,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.domain.ticket.templates import TemplateLifecycle, TemplateVersion
from dahe.jobs.ocr_execution import AsyncOcrExecutionBackend
from dahe.system.instance_lock import SingleInstanceGuard

ROOT = Path(__file__).resolve().parents[1]
ACTOR_ID = "loop7-build-rollover"
_RUNTIME_KINDS: tuple[Literal["cpu", "gpu"], ...] = ("cpu", "gpu")


class ShadowAuthorityRolloverToolError(RuntimeError):
    """Raised when the supported same-content rollover cannot complete."""


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Clone the current Loop 7 shadow templates without semantic "
            "changes and bind them to the current build."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--data-root", type=_absolute_path, required=True)
    parser.add_argument("--ocr-evidence", type=_absolute_path, required=True)
    parser.add_argument("--output", type=_absolute_path, required=True)
    return parser


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _same_or_descendant(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath(
            (os.fspath(path), os.fspath(root))
        )
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(
        os.fspath(root)
    )


def _validate_output(path: Path, *, data_root: Path) -> Path:
    resolved = path.resolve(strict=False)
    if resolved.suffix.lower() != ".json":
        raise ShadowAuthorityRolloverToolError(
            "output path must use the .json extension"
        )
    if resolved.is_symlink():
        raise ShadowAuthorityRolloverToolError(
            "output path must not be a symbolic link"
        )
    if _same_or_descendant(resolved, data_root):
        raise ShadowAuthorityRolloverToolError(
            "output must stay outside application data"
        )
    return resolved


def _write_idempotent_json(
    path: Path,
    payload: Mapping[str, object],
    *,
    data_root: Path,
) -> Path:
    output = _validate_output(path, data_root=data_root)
    content = (_canonical_json(dict(payload)) + "\n").encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        try:
            existing = output.read_bytes()
        except OSError as exc:
            raise ShadowAuthorityRolloverToolError(
                "existing output cannot be read"
            ) from exc
        if existing != content:
            raise ShadowAuthorityRolloverToolError(
                "output already exists with different evidence"
            )
        return output
    staged = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, output)
        except FileExistsError:
            if output.read_bytes() != content:
                raise ShadowAuthorityRolloverToolError(
                    "output appeared with different evidence"
                ) from None
        except OSError as exc:
            raise ShadowAuthorityRolloverToolError(
                "output could not be published atomically"
            ) from exc
    finally:
        staged.unlink(missing_ok=True)
    return output


def _qualified_runtime_fingerprint(
    backend: AsyncOcrExecutionBackend,
) -> str:
    identities: list[dict[str, str]] = []
    for runtime_kind in _RUNTIME_KINDS:
        if not backend.has_runtime(runtime_kind):
            raise ShadowAuthorityRolloverToolError(
                "shadow rollover requires qualified CPU and GPU runtimes"
            )
        identity = backend.identity_for(runtime_kind)
        identities.append(
            {
                "profile_id": identity.profile_id,
                "runtime_fingerprint": identity.runtime_fingerprint,
                "runtime_kind": identity.runtime_kind,
            }
        )
    return current_template_ocr_runtime_set_fingerprint(identities)


def _reference_payload(
    current: TemplateFamilyCurrent,
    *,
    prefix: str,
) -> dict[str, str]:
    return {
        f"{prefix}_alignment_fingerprint": (
            current.alignment_fingerprint
        ),
        f"{prefix}_reference_image_sha256": (
            current.reference_image_sha256
        ),
        f"{prefix}_reference_mask_sha256": (
            current.reference_mask_sha256
        ),
    }


def _source_state_path(
    data_root: Path,
    *,
    build_fingerprint: str,
) -> Path:
    return (
        data_root
        / "development"
        / "authority-rollovers"
        / build_fingerprint
        / "source-state.json"
    )


def _load_state(
    path: Path,
    *,
    expected_kind: str = "loop7_shadow_rollover_source_state",
) -> dict[str, object]:
    try:
        content = path.read_bytes()
        value = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ShadowAuthorityRolloverToolError(
            "rollover source state is unreadable"
        ) from exc
    if (
        not isinstance(value, dict)
        or content != (_canonical_json(value) + "\n").encode("utf-8")
        or value.get("kind") != expected_kind
        or value.get("schema_version") != 1
    ):
        raise ShadowAuthorityRolloverToolError(
            "rollover source state is invalid"
        )
    declared = value.get("state_sha256")
    without_hash = dict(value)
    without_hash.pop("state_sha256", None)
    if (
        not isinstance(declared, str)
        or _canonical_sha256(without_hash) != declared
    ):
        raise ShadowAuthorityRolloverToolError(
            "rollover source state hash does not match"
        )
    return value


def _write_state(
    path: Path,
    payload: dict[str, object],
) -> dict[str, object]:
    without_hash = dict(payload)
    without_hash["state_sha256"] = _canonical_sha256(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (_canonical_json(without_hash) + "\n").encode("utf-8")
    if path.exists():
        existing = _load_state(
            path,
            expected_kind=str(payload["kind"]),
        )
        if existing != without_hash:
            raise ShadowAuthorityRolloverToolError(
                "rollover source state conflicts"
            )
        return existing
    staged = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with staged.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, path)
        except FileExistsError:
            existing = _load_state(
                path,
                expected_kind=str(payload["kind"]),
            )
            if existing != without_hash:
                raise ShadowAuthorityRolloverToolError(
                    "rollover source state conflicts"
                ) from None
    finally:
        staged.unlink(missing_ok=True)
    return without_hash


def _source_state(
    *,
    data_root: Path,
    build_fingerprint: str,
    repository: SqliteTemplateRepository,
    runtime: SqliteRuntime,
) -> dict[str, object]:
    path = _source_state_path(
        data_root,
        build_fingerprint=build_fingerprint,
    )
    if path.exists():
        return _load_state(path)
    prior_states: list[
        tuple[
            int,
            str,
            dict[str, object],
            FormalDevelopmentAuthority,
        ]
    ] = []
    rollover_root = data_root / "development" / "authority-rollovers"
    if rollover_root.is_dir():
        for candidate_path in rollover_root.glob("*/source-state.json"):
            candidate = _load_state(candidate_path)
            authority_sha256 = candidate.get(
                "source_authority_sha256"
            )
            if not isinstance(authority_sha256, str):
                continue
            authority = load_persisted_formal_development_authority(
                data_root,
                authority_sha256=authority_sha256,
            )
            prior_states.append(
                (
                    authority.inventory_high_watermark,
                    authority.authority_sha256,
                    candidate,
                    authority,
                )
            )
    if prior_states:
        _watermark, _sha256_value, anchor, authority_object = min(
            prior_states,
            key=lambda item: (item[0], item[1]),
        )
        anchor_families = anchor.get("families")
        if not isinstance(anchor_families, list):
            raise ShadowAuthorityRolloverToolError(
                "rollover source anchor families are invalid"
            )
        authority = authority_object
        publication_by_family = {
            version.definition.family_id: version
            for version in authority.shadow_templates
        }
        anchor_family_records: list[dict[str, object]] = []
        for raw in anchor_families:
            if not isinstance(raw, Mapping):
                raise ShadowAuthorityRolloverToolError(
                    "rollover source anchor family is invalid"
                )
            family_id = str(raw["family_id"])
            source = publication_by_family.get(family_id)
            current = repository.get_family_current(family_id)
            if (
                source is None
                or current.summary.shadow_version_id is None
                or current.version.content_sha256
                != source.content_sha256
                or current.reference_image_sha256
                != str(raw["source_reference_image_sha256"])
                or current.reference_mask_sha256
                != str(raw["source_reference_mask_sha256"])
                or current.alignment_fingerprint
                != str(raw["source_alignment_fingerprint"])
            ):
                raise ShadowAuthorityRolloverToolError(
                    "rollover source anchor no longer matches the live family"
                )
            anchor_family_records.append(
                {
                    **dict(raw),
                    "source_version_number": source.version_number,
                }
            )
        return _write_state(
            path,
            {
                "build_fingerprint": build_fingerprint,
                "families": sorted(
                    anchor_family_records,
                    key=lambda value: str(value["family_id"]),
                ),
                "kind": "loop7_shadow_rollover_source_state",
                "schema_version": 1,
                "source_authority_sha256": (
                    authority.authority_sha256
                ),
            },
        )
    contract = SqliteTemplateRepository.current_shadow_eligibility_contract(
        runtime
    )
    publications = (
        repository.list_current_shadow_publication_authorities()
    )
    source_authority = build_formal_development_authority(
        exclusion_snapshot=SqliteLockedSetRepository(
            runtime=runtime
        ).build_exclusion_snapshot(),
        eligibility_contract=contract,
        shadow_publications=publications,
    )
    persist_formal_development_authority(
        data_root,
        source_authority,
    )
    families: list[dict[str, object]] = []
    for publication in publications:
        family_id = publication.version.definition.family_id
        current = repository.get_family_current(family_id)
        if (
            current.summary.shadow_version_id
            != publication.version.version_id
        ):
            raise ShadowAuthorityRolloverToolError(
                "source shadow pointer changed before rollover"
            )
        if current.version.version_id != publication.version.version_id and (
            current.version.lifecycle is not TemplateLifecycle.DRAFT
            or current.version.parent_version_id
            != publication.version.version_id
            or current.version.content_sha256
            != publication.version.content_sha256
        ):
            raise ShadowAuthorityRolloverToolError(
                "a family has an incompatible unsealed later version"
            )
        families.append(
            {
                "family_id": family_id,
                "source_content_sha256": (
                    publication.version.content_sha256
                ),
                "source_record_version": (
                    publication.version.record_version
                ),
                "source_version_id": publication.version.version_id,
                "source_version_number": (
                    publication.version.version_number
                ),
                **_reference_payload(current, prefix="source"),
            }
        )
    return _write_state(
        path,
        {
            "build_fingerprint": build_fingerprint,
            "families": sorted(
                families,
                key=lambda value: str(value["family_id"]),
            ),
            "kind": "loop7_shadow_rollover_source_state",
            "schema_version": 1,
            "source_authority_sha256": (
                source_authority.authority_sha256
            ),
        },
    )


def _draft_state_path(
    data_root: Path,
    *,
    build_fingerprint: str,
) -> Path:
    return (
        data_root
        / "development"
        / "authority-rollovers"
        / build_fingerprint
        / "draft-state.json"
    )


def _load_or_write_draft_state(
    *,
    data_root: Path,
    build_fingerprint: str,
    repository: SqliteTemplateRepository,
    source_state: Mapping[str, object],
) -> tuple[TemplateVersion, ...]:
    path = _draft_state_path(
        data_root,
        build_fingerprint=build_fingerprint,
    )
    if path.exists():
        draft_state = _load_state(
            path,
            expected_kind="loop7_shadow_rollover_draft_state",
        )
        raw_candidates = draft_state.get("candidate_versions")
        if (
            draft_state.get("source_state_sha256")
            != source_state.get("state_sha256")
            or not isinstance(raw_candidates, list)
            or len(raw_candidates) != 4
        ):
            raise ShadowAuthorityRolloverToolError(
                "rollover draft state does not match its source state"
            )
        versions = tuple(
            repository.get_version(str(item["version_id"]))
            for item in raw_candidates
            if isinstance(item, Mapping)
        )
        if len(versions) != 4:
            raise ShadowAuthorityRolloverToolError(
                "rollover draft state is incomplete"
            )
        source_families = source_state.get("families")
        if not isinstance(source_families, list):
            raise ShadowAuthorityRolloverToolError(
                "rollover source family state is incomplete"
            )
        source_by_family = {
            str(item["family_id"]): item
            for item in source_families
            if isinstance(item, Mapping)
        }
        candidate_by_family = {
            str(item["family_id"]): item
            for item in raw_candidates
            if isinstance(item, Mapping)
        }
        for version in versions:
            family_id = version.definition.family_id
            source = source_by_family.get(family_id)
            candidate = candidate_by_family.get(family_id)
            if (
                source is None
                or candidate is None
                or version.parent_version_id
                is None
                or version.content_sha256
                != source.get("source_content_sha256")
                or version.version_number
                <= int(source.get("source_version_number", 0))
                or version.version_id != candidate.get("version_id")
                or version.version_number
                != candidate.get("version_number")
                or version.content_sha256
                != candidate.get("content_sha256")
            ):
                raise ShadowAuthorityRolloverToolError(
                    "rollover draft state changed"
                )
        return tuple(
            sorted(
                versions,
                key=lambda value: value.definition.family_id,
            )
        )
    drafts = _clone_drafts(
        repository=repository,
        state=source_state,
        build_fingerprint=build_fingerprint,
    )
    _write_state(
        path,
        {
            "build_fingerprint": build_fingerprint,
            "candidate_versions": [
                {
                    "content_sha256": version.content_sha256,
                    "family_id": version.definition.family_id,
                    "parent_version_id": version.parent_version_id,
                    "version_id": version.version_id,
                    "version_number": version.version_number,
                }
                for version in drafts
            ],
            "kind": "loop7_shadow_rollover_draft_state",
            "schema_version": 1,
            "source_state_sha256": source_state["state_sha256"],
        },
    )
    return drafts


def _load_completed_result(
    path: Path,
    *,
    build_fingerprint: str,
) -> dict[str, object]:
    try:
        content = path.read_bytes()
        payload = json.loads(content.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ShadowAuthorityRolloverToolError(
            "existing rollover result is unreadable"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("kind")
        != "loop7_shadow_authority_rollover_result"
        or payload.get("schema_version") != 1
        or payload.get("build_fingerprint") != build_fingerprint
    ):
        raise ShadowAuthorityRolloverToolError(
            "existing rollover result is invalid"
        )
    declared = payload.get("result_sha256")
    without_hash = dict(payload)
    without_hash.pop("result_sha256", None)
    if (
        not isinstance(declared, str)
        or _canonical_sha256(without_hash) != declared
        or content != (_canonical_json(payload) + "\n").encode("utf-8")
    ):
        raise ShadowAuthorityRolloverToolError(
            "existing rollover result hash does not match"
        )
    return payload


def _clone_drafts(
    *,
    repository: SqliteTemplateRepository,
    state: Mapping[str, object],
    build_fingerprint: str,
) -> tuple[TemplateVersion, ...]:
    raw_families = state.get("families")
    if not isinstance(raw_families, list) or len(raw_families) != 4:
        raise ShadowAuthorityRolloverToolError(
            "rollover requires exactly four source shadow families"
        )
    drafts: list[TemplateVersion] = []
    for raw in raw_families:
        if not isinstance(raw, Mapping):
            raise ShadowAuthorityRolloverToolError(
                "rollover family state is invalid"
            )
        family_id = str(raw["family_id"])
        current = repository.get_family_current(family_id)
        shadow_version_id = current.summary.shadow_version_id
        if shadow_version_id is None:
            raise ShadowAuthorityRolloverToolError(
                "source shadow pointer is unavailable before rollover"
            )
        shadow_version = repository.get_version(shadow_version_id)
        if shadow_version.content_sha256 != str(
            raw["source_content_sha256"]
        ):
            raise ShadowAuthorityRolloverToolError(
                "source shadow lineage changed before rollover"
            )
        if current.version.version_id == shadow_version_id:
            draft, _created = repository.revise_draft(
                source_version_id=shadow_version_id,
                definition=current.version.definition,
                reference_image_sha256=current.reference_image_sha256,
                reference_mask_sha256=current.reference_mask_sha256,
                alignment_fingerprint=current.alignment_fingerprint,
                expected_record_version=current.version.record_version,
                actor_id=ACTOR_ID,
                idempotency_key=(
                    f"loop7-rollover-draft:{build_fingerprint}:"
                    f"{family_id}"
                ),
            )
        else:
            draft = current.version
        if (
            draft.parent_version_id is None
            or draft.lifecycle
            not in {
                TemplateLifecycle.DRAFT,
                TemplateLifecycle.DEVELOPMENT_TESTED,
                TemplateLifecycle.SHADOW,
            }
            or draft.content_sha256
            != str(raw["source_content_sha256"])
            or current.reference_image_sha256
            != str(raw["source_reference_image_sha256"])
            or current.reference_mask_sha256
            != str(raw["source_reference_mask_sha256"])
            or current.alignment_fingerprint
            != str(raw["source_alignment_fingerprint"])
        ):
            raise ShadowAuthorityRolloverToolError(
                f"rollover draft for {family_id} is not identical"
            )
        drafts.append(draft)
    return tuple(sorted(drafts, key=lambda value: value.definition.family_id))


def _run_composite(
    *,
    data_root: Path,
    ocr_evidence: Path,
    candidate_versions: tuple[TemplateVersion, ...],
    output: Path,
) -> dict[str, object]:
    command = [
        sys.executable,
        os.fspath(
            ROOT / "tools" / "loop7_composite_lifecycle_evaluation.py"
        ),
        "--data-root",
        os.fspath(data_root),
        "--ocr-evidence",
        os.fspath(ocr_evidence),
    ]
    for version in candidate_versions:
        command.extend(["--candidate-version", version.version_id])
    command.extend(["--output", os.fspath(output)])
    if not output.exists():
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if completed.returncode != 0:
            raise ShadowAuthorityRolloverToolError(
                "composite lifecycle evaluation failed: "
                + completed.stderr.strip()
            )
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ShadowAuthorityRolloverToolError(
            "composite lifecycle evidence is unreadable"
        ) from exc
    composite = payload.get("composite") if isinstance(payload, dict) else None
    persisted = payload.get("persisted") if isinstance(payload, dict) else None
    gate = composite.get("gate") if isinstance(composite, Mapping) else None
    if (
        not isinstance(composite, Mapping)
        or not isinstance(persisted, Mapping)
        or not isinstance(gate, Mapping)
        or gate.get("passed") is not True
        or not isinstance(persisted.get("evaluation_id"), str)
    ):
        raise ShadowAuthorityRolloverToolError(
            "composite lifecycle evidence did not pass"
        )
    expected_ids = {
        version.version_id for version in candidate_versions
    }
    real_component = payload.get("real_component")
    runtimes = (
        real_component.get("runtimes")
        if isinstance(real_component, Mapping)
        else None
    )
    runtime_candidate_sets: list[set[object]] = []
    if isinstance(runtimes, Mapping):
        for runtime_kind in _RUNTIME_KINDS:
            runtime = runtimes.get(runtime_kind)
            support = (
                runtime.get("candidate_support")
                if isinstance(runtime, Mapping)
                else None
            )
            results = (
                support.get("results")
                if isinstance(support, Mapping)
                else None
            )
            if isinstance(results, list):
                runtime_candidate_sets.append(
                    {
                        item.get("candidate_version_id")
                        for item in results
                        if isinstance(item, Mapping)
                    }
                )
    observed_ids = (
        runtime_candidate_sets[0]
        if len(runtime_candidate_sets) == len(_RUNTIME_KINDS)
        and all(
            candidate_set == runtime_candidate_sets[0]
            for candidate_set in runtime_candidate_sets
        )
        else set()
    )
    if observed_ids != expected_ids:
        raise ShadowAuthorityRolloverToolError(
            "composite lifecycle evidence candidate set changed"
        )
    return cast(dict[str, object], payload)


def _publish(
    *,
    repository: SqliteTemplateRepository,
    candidate_versions: tuple[TemplateVersion, ...],
    evaluation_id: str,
    build_fingerprint: str,
) -> tuple[TemplateVersion, ...]:
    published: list[TemplateVersion] = []
    authorization = f"loop7-rollover-{build_fingerprint[:20]}"
    for candidate in candidate_versions:
        current = repository.get_version(candidate.version_id)
        if current.lifecycle is TemplateLifecycle.DRAFT:
            current, _ = repository.mark_development_tested(
                version_id=current.version_id,
                expected_record_version=current.record_version,
                evaluation_id=evaluation_id,
                developer_authorization_id=authorization,
                actor_id=ACTOR_ID,
                idempotency_key=(
                    f"loop7-rollover-tested:{build_fingerprint}:"
                    f"{current.definition.family_id}"
                ),
            )
        if current.lifecycle is TemplateLifecycle.DEVELOPMENT_TESTED:
            current, _ = repository.publish_shadow(
                version_id=current.version_id,
                expected_record_version=current.record_version,
                evaluation_id=evaluation_id,
                developer_authorization_id=authorization,
                actor_id=ACTOR_ID,
                idempotency_key=(
                    f"loop7-rollover-shadow:{build_fingerprint}:"
                    f"{current.definition.family_id}"
                ),
            )
        if current.lifecycle is not TemplateLifecycle.SHADOW:
            raise ShadowAuthorityRolloverToolError(
                "rollover template did not reach shadow"
            )
        published.append(current)
    return tuple(
        sorted(published, key=lambda value: value.definition.family_id)
    )


def _version_lineage(
    *,
    repository: SqliteTemplateRepository,
    source_version_id: str,
    execution_version: TemplateVersion,
) -> tuple[Mapping[str, object], ...]:
    reverse: list[TemplateVersion] = []
    current = execution_version
    while True:
        reverse.append(current)
        if current.version_id == source_version_id:
            break
        if current.parent_version_id is None:
            raise ShadowAuthorityRolloverToolError(
                "template lineage does not reach the frozen source"
            )
        current = repository.get_version(current.parent_version_id)
    lineage = tuple(reversed(reverse))
    if any(
        current.content_sha256 != lineage[0].content_sha256
        or current.version_number
        != previous.version_number + 1
        or current.parent_version_id != previous.version_id
        for previous, current in pairwise(lineage)
    ):
        raise ShadowAuthorityRolloverToolError(
            "template lineage is not consecutive and identical"
        )
    return tuple(
        {
            "content_sha256": version.content_sha256,
            "parent_version_id": version.parent_version_id,
            "version_id": version.version_id,
            "version_number": version.version_number,
        }
        for version in lineage
    )


def _run(args: argparse.Namespace) -> int:
    data_root = args.data_root
    if (
        not data_root.is_dir()
        or data_root.resolve(strict=True) != data_root
    ):
        raise ShadowAuthorityRolloverToolError(
            "data root must be an existing resolved directory"
        )
    ocr_evidence = args.ocr_evidence.resolve(strict=True)
    output = _validate_output(args.output, data_root=data_root)
    build_fingerprint = current_template_pipeline_build_fingerprint(
        application_version=__version__,
    )
    if output.exists():
        completed = _load_completed_result(
            output,
            build_fingerprint=build_fingerprint,
        )
        completed_rollover = completed.get("rollover")
        if not isinstance(completed_rollover, Mapping):
            raise ShadowAuthorityRolloverToolError(
                "completed rollover result is invalid"
            )
        print(
            json.dumps(
                {
                    "execution_authority_sha256": completed[
                        "execution_authority_sha256"
                    ],
                    "output": os.fspath(output),
                    "rollover_sha256": completed_rollover[
                        "rollover_sha256"
                    ],
                    "source_authority_sha256": completed[
                        "source_authority_sha256"
                    ],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    config = AppConfig(
        runtime_profile=RuntimeProfile.DEVELOPMENT,
        data_root=data_root,
    )
    prepared_root = prepare_startup_environment(config, ROOT)
    if prepared_root != data_root:
        raise ShadowAuthorityRolloverToolError(
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
        backend = build_ocr_execution_backend(
            config=config,
            repository_root=ROOT,
        )
        try:
            runtime_fingerprint = _qualified_runtime_fingerprint(backend)
            state_path = _source_state_path(
                data_root,
                build_fingerprint=build_fingerprint,
            )
            if state_path.exists():
                state = _load_state(state_path)
                source_authority = (
                    load_persisted_formal_development_authority(
                        data_root,
                        authority_sha256=str(
                            state["source_authority_sha256"]
                        ),
                    )
                )
                old_contract = source_authority.eligibility_contract
            else:
                old_contract = (
                    SqliteTemplateRepository.current_shadow_eligibility_contract(
                        runtime
                    )
                )
            old_repository = SqliteTemplateRepository(
                runtime=runtime,
                accepted_build_fingerprint=old_contract.build_fingerprint,
                accepted_runtime_fingerprint=(
                    old_contract.runtime_fingerprint
                ),
                accepted_development_manifest_sha256=(
                    old_contract.dataset_manifest_sha256
                ),
                accepted_matcher_fingerprint=(
                    old_contract.matcher_fingerprint
                ),
                accepted_policy_fingerprint=(
                    old_contract.policy_fingerprint
                ),
            )
            if not state_path.exists():
                state = _source_state(
                    data_root=data_root,
                    build_fingerprint=build_fingerprint,
                    repository=old_repository,
                    runtime=runtime,
                )
            drafts = _load_or_write_draft_state(
                data_root=data_root,
                build_fingerprint=build_fingerprint,
                repository=old_repository,
                source_state=state,
            )
        finally:
            backend.close()
            runtime.close()

    composite_output = output.with_name(
        f".{output.stem}.{build_fingerprint[:16]}.composite.json"
    )
    composite_payload = _run_composite(
        data_root=data_root,
        ocr_evidence=ocr_evidence,
        candidate_versions=drafts,
        output=composite_output,
    )
    composite = composite_payload["composite"]
    persisted = composite_payload["persisted"]
    if not isinstance(composite, Mapping) or not isinstance(
        persisted,
        Mapping,
    ):
        raise ShadowAuthorityRolloverToolError(
            "composite lifecycle evidence is invalid"
        )
    composite_manifest_sha256 = str(
        composite["dataset_manifest_sha256"]
    )
    evaluation_id = str(persisted["evaluation_id"])

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
            repository = SqliteTemplateRepository(
                runtime=runtime,
                accepted_build_fingerprint=build_fingerprint,
                accepted_runtime_fingerprint=runtime_fingerprint,
                accepted_development_manifest_sha256=(
                    composite_manifest_sha256
                ),
                accepted_matcher_fingerprint=(
                    development_matcher_fingerprint()
                ),
                accepted_policy_fingerprint=(
                    development_policy_fingerprint()
                ),
            )
            published = _publish(
                repository=repository,
                candidate_versions=drafts,
                evaluation_id=evaluation_id,
                build_fingerprint=build_fingerprint,
            )
            source_authority = (
                load_persisted_formal_development_authority(
                    data_root,
                    authority_sha256=str(
                        state["source_authority_sha256"]
                    ),
                )
            )
            execution_authority = (
                build_current_formal_development_authority(
                    runtime,
                    frozen_exclusion_snapshot_sha256=(
                        source_authority.exclusion_snapshot.canonical_sha256
                    ),
                )
            )
            raw_families = state["families"]
            if not isinstance(raw_families, list):
                raise ShadowAuthorityRolloverToolError(
                    "source state families are invalid"
                )
            state_by_family = {
                str(item["family_id"]): item
                for item in raw_families
                if isinstance(item, Mapping)
            }
            if len(state_by_family) != len(raw_families):
                raise ShadowAuthorityRolloverToolError(
                    "source state family entry is invalid"
                )
            references: dict[str, dict[str, str]] = {}
            version_lineages: dict[
                str,
                tuple[Mapping[str, object], ...],
            ] = {}
            for version in published:
                family_id = version.definition.family_id
                current = repository.get_family_current(family_id)
                references[family_id] = {
                    **_reference_payload(
                        current,
                        prefix="execution",
                    ),
                    "source_alignment_fingerprint": str(
                        state_by_family[family_id][
                            "source_alignment_fingerprint"
                        ]
                    ),
                    "source_reference_image_sha256": str(
                        state_by_family[family_id][
                            "source_reference_image_sha256"
                        ]
                    ),
                    "source_reference_mask_sha256": str(
                        state_by_family[family_id][
                            "source_reference_mask_sha256"
                        ]
                    ),
                }
                version_lineages[family_id] = _version_lineage(
                    repository=repository,
                    source_version_id=str(
                        state_by_family[family_id][
                            "source_version_id"
                        ]
                    ),
                    execution_version=version,
                )
            rollover = build_development_authority_rollover(
                source_authority=source_authority,
                execution_authority=execution_authority,
                reference_evidence_by_family=references,
                version_lineage_by_family=version_lineages,
            )
            persist_formal_development_authority(
                data_root,
                execution_authority,
            )
            persist_development_authority_rollover(
                data_root,
                rollover,
            )
        finally:
            runtime.close()

    result_without_hash: dict[str, object] = {
        "build_fingerprint": build_fingerprint,
        "composite_evaluation_id": evaluation_id,
        "composite_evaluation_sha256": str(
            composite["evaluation_sha256"]
        ),
        "execution_authority_sha256": (
            execution_authority.authority_sha256
        ),
        "kind": "loop7_shadow_authority_rollover_result",
        "rollover": rollover.payload,
        "schema_version": 1,
        "source_authority_sha256": (
            source_authority.authority_sha256
        ),
        "template_version_mappings": [
            {
                "execution_version_id": version.version_id,
                "family_id": version.definition.family_id,
                "source_version_id": str(
                    state_by_family[version.definition.family_id][
                        "source_version_id"
                    ]
                ),
            }
            for version in published
        ],
    }
    result = {
        **result_without_hash,
        "result_sha256": _canonical_sha256(result_without_hash),
    }
    _write_idempotent_json(
        output,
        result,
        data_root=data_root,
    )
    print(
        json.dumps(
            {
                "execution_authority_sha256": (
                    execution_authority.authority_sha256
                ),
                "output": os.fspath(output),
                "rollover_sha256": rollover.rollover_sha256,
                "source_authority_sha256": (
                    source_authority.authority_sha256
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except (
        DevelopmentAuthorityRolloverError,
        FormalDevelopmentAuthorityError,
        OSError,
        ShadowAuthorityRolloverToolError,
        TemplatePersistenceError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
