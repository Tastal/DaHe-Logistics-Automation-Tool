from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Mapping
from pathlib import Path

from dahe.adapters.sqlite.template_studio import (
    deserialize_template_definition,
)
from dahe.domain.ticket.templates import (
    TemplateLifecycle,
    TemplateVersion,
    canonical_template_hash,
)

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class OperationalTemplateBundleError(RuntimeError):
    """Raised when an operational-only template bundle is unsafe."""


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_operational_template_bundle(
    *,
    templates: list[dict[str, object]],
    evaluation: dict[str, object],
) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": 1,
        "kind": "dahe_operational_shadow_template_bundle",
        "classification": "operational_only",
        "formal_loop9_gate_eligible": False,
        "evaluation": evaluation,
        "templates": templates,
    }
    body["bundle_sha256"] = hashlib.sha256(canonical_json(body)).hexdigest()
    return body


def load_operational_template_bundle(
    path: Path,
    *,
    expected_matcher_fingerprint: str,
    expected_policy_fingerprint: str,
) -> tuple[TemplateVersion, ...]:
    if not path.is_absolute() or path.is_symlink():
        raise OperationalTemplateBundleError("operational template bundle path is unsafe")
    try:
        metadata = path.stat(follow_symlinks=False)
        raw = path.read_bytes()
    except OSError as exc:
        raise OperationalTemplateBundleError("operational template bundle is unavailable") from exc
    if getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT or not path.is_file():
        raise OperationalTemplateBundleError("operational template bundle is unsafe")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperationalTemplateBundleError("operational template bundle is invalid") from exc
    if not isinstance(payload, dict):
        raise OperationalTemplateBundleError("operational template bundle is invalid")
    supplied_sha256 = payload.pop("bundle_sha256", None)
    if (
        payload.get("schema_version") != 1
        or payload.get("kind") != "dahe_operational_shadow_template_bundle"
        or payload.get("classification") != "operational_only"
        or payload.get("formal_loop9_gate_eligible") is not False
        or not isinstance(supplied_sha256, str)
        or supplied_sha256 != hashlib.sha256(canonical_json(payload)).hexdigest()
    ):
        raise OperationalTemplateBundleError("operational template bundle identity is invalid")
    evaluation = payload.get("evaluation")
    records = payload.get("templates")
    if not isinstance(evaluation, Mapping) or not isinstance(records, list):
        raise OperationalTemplateBundleError("operational template bundle schema is invalid")
    if (
        evaluation.get("verification_source") != "frozen_runner"
        or evaluation.get("gate_passed") is not True
        or evaluation.get("matcher_fingerprint") != expected_matcher_fingerprint
        or evaluation.get("policy_fingerprint") != expected_policy_fingerprint
    ):
        raise OperationalTemplateBundleError("operational template evaluation is incompatible")
    versions: list[TemplateVersion] = []
    seen_families: set[str] = set()
    seen_versions: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise OperationalTemplateBundleError("operational template record is invalid")
        definition_raw = record.get("definition")
        if not isinstance(definition_raw, Mapping):
            raise OperationalTemplateBundleError("operational template definition is invalid")
        try:
            definition = deserialize_template_definition(definition_raw)
            version = TemplateVersion(
                version_id=str(record["version_id"]),
                definition=definition,
                lifecycle=TemplateLifecycle(str(record["lifecycle"])),
                parent_version_id=(
                    None
                    if record.get("parent_version_id") is None
                    else str(record["parent_version_id"])
                ),
                record_version=int(record["record_version"]),
                version_number=int(record["version_number"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OperationalTemplateBundleError("operational template record is invalid") from exc
        if (
            version.lifecycle is not TemplateLifecycle.SHADOW
            or record.get("content_sha256") != canonical_template_hash(definition)
            or definition.family_id in seen_families
            or version.version_id in seen_versions
        ):
            raise OperationalTemplateBundleError("operational template record identity is invalid")
        seen_families.add(definition.family_id)
        seen_versions.add(version.version_id)
        versions.append(version)
    if len(versions) != 4:
        raise OperationalTemplateBundleError(
            "operational template bundle must contain four shadow templates"
        )
    return tuple(sorted(versions, key=lambda item: item.definition.family_id))
