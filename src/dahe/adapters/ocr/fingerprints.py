from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from dahe.adapters.ocr.profiles import RuntimeKind


@dataclass(frozen=True, slots=True)
class RuntimeFingerprintInput:
    runtime_kind: RuntimeKind
    python_version: str
    paddle_version: str
    paddleocr_version: str
    paddlex_version: str
    dependency_lock_sha256: str
    model_manifest_sha256: str
    worker_build_sha256: str
    profile_id: str
    profile_payload: dict[str, object]
    stable_device_id: str | None
    driver_version: str | None


def _fingerprint(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_runtime_fingerprint(value: RuntimeFingerprintInput) -> str:
    payload = asdict(value)
    payload["runtime_kind"] = value.runtime_kind.value
    return _fingerprint(payload)


def build_runtime_profile_id(
    *,
    runtime_kind: RuntimeKind,
    stable_device_id: str | None,
    precision: str,
    batch_size: int,
    worker_count: int,
) -> str:
    """Build the canonical readable identity that is also fingerprint-bound."""

    stable_fragment = (
        hashlib.sha256(stable_device_id.encode("utf-8")).hexdigest()[:12]
        if stable_device_id is not None
        else "portable"
    )
    return (
        f"{runtime_kind.value}-{stable_fragment}-{precision}"
        f"-b{batch_size}-w{worker_count}"
    )


def build_ocr_output_fingerprint(
    *,
    image_sha256: str,
    fields: object,
    role_observation: object,
    text_lines: object,
    verified_image_sha256: str,
    pipeline_fingerprint: str,
    profile_id: str,
    runtime_fingerprint: str,
    runtime_kind: str,
) -> str:
    """Bind stable OCR business output to its runtime and pipeline authority."""

    return _fingerprint(
        {
            "image_sha256": image_sha256,
            "output": {
                "fields": fields,
                "role_observation": role_observation,
                "text_lines": text_lines,
                "verified_image_sha256": verified_image_sha256,
            },
            "pipeline_fingerprint": pipeline_fingerprint,
            "profile_id": profile_id,
            "runtime_fingerprint": runtime_fingerprint,
            "runtime_kind": runtime_kind,
        }
    )


def build_pipeline_fingerprint(
    *,
    code_build: str,
    runtime_fingerprint: str,
    model_manifest_sha256: str,
    template_set_fingerprint: str,
    extraction_rule_version: str,
) -> str:
    return _fingerprint(
        {
            "code_build": code_build,
            "runtime_fingerprint": runtime_fingerprint,
            "model_manifest_sha256": model_manifest_sha256,
            "template_set_fingerprint": template_set_fingerprint,
            "extraction_rule_version": extraction_rule_version,
        }
    )
