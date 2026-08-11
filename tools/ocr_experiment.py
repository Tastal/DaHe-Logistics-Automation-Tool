from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "dev-tools" / "ocr-experiment-tools.json"
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXPECTED_TOOLS = {
    "cleanvision": (
        "0.3.7",
        "46ad8296a7750c354cef5ac39136f0d0e2c9bbdb88eda68c037877ed2702d74f",
    ),
    "rapidocr": (
        "3.9.2",
        "04d6b8d151f823d930bd91910555f57bea897c0c44fa6794267b94cf9c1ef9a0",
    ),
}
_PROTECTED_PREFIX = (
    "development",
    "protected-candidate-review-ocr",
)


@dataclass(frozen=True)
class ToolPin:
    name: str
    package: str
    version: str
    license: str
    source: str
    wheel_sha256: str
    runtime_backend: RuntimeBackendPin | None = None


@dataclass(frozen=True)
class RuntimeBackendPin:
    package: str
    version: str
    license: str
    source: str
    platform: str
    wheel_sha256: str


@dataclass(frozen=True)
class ExperimentManifest:
    cleanvision: ToolPin
    rapidocr: ToolPin

    def get(self, name: str) -> ToolPin:
        if name == "cleanvision":
            return self.cleanvision
        if name == "rapidocr":
            return self.rapidocr
        raise KeyError(name)


@dataclass(frozen=True)
class ReviewImage:
    image_sha256: str
    path: Path
    media_type: str
    byte_size: int
    truth_ordinary_net: str | None
    truth_role: str
    human_confirmed: bool
    quality_conditions: tuple[str, ...]


@dataclass(frozen=True)
class CpuBaseline:
    image_sha256: str
    ordinary_net: str | None
    elapsed_ms: float


@dataclass(frozen=True)
class ProtectedReviewRecord:
    evidence_sha256: str
    image_set_sha256: str
    images: tuple[ReviewImage, ...]
    cpu_baselines: tuple[CpuBaseline, ...]


def require_project_venv() -> None:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise RuntimeError("OCR experiments must run from the project .venv")


def _exact_dict(value: object, fields: set[str], *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields are invalid")
    return value


def load_experiment_manifest(path: Path = MANIFEST_PATH) -> ExperimentManifest:
    payload = json.loads(path.read_text(encoding="utf-8"))
    root = _exact_dict(payload, {"schema_version", "tools"}, label="experiment manifest")
    if root["schema_version"] != 1:
        raise ValueError("experiment manifest schema is unsupported")
    tools = root["tools"]
    if not isinstance(tools, dict) or set(tools) != set(_EXPECTED_TOOLS):
        raise ValueError("experiment tool set is invalid")
    pins: dict[str, ToolPin] = {}
    for name, (expected_version, expected_hash) in _EXPECTED_TOOLS.items():
        expected_fields = {"license", "package", "source", "version", "wheel_sha256"}
        if name == "rapidocr":
            expected_fields.add("runtime_backend")
        raw = _exact_dict(
            tools[name],
            expected_fields,
            label=f"experiment tool {name}",
        )
        source = raw["source"]
        if (
            raw["package"] != name
            or raw["version"] != expected_version
            or raw["wheel_sha256"] != expected_hash
            or raw["license"] != "Apache-2.0"
            or not isinstance(source, str)
            or urlsplit(source).scheme != "https"
            or urlsplit(source).hostname not in {"pypi.org", "www.pypi.org"}
        ):
            raise ValueError(f"experiment tool {name} pin is invalid")
        backend: RuntimeBackendPin | None = None
        if name == "rapidocr":
            backend_raw = _exact_dict(
                raw["runtime_backend"],
                {"license", "package", "platform", "source", "version", "wheel_sha256"},
                label="rapidocr runtime backend",
            )
            backend_source = backend_raw["source"]
            if (
                backend_raw["package"] != "onnxruntime"
                or backend_raw["version"] != "1.28.0"
                or backend_raw["license"] != "MIT"
                or backend_raw["platform"] != "win_amd64_cp312"
                or backend_raw["wheel_sha256"]
                != "c35064f9b3c43c81c5d5d282091401d0f1ff22796d93ccade4ea2ece5e137ab8"
                or not isinstance(backend_source, str)
                or urlsplit(backend_source).scheme != "https"
                or urlsplit(backend_source).hostname not in {"pypi.org", "www.pypi.org"}
            ):
                raise ValueError("rapidocr runtime backend pin is invalid")
            backend = RuntimeBackendPin(
                package="onnxruntime",
                version="1.28.0",
                license="MIT",
                source=backend_source,
                platform="win_amd64_cp312",
                wheel_sha256=str(backend_raw["wheel_sha256"]),
            )
        pins[name] = ToolPin(
            name=name,
            package=name,
            version=expected_version,
            license="Apache-2.0",
            source=source,
            wheel_sha256=expected_hash,
            runtime_backend=backend,
        )
    return ExperimentManifest(
        cleanvision=pins["cleanvision"],
        rapidocr=pins["rapidocr"],
    )


def experiment_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA is unavailable")
    return (
        Path(local_app_data)
        / "DaHeLogistics"
        / "development-tools"
        / "ocr-experiment"
    )


def tool_python(pin: ToolPin) -> Path:
    return (
        experiment_root()
        / pin.name
        / pin.version
        / "python"
        / "Scripts"
        / "python.exe"
    )


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_absolute(path: Path, *, label: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    return path.resolve(strict=True)


def _reject_symlinks(root: Path, target: Path) -> None:
    relative = target.relative_to(root)
    current = root
    if root.is_symlink():
        raise ValueError("protected development path must not use symbolic links")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("protected development path must not use symbolic links")


def _truth_by_image(
    payload: dict[str, object],
) -> dict[str, tuple[str | None, str, bool]]:
    source = payload.get("source")
    if not isinstance(source, dict):
        raise ValueError("protected review source is invalid")
    manifest = source.get("manifest_payload")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("waybills"), list):
        raise ValueError("protected review manifest is invalid")
    truth: dict[str, tuple[str | None, str, bool]] = {}
    for waybill in manifest["waybills"]:
        if not isinstance(waybill, dict) or not isinstance(waybill.get("images"), list):
            raise ValueError("protected review waybill is invalid")
        human_confirmed = waybill.get("human_confirmed") is True
        if not human_confirmed:
            raise ValueError("protected review image is not human confirmed")
        for image in waybill["images"]:
            if not isinstance(image, dict):
                raise ValueError("protected review truth image is invalid")
            image_sha256 = image.get("image_sha256")
            ordinary_net = image.get("ordinary_net")
            role = image.get("role")
            if (
                not isinstance(image_sha256, str)
                or not _SHA256.fullmatch(image_sha256)
                or not isinstance(role, str)
                or (
                    ordinary_net is not None
                    and not isinstance(ordinary_net, str)
                )
                or (ordinary_net is None and role != "unknown")
                or image_sha256 in truth
            ):
                raise ValueError("protected review truth image is invalid")
            truth[image_sha256] = (ordinary_net, role, human_confirmed)
    return truth


def _quality_conditions_by_image(payload: dict[str, object]) -> dict[str, set[str]]:
    source = payload.get("source")
    if not isinstance(source, dict):
        return {}
    quality = source.get("quality_coverage_payload")
    if quality is None:
        return {}
    if not isinstance(quality, dict) or not isinstance(quality.get("entries"), list):
        raise ValueError("protected review quality coverage is invalid")
    result: dict[str, set[str]] = {}
    for entry in quality["entries"]:
        if not isinstance(entry, dict):
            raise ValueError("protected review quality coverage entry is invalid")
        image_sha256 = entry.get("image_sha256")
        condition = entry.get("condition")
        if (
            not isinstance(image_sha256, str)
            or not _SHA256.fullmatch(image_sha256)
            or not isinstance(condition, str)
            or not condition
        ):
            raise ValueError("protected review quality coverage entry is invalid")
        result.setdefault(image_sha256, set()).add(condition)
    return result


def load_protected_review_record(
    development_root: Path,
    review_record: Path,
) -> ProtectedReviewRecord:
    root = _require_absolute(development_root, label="development root")
    record = _require_absolute(review_record, label="review record")
    try:
        relative_record = record.relative_to(root)
    except ValueError as error:
        raise ValueError("review record is outside protected development data") from error
    expected_parts = (*_PROTECTED_PREFIX, "records", "sha256")
    if (
        relative_record.parts[: len(expected_parts)] != expected_parts
        or len(relative_record.parts) != len(expected_parts) + 3
    ):
        raise ValueError("review record is outside protected development data")
    _reject_symlinks(root, record)
    payload = json.loads(record.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("protected review record is invalid")
    evidence_sha256 = payload.get("evidence_sha256")
    if (
        not isinstance(evidence_sha256, str)
        or not _SHA256.fullmatch(evidence_sha256)
        or record.stem != evidence_sha256
        or relative_record.parts[-3:-1]
        != (evidence_sha256[:2], evidence_sha256[2:4])
        or payload.get("development_only") is not True
        or payload.get("formal_accuracy_claim") is not False
        or payload.get("formal_release_eligible") is not False
    ):
        raise ValueError("protected review authority is invalid")
    copied_images = payload.get("copied_images")
    if not isinstance(copied_images, list) or not copied_images:
        raise ValueError("protected review image list is invalid")
    truth = _truth_by_image(payload)
    quality_conditions = _quality_conditions_by_image(payload)
    if not set(quality_conditions).issubset(truth):
        raise ValueError("protected review quality coverage is outside the image set")
    images: list[ReviewImage] = []
    seen: set[str] = set()
    for raw in copied_images:
        if not isinstance(raw, dict):
            raise ValueError("protected review image entry is invalid")
        image_sha256 = raw.get("image_sha256")
        relative_path = raw.get("relative_path")
        media_type = raw.get("media_type")
        byte_size = raw.get("byte_size")
        if (
            not isinstance(image_sha256, str)
            or not _SHA256.fullmatch(image_sha256)
            or image_sha256 in seen
            or not isinstance(relative_path, str)
            or not isinstance(media_type, str)
            or media_type not in {"image/jpeg", "image/png"}
            or not isinstance(byte_size, int)
            or byte_size < 1
            or image_sha256 not in truth
        ):
            raise ValueError("protected review image entry is invalid")
        expected_relative = Path(
            *_PROTECTED_PREFIX,
            "evidence",
            "sha256",
            image_sha256[:2],
            image_sha256[2:4],
            f"{image_sha256}.blob",
        )
        if Path(relative_path) != expected_relative:
            raise ValueError("protected review image path is not content-addressed")
        image_path = (root / expected_relative).resolve(strict=True)
        _reject_symlinks(root, image_path)
        if image_path.stat().st_size != byte_size or _sha256_path(image_path) != image_sha256:
            raise ValueError("protected review image SHA-256 does not match")
        ordinary_net, role, human_confirmed = truth[image_sha256]
        images.append(
            ReviewImage(
                image_sha256=image_sha256,
                path=image_path,
                media_type=media_type,
                byte_size=byte_size,
                truth_ordinary_net=ordinary_net,
                truth_role=role,
                human_confirmed=human_confirmed,
                quality_conditions=tuple(sorted(quality_conditions.get(image_sha256, set()))),
            )
        )
        seen.add(image_sha256)
    if seen != set(truth):
        raise ValueError("protected review image and truth sets differ")
    baselines: list[CpuBaseline] = []
    runtime_attempts = payload.get("runtime_attempts", [])
    if not isinstance(runtime_attempts, list):
        raise ValueError("protected review runtime attempts are invalid")
    for attempt in runtime_attempts:
        if not isinstance(attempt, dict) or attempt.get("runtime_kind") != "cpu":
            continue
        image_sha256 = attempt.get("image_sha256")
        elapsed_ms = attempt.get("wall_elapsed_ms")
        fields = attempt.get("fields")
        ordinary_net = fields.get("ordinary_net") if isinstance(fields, dict) else None
        amount = ordinary_net.get("amount") if isinstance(ordinary_net, dict) else None
        if (
            not isinstance(image_sha256, str)
            or image_sha256 not in seen
            or not isinstance(elapsed_ms, int | float)
            or elapsed_ms < 0
            or (amount is not None and not isinstance(amount, str))
            or any(item.image_sha256 == image_sha256 for item in baselines)
        ):
            raise ValueError("protected review CPU baseline is invalid")
        baselines.append(
            CpuBaseline(
                image_sha256=image_sha256,
                ordinary_net=amount,
                elapsed_ms=float(elapsed_ms),
            )
        )
    ordered_hashes = sorted(seen)
    return ProtectedReviewRecord(
        evidence_sha256=evidence_sha256,
        image_set_sha256=_canonical_sha256(ordered_hashes),
        images=tuple(sorted(images, key=lambda item: item.image_sha256)),
        cpu_baselines=tuple(sorted(baselines, key=lambda item: item.image_sha256)),
    )


def deterministic_sample(
    images: tuple[ReviewImage, ...],
    sample_size: int,
) -> tuple[ReviewImage, ...]:
    if not 1 <= sample_size <= 30:
        raise ValueError("sample size must be between 1 and 30")
    if sample_size > len(images):
        raise ValueError("sample size exceeds protected development images")
    unique = {image.image_sha256: image for image in images}
    if len(unique) != len(images):
        raise ValueError("protected development sample contains duplicate identities")
    coverage_order = [
        image.image_sha256
        for image in sorted(
            images,
            key=lambda item: (
                item.quality_conditions[0] if item.quality_conditions else "~",
                item.image_sha256,
            ),
        )
        if image.quality_conditions
    ]
    selected: list[str] = []
    for image_sha256 in (*coverage_order, *sorted(unique)):
        if image_sha256 not in selected:
            selected.append(image_sha256)
        if len(selected) == sample_size:
            break
    return tuple(unique[image_sha256] for image_sha256 in sorted(selected))


def make_safe_result(
    *,
    source_record_sha256: str,
    source_image_set_sha256: str,
    sample_results: list[dict[str, object]],
    tool_runtime_sha256s: dict[str, str],
) -> dict[str, object]:
    if not _SHA256.fullmatch(source_record_sha256) or not _SHA256.fullmatch(
        source_image_set_sha256
    ):
        raise ValueError("experiment source identity is invalid")
    if set(tool_runtime_sha256s) != set(_EXPECTED_TOOLS) or any(
        not _SHA256.fullmatch(value) for value in tool_runtime_sha256s.values()
    ):
        raise ValueError("experiment runtime identities are invalid")
    safe_samples: list[dict[str, object]] = []
    match_count = 0
    truth_evaluated_count = 0
    for raw in sample_results:
        image_sha256 = raw.get("image_sha256")
        truth = raw.get("truth_ordinary_net")
        candidates = raw.get("rapidocr_ordinary_net_candidates")
        issues = raw.get("quality_issue_types")
        source_conditions = raw.get("source_quality_conditions", [])
        elapsed = raw.get("rapidocr_elapsed_ms")
        if (
            not isinstance(image_sha256, str)
            or not _SHA256.fullmatch(image_sha256)
            or (truth is not None and not isinstance(truth, str))
            or not isinstance(candidates, list)
            or not all(isinstance(value, str) for value in candidates)
            or not isinstance(issues, list)
            or not all(isinstance(value, str) for value in issues)
            or not isinstance(source_conditions, list)
            or not all(isinstance(value, str) for value in source_conditions)
            or not isinstance(elapsed, int | float)
            or elapsed < 0
        ):
            raise ValueError("experiment sample result is invalid")
        matched = truth in candidates if truth is not None else None
        if matched is not None:
            truth_evaluated_count += 1
            match_count += int(matched)
        safe_samples.append(
            {
                "image_sha256": image_sha256,
                "quality_issue_types": sorted(set(issues)),
                "source_quality_conditions": sorted(set(source_conditions)),
                "rapidocr_candidate_count": len(set(candidates)),
                "rapidocr_truth_match": matched,
                "rapidocr_elapsed_ms": round(float(elapsed), 3),
            }
        )
    sample_count = len(safe_samples)
    return {
        "schema_version": 1,
        "kind": "isolated_ocr_quality_experiment",
        "development_only": True,
        "formal_acceptance": False,
        "future_locked_set_eligible": False,
        "production_promotion_allowed": False,
        "source_record_sha256": source_record_sha256,
        "source_image_set_sha256": source_image_set_sha256,
        "tool_runtime_sha256s": dict(sorted(tool_runtime_sha256s.items())),
        "sample_count": sample_count,
        "rapidocr_truth_evaluated_count": truth_evaluated_count,
        "rapidocr_truth_match_count": match_count,
        "rapidocr_truth_match_rate": (
            match_count / truth_evaluated_count if truth_evaluated_count else None
        ),
        "samples": sorted(safe_samples, key=lambda item: str(item["image_sha256"])),
    }
