from __future__ import annotations

import json
from pathlib import Path

import pytest

from dahe.adapters.ocr.devices import NvidiaDevice
from dahe.adapters.ocr.fingerprints import (
    RuntimeFingerprintInput,
    build_runtime_fingerprint,
    build_runtime_profile_id,
)
from dahe.adapters.ocr.profile_registry import (
    QualificationRegistryError,
    load_qualified_candidates,
)
from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.adapters.ocr.runtime_inventory import inventory_sha256

PYTHON_VERSIONS = {
    RuntimeKind.CPU: "3.12.10",
    RuntimeKind.GPU: "3.12.10",
}


def _gpu() -> NvidiaDevice:
    return NvidiaDevice(
        current_index=2,
        stable_id="GPU-stable",
        name="NVIDIA RTX Example",
        memory_mib=8192,
        driver_version="610.62",
        compute_capability="8.9",
    )


def _report(kind: str) -> dict[str, object]:
    gpu = kind == "gpu"
    runtime_kind = RuntimeKind(kind)
    precision = "fp16" if gpu else "fp32"
    batch_size = 6 if gpu else 1
    stable_device_id = "GPU-stable" if gpu else None
    driver_version = "610.62" if gpu else None
    packages = {
        ("paddlepaddle-gpu" if gpu else "paddlepaddle"): "3.3.1",
        "paddleocr": "3.7.0",
        "paddlex": "3.7.2",
    }
    profile_id = build_runtime_profile_id(
        runtime_kind=runtime_kind,
        stable_device_id=stable_device_id,
        precision=precision,
        batch_size=batch_size,
        worker_count=1,
    )
    runtime_fingerprint = build_runtime_fingerprint(
        RuntimeFingerprintInput(
            runtime_kind=runtime_kind,
            python_version=PYTHON_VERSIONS[runtime_kind],
            paddle_version="3.3.1",
            paddleocr_version="3.7.0",
            paddlex_version="3.7.2",
            dependency_lock_sha256=("b" if gpu else "a") * 64,
            model_manifest_sha256="d" * 64,
            worker_build_sha256="c" * 64,
            profile_id=profile_id,
            profile_payload={
                "precision": precision,
                "batch_size": batch_size,
                "worker_count": 1,
                "memory_safety_ratio": "0.90",
                "hpi_enabled": False,
                "tensorrt_enabled": False,
            },
            stable_device_id=stable_device_id,
            driver_version=driver_version,
        )
    )
    report: dict[str, object] = {
        "runtime_kind": kind,
        "status": "qualified",
        "profile_id": profile_id,
        "runtime_fingerprint": runtime_fingerprint,
        "stable_device_id": stable_device_id,
        "driver_version": driver_version,
        "memory_mib": 8192 if gpu else None,
        "precision": precision,
        "batch_size": batch_size,
        "worker_count": 1,
        "memory_safety_ratio": "0.90",
        "peak_memory_used_mib": 5600 if gpu else None,
        "dependency_lock_sha256": ("b" if gpu else "a") * 64,
        "worker_source_sha256": "c" * 64,
        "model_manifest_sha256": "d" * 64,
        "packages": packages,
        "images": [
            {
                "image_id": "loading",
                "image_sha256": "e" * 64,
                "verified_image_sha256": "e" * 64,
                "elapsed_ms": 10,
                "role": "loading",
                "field_reliable": True,
            },
            {
                "image_id": "unloading",
                "image_sha256": "f" * 64,
                "verified_image_sha256": "f" * 64,
                "elapsed_ms": 11,
                "role": "unloading",
                "field_reliable": True,
            },
        ],
        "p50_ms": 10.5,
        "p95_ms": 11,
    }
    report["package_inventory_sha256"] = inventory_sha256(
        report["packages"]  # type: ignore[arg-type]
    )
    return report


def _write_bundle(path: Path, reports: list[dict[str, object]]) -> None:
    image_hashes = ("e" * 64, "f" * 64)
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "reports": reports,
                "difference_report": {
                    "sample_count": 2,
                    "critical_match_count": 2,
                    "all_critical_fields_match": True,
                    "items": [
                        {
                            "image_sha256": image_hash,
                            "critical_fields_match": True,
                            "differences": [],
                            "cpu_elapsed_ms": 10,
                            "gpu_elapsed_ms": 9,
                        }
                        for image_hash in image_hashes
                    ],
                },
            }
        ),
        encoding="utf-8",
    )


def test_registry_loads_only_current_fully_matching_profiles(tmp_path: Path) -> None:
    path = tmp_path / "qualification.json"
    _write_bundle(path, [_report("cpu"), _report("gpu")])

    candidates = load_qualified_candidates(
        path,
        expected_python_version=PYTHON_VERSIONS,
        expected_lock_sha256={
            RuntimeKind.CPU: "a" * 64,
            RuntimeKind.GPU: "b" * 64,
        },
        expected_worker_source_sha256="c" * 64,
        expected_model_manifest_sha256="d" * 64,
        expected_package_inventory_sha256={
            RuntimeKind.CPU: str(_report("cpu")["package_inventory_sha256"]),
            RuntimeKind.GPU: str(_report("gpu")["package_inventory_sha256"]),
        },
        devices=(_gpu(),),
    )

    assert candidates[RuntimeKind.CPU].device is None
    assert candidates[RuntimeKind.GPU].device == _gpu()
    selected_gpu = candidates[RuntimeKind.GPU].device
    assert selected_gpu is not None
    assert selected_gpu.current_index == 2


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (("driver_version", "999.0"), "driver"),
        (("worker_source_sha256", "9" * 64), "worker"),
        (("model_manifest_sha256", "8" * 64), "model"),
        (("peak_memory_used_mib", 8000), "memory"),
    ],
)
def test_registry_rejects_stale_or_unsafe_gpu_qualification(
    tmp_path: Path,
    mutation: tuple[str, object],
    message: str,
) -> None:
    gpu_report = _report("gpu")
    gpu_report[mutation[0]] = mutation[1]
    path = tmp_path / "qualification.json"
    _write_bundle(path, [_report("cpu"), gpu_report])

    with pytest.raises(QualificationRegistryError, match=message):
        load_qualified_candidates(
            path,
            expected_python_version=PYTHON_VERSIONS,
            expected_lock_sha256={
                RuntimeKind.CPU: "a" * 64,
                RuntimeKind.GPU: "b" * 64,
            },
            expected_worker_source_sha256="c" * 64,
            expected_model_manifest_sha256="d" * 64,
            expected_package_inventory_sha256={
                RuntimeKind.CPU: str(_report("cpu")["package_inventory_sha256"]),
                RuntimeKind.GPU: str(gpu_report["package_inventory_sha256"]),
            },
            devices=(_gpu(),),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("precision", "fp32"),
        ("batch_size", 1),
        ("profile_id", "gpu-tampered-profile"),
        ("runtime_fingerprint", "9" * 64),
    ],
)
def test_registry_rejects_tampered_runtime_profile_identity(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    gpu_report = _report("gpu")
    gpu_report[field] = value
    path = tmp_path / "qualification.json"
    _write_bundle(path, [_report("cpu"), gpu_report])

    with pytest.raises(
        QualificationRegistryError,
        match=r"profile|fingerprint",
    ):
        load_qualified_candidates(
            path,
            expected_python_version=PYTHON_VERSIONS,
            expected_lock_sha256={
                RuntimeKind.CPU: "a" * 64,
                RuntimeKind.GPU: "b" * 64,
            },
            expected_worker_source_sha256="c" * 64,
            expected_model_manifest_sha256="d" * 64,
            expected_package_inventory_sha256={
                RuntimeKind.CPU: str(
                    _report("cpu")["package_inventory_sha256"]
                ),
                RuntimeKind.GPU: str(
                    gpu_report["package_inventory_sha256"]
                ),
            },
            devices=(_gpu(),),
        )


def test_registry_rejects_nonportable_cpu_profile(
    tmp_path: Path,
) -> None:
    cpu_report = _report("cpu")
    cpu_report["precision"] = "fp16"
    path = tmp_path / "qualification.json"
    _write_bundle(path, [cpu_report])

    with pytest.raises(QualificationRegistryError, match="profile"):
        load_qualified_candidates(
            path,
            expected_python_version=PYTHON_VERSIONS,
            expected_lock_sha256={RuntimeKind.CPU: "a" * 64},
            expected_worker_source_sha256="c" * 64,
            expected_model_manifest_sha256="d" * 64,
            expected_package_inventory_sha256={
                RuntimeKind.CPU: str(
                    cpu_report["package_inventory_sha256"]
                )
            },
            devices=(),
        )


def test_registry_rejects_old_or_single_image_qualification(tmp_path: Path) -> None:
    path = tmp_path / "qualification.json"
    path.write_text('{"schema_version":1,"reports":[]}', encoding="utf-8")
    with pytest.raises(QualificationRegistryError, match="schema"):
        load_qualified_candidates(
            path,
            expected_python_version=PYTHON_VERSIONS,
            expected_lock_sha256={},
            expected_worker_source_sha256="c" * 64,
            expected_model_manifest_sha256="d" * 64,
            expected_package_inventory_sha256={},
            devices=(),
        )

    cpu_report = _report("cpu")
    images = cpu_report["images"]
    assert isinstance(images, list)
    cpu_report["images"] = images[:1]
    _write_bundle(path, [cpu_report])
    with pytest.raises(QualificationRegistryError, match="images"):
        load_qualified_candidates(
            path,
            expected_python_version=PYTHON_VERSIONS,
            expected_lock_sha256={RuntimeKind.CPU: "a" * 64},
            expected_worker_source_sha256="c" * 64,
            expected_model_manifest_sha256="d" * 64,
            expected_package_inventory_sha256={
                RuntimeKind.CPU: str(
                    cpu_report["package_inventory_sha256"]
                ),
            },
            devices=(),
        )


def test_registry_binds_each_difference_item_to_the_qualified_images(
    tmp_path: Path,
) -> None:
    path = tmp_path / "qualification.json"
    _write_bundle(path, [_report("cpu"), _report("gpu")])
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["difference_report"]["items"][0]["image_sha256"] = "9" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(QualificationRegistryError, match="images"):
        load_qualified_candidates(
            path,
            expected_python_version=PYTHON_VERSIONS,
            expected_lock_sha256={
                RuntimeKind.CPU: "a" * 64,
                RuntimeKind.GPU: "b" * 64,
            },
            expected_worker_source_sha256="c" * 64,
            expected_model_manifest_sha256="d" * 64,
            expected_package_inventory_sha256={
                RuntimeKind.CPU: str(
                    _report("cpu")["package_inventory_sha256"]
                ),
                RuntimeKind.GPU: str(
                    _report("gpu")["package_inventory_sha256"]
                ),
            },
            devices=(_gpu(),),
        )
