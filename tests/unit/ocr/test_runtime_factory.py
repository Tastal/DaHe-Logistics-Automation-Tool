from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, ClassVar

import pytest

from dahe.adapters.ocr import runtime_factory
from dahe.adapters.ocr.devices import NvidiaDevice
from dahe.adapters.ocr.fingerprints import (
    RuntimeFingerprintInput,
    build_runtime_fingerprint,
    build_runtime_profile_id,
)
from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.adapters.ocr.runtime_factory import (
    OcrRuntimeCompositionError,
    build_ocr_execution_backend,
)
from dahe.adapters.ocr.runtime_inventory import inventory_sha256
from dahe.adapters.ocr.runtime_layout import (
    activate_composition,
    write_composition_manifest,
)
from dahe.application.template_studio.fingerprints import (
    current_template_ocr_runtime_set_fingerprint,
)
from dahe.config.schema import AppConfig, OcrPreference, OcrSettings, RuntimeProfile
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrImageExecution,
    OcrImageWork,
    OcrRuntimeIdentity,
)

PYTHON_VERSION = "3.12.10"


def test_formal_ocr_runtime_prefers_root_embed_interpreter(
    tmp_path: Path,
) -> None:
    portable = tmp_path / "ocr-cpu" / "python.exe"
    portable.parent.mkdir()
    portable.write_bytes(b"portable")
    legacy = portable.parent / "Scripts" / "python.exe"
    legacy.parent.mkdir()
    legacy.write_bytes(b"venv")

    assert runtime_factory._runtime_python(portable.parent) == portable.resolve()


class _FakeWorker:
    created: ClassVar[list[_FakeWorker]] = []
    fail_hello_for: ClassVar[str | None] = None

    def __init__(
        self,
        *,
        worker_id: str,
        argv: tuple[str, ...],
        runtime_dir: Path,
        environment: dict[str, str] | None = None,
    ) -> None:
        del worker_id, runtime_dir, environment
        self.argv = argv
        self.closed = False
        self.hello_calls: list[tuple[str, str, float]] = []
        self.runtime_kind = argv[argv.index("--runtime-kind") + 1]
        type(self).created.append(self)

    def hello(
        self,
        *,
        runtime_fingerprint: str,
        profile_id: str,
        timeout_seconds: float,
    ) -> object:
        self.hello_calls.append((runtime_fingerprint, profile_id, timeout_seconds))
        if self.runtime_kind == type(self).fail_hello_for:
            raise RuntimeError("synthetic hello failure")
        return object()

    def request(self, command: object, *, timeout_seconds: float) -> object:
        del command, timeout_seconds
        raise AssertionError("the composition test must not perform OCR")

    def close(self) -> None:
        self.closed = True


class _ManualGateway:
    def __init__(self) -> None:
        self._identity = OcrRuntimeIdentity(
            runtime_kind="cpu",
            profile_id="manual-test-runtime",
            runtime_fingerprint="f" * 64,
        )

    @property
    def identity(self) -> OcrRuntimeIdentity:
        return self._identity

    def extract(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution:
        raise AssertionError(
            f"manual authority test unexpectedly ran OCR: {image} {pipeline_fingerprint}"
        )

    def close(self) -> None:
        return None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _write_models(models_dir: Path) -> str:
    files: list[dict[str, object]] = []
    for model_name in ("PP-OCRv6_medium_det", "PP-OCRv6_medium_rec"):
        model_file = models_dir / model_name / "inference.pdmodel"
        model_file.parent.mkdir(parents=True)
        model_file.write_bytes(model_name.encode("ascii"))
        files.append(
            {
                "relative_path": model_file.relative_to(models_dir).as_posix(),
                "size_bytes": model_file.stat().st_size,
                "sha256": _sha256(model_file),
            }
        )
    manifest_path = models_dir / "model-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "model_set_id": "loop6-test-models",
                "models": [
                    {
                        "name": "PP-OCRv6_medium_det",
                        "purpose": "text_detection",
                    },
                    {
                        "name": "PP-OCRv6_medium_rec",
                        "purpose": "text_recognition",
                    },
                ],
                "files": files,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return _sha256(manifest_path)


def _runtime_report(
    *,
    kind: RuntimeKind,
    inventory: dict[str, str],
    lock_sha256: str,
    worker_sha256: str,
    model_sha256: str,
) -> dict[str, object]:
    gpu = kind is RuntimeKind.GPU
    precision = "fp16" if gpu else "fp32"
    batch_size = 6 if gpu else 1
    stable_device_id = "GPU-qualified" if gpu else None
    driver_version = "610.62" if gpu else None
    profile_id = build_runtime_profile_id(
        runtime_kind=kind,
        stable_device_id=stable_device_id,
        precision=precision,
        batch_size=batch_size,
        worker_count=1,
    )
    runtime_fingerprint = build_runtime_fingerprint(
        RuntimeFingerprintInput(
            runtime_kind=kind,
            python_version=PYTHON_VERSION,
            paddle_version=str(
                inventory.get("paddlepaddle-gpu") or inventory.get("paddlepaddle") or ""
            ),
            paddleocr_version=str(inventory.get("paddleocr", "")),
            paddlex_version=str(inventory.get("paddlex", "")),
            dependency_lock_sha256=lock_sha256,
            model_manifest_sha256=model_sha256,
            worker_build_sha256=worker_sha256,
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
    return {
        "runtime_kind": kind.value,
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
        "peak_memory_used_mib": 4096 if gpu else None,
        "dependency_lock_sha256": lock_sha256,
        "worker_source_sha256": worker_sha256,
        "model_manifest_sha256": model_sha256,
        "packages": inventory,
        "package_inventory_sha256": inventory_sha256(inventory),
        "images": [
            {
                "image_id": "loading",
                "image_sha256": "a" * 64,
                "verified_image_sha256": "a" * 64,
                "elapsed_ms": 10,
                "role": "loading",
                "field_reliable": True,
            },
            {
                "image_id": "unloading",
                "image_sha256": "b" * 64,
                "verified_image_sha256": "b" * 64,
                "elapsed_ms": 11,
                "role": "unloading",
                "field_reliable": True,
            },
        ],
        "p50_ms": 10.5,
        "p95_ms": 11,
    }


def _fixture_layout(tmp_path: Path) -> dict[str, Any]:
    repository_root = tmp_path / "repo"
    runtime_root = tmp_path / "runtime"
    data_root = tmp_path / "data"
    data_root.mkdir(parents=True)
    worker_source = repository_root / "ocr-runtime" / "src" / "dahe_ocr_worker"
    worker_source.mkdir(parents=True)
    (worker_source / "__init__.py").write_text("", encoding="utf-8")
    (worker_source / "engine.py").write_text("BUILD = 1\n", encoding="utf-8")
    (repository_root / "ocr-runtime" / "pyproject.toml").write_text(
        '[project]\nname = "dahe-ocr-worker"\nversion = "0.6.0"\n',
        encoding="utf-8",
    )

    locked: dict[RuntimeKind, dict[str, str]] = {
        RuntimeKind.CPU: {
            "paddlepaddle": "3.3.1",
            "paddleocr": "3.7.0",
            "paddlex": "3.7.2",
        },
        RuntimeKind.GPU: {
            "paddlepaddle-gpu": "3.3.1",
            "paddleocr": "3.7.0",
            "paddlex": "3.7.2",
            "nvidia-cudnn-cu13": "9.13.0.50",
        },
    }
    inventories: dict[RuntimeKind, dict[str, str]] = {}
    lock_hashes: dict[RuntimeKind, str] = {}
    for kind in RuntimeKind:
        lock_path = repository_root / "ocr-runtime" / f"requirements-{kind.value}.lock"
        prefix = "--extra-index-url https://example.invalid/\n" if kind is RuntimeKind.GPU else ""
        lock_path.write_text(
            prefix + "".join(f"{name}=={version}\n" for name, version in locked[kind].items()),
            encoding="utf-8",
        )
        lock_hashes[kind] = _sha256(lock_path)
        inventories[kind] = {
            **locked[kind],
            "pip": "26.1",
            "dahe-ocr-worker": "0.6.0",
        }
        python = runtime_root / f"ocr-{kind.value}" / "Scripts" / "python.exe"
        python.parent.mkdir(parents=True)
        python.write_bytes(b"fake")
        (python.parents[1] / "runtime-installation.json").write_text(
            json.dumps({"runtime_kind": kind.value}),
            encoding="utf-8",
        )

    models_dir = runtime_root / "model-cache" / "official_models"
    models_dir.mkdir(parents=True)
    model_sha256 = _write_models(models_dir)
    worker_sha256 = _tree_sha256(worker_source)
    qualification_path = runtime_root / "qualification" / "qualification.json"
    qualification_path.parent.mkdir()
    qualification_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "reports": [
                    _runtime_report(
                        kind=kind,
                        inventory=inventories[kind],
                        lock_sha256=lock_hashes[kind],
                        worker_sha256=worker_sha256,
                        model_sha256=model_sha256,
                    )
                    for kind in RuntimeKind
                ],
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
                        for image_hash in ("a" * 64, "b" * 64)
                    ],
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    generation_id = "1" * 32
    generation = runtime_root / "generations" / generation_id
    for kind in RuntimeKind:
        shutil.copytree(
            runtime_root / f"ocr-{kind.value}",
            generation / f"ocr-{kind.value}",
        )
    shutil.copytree(
        runtime_root / "model-cache",
        generation / "model-cache",
    )
    active_qualification = generation / "qualification" / "qualification.json"
    active_qualification.parent.mkdir(parents=True)
    shutil.copy2(qualification_path, active_qualification)
    write_composition_manifest(
        generation_dir=generation,
        generation_id=generation_id,
        gpu_present=True,
    )
    activate_composition(
        runtime_root=runtime_root,
        generation_id=generation_id,
    )
    return {
        "repository_root": repository_root,
        "runtime_root": runtime_root,
        "data_root": data_root,
        "inventories": inventories,
        "qualification_path": active_qualification,
        "legacy_qualification_path": qualification_path,
        "models_dir": generation / "model-cache" / "official_models",
        "generation_id": generation_id,
    }


def _config(
    data_root: Path,
    *,
    preference: OcrPreference = OcrPreference.AUTO,
    preferred_device_id: str | None = None,
    allow_cpu_fallback: bool = True,
) -> AppConfig:
    return AppConfig(
        runtime_profile=RuntimeProfile.TEST,
        data_root=data_root,
        ocr=OcrSettings(
            preference=preference,
            preferred_device_id=preferred_device_id,
            allow_cpu_fallback=allow_cpu_fallback,
        ),
    )


@pytest.fixture(autouse=True)
def _reset_worker() -> None:
    _FakeWorker.created = []
    _FakeWorker.fail_hello_for = None


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    layout: dict[str, Any],
    *,
    devices: tuple[NvidiaDevice, ...] | None = None,
) -> None:
    def query_inventory(python: Path) -> dict[str, str]:
        kind = RuntimeKind.GPU if "ocr-gpu" in python.parts else RuntimeKind.CPU
        return dict(layout["inventories"][kind])

    monkeypatch.setattr(runtime_factory, "query_installed_inventory", query_inventory)
    monkeypatch.setattr(
        runtime_factory,
        "_query_runtime_python_version",
        lambda _python: PYTHON_VERSION,
    )
    monkeypatch.setattr(
        runtime_factory,
        "installed_worker_source_sha256",
        lambda **_kwargs: _tree_sha256(
            layout["repository_root"] / "ocr-runtime" / "src" / "dahe_ocr_worker"
        ),
    )
    monkeypatch.setattr(runtime_factory, "SupervisedNdjsonWorker", _FakeWorker)
    monkeypatch.setattr(
        runtime_factory,
        "discover_nvidia_devices",
        lambda: (
            devices
            if devices is not None
            else (
                NvidiaDevice(
                    current_index=3,
                    stable_id="GPU-qualified",
                    name="NVIDIA Example",
                    memory_mib=8192,
                    driver_version="610.62",
                    compute_capability="8.9",
                ),
            )
        ),
    )


def test_factory_builds_qualified_gpu_and_cpu_fallback_with_handshake(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    _install_fakes(monkeypatch, layout)

    backend = build_ocr_execution_backend(
        config=_config(layout["data_root"]),
        repository_root=layout["repository_root"],
        runtime_root=layout["runtime_root"],
    )
    try:
        assert backend.primary_runtime_kind == "gpu"
        assert backend.has_runtime("gpu")
        assert backend.has_runtime("cpu")
        assert len(_FakeWorker.created) == 2
        gpu = next(worker for worker in _FakeWorker.created if worker.runtime_kind == "gpu")
        cpu = next(worker for worker in _FakeWorker.created if worker.runtime_kind == "cpu")
        assert gpu.argv[gpu.argv.index("--precision") + 1] == "fp16"
        assert gpu.argv[gpu.argv.index("--batch-size") + 1] == "6"
        assert gpu.argv[gpu.argv.index("--device-index") + 1] == "3"
        assert gpu.argv[1:5] == ("-I", "-B", "-m", "dahe_ocr_worker")
        assert cpu.argv[cpu.argv.index("--precision") + 1] == "fp32"
        assert cpu.argv[cpu.argv.index("--batch-size") + 1] == "1"
        assert "--device-index" not in cpu.argv
        assert len(gpu.hello_calls) == len(cpu.hello_calls) == 1
        assert all(
            "expected" not in argument.lower() and "platform-weight" not in argument.lower()
            for worker in _FakeWorker.created
            for argument in worker.argv
        )
    finally:
        backend.close()

    assert all(worker.closed for worker in _FakeWorker.created)


def test_factory_binds_formal_authority_to_verified_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    _install_fakes(monkeypatch, layout)

    backend = build_ocr_execution_backend(
        config=_config(layout["data_root"]),
        repository_root=layout["repository_root"],
        runtime_root=layout["runtime_root"],
    )
    try:
        authority = backend.formal_authority
        assert authority is not None
        assert authority.data_root == layout["data_root"].resolve(strict=True)
        assert authority.repository_root == layout["repository_root"].resolve(strict=True)
        identities = (
            backend.identity_for("cpu"),
            backend.identity_for("gpu"),
        )
        assert authority.runtime_identities == identities
        assert authority.runtime_set_sha256 == (
            current_template_ocr_runtime_set_fingerprint(
                tuple(
                    {
                        "profile_id": identity.profile_id,
                        "runtime_fingerprint": identity.runtime_fingerprint,
                        "runtime_kind": identity.runtime_kind,
                    }
                    for identity in identities
                )
            )
        )
        assert len(authority.composition_evidence_sha256) == 64
        assert set(authority.composition_evidence_sha256) <= set("0123456789abcdef")
        authority_field = "runtime_set_sha256"
        with pytest.raises(FrozenInstanceError):
            setattr(authority, authority_field, "0" * 64)
        backend_property = "formal_authority"
        with pytest.raises(AttributeError):
            setattr(backend, backend_property, None)
    finally:
        backend.close()


def test_manually_constructed_backend_has_no_formal_authority() -> None:
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="cpu",
        gateways={"cpu": _ManualGateway()},
    )
    try:
        assert backend.formal_authority is None
    finally:
        backend.close()


def test_factory_uses_the_atomic_active_composition_pointer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    generation_id = str(layout["generation_id"])
    layout["legacy_qualification_path"].write_text(
        '{"legacy":"must-not-be-read"}',
        encoding="utf-8",
    )
    _install_fakes(monkeypatch, layout)

    backend = build_ocr_execution_backend(
        config=_config(layout["data_root"]),
        repository_root=layout["repository_root"],
        runtime_root=layout["runtime_root"],
    )
    try:
        assert backend.primary_runtime_kind == "gpu"
        assert backend.has_runtime("cpu")
        assert backend.has_runtime("gpu")
        assert all(generation_id in Path(worker.argv[0]).parts for worker in _FakeWorker.created)
    finally:
        backend.close()


def test_factory_rejects_complete_legacy_layout_without_active_pointer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    (layout["runtime_root"] / "active-composition.json").unlink()
    _install_fakes(monkeypatch, layout)

    with pytest.raises(OcrRuntimeCompositionError, match="unavailable"):
        build_ocr_execution_backend(
            config=_config(layout["data_root"]),
            repository_root=layout["repository_root"],
            runtime_root=layout["runtime_root"],
        )

    assert _FakeWorker.created == []


def test_factory_honors_cpu_only_without_starting_gpu(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    _install_fakes(monkeypatch, layout)

    backend = build_ocr_execution_backend(
        config=_config(
            layout["data_root"],
            preference=OcrPreference.CPU_ONLY,
            preferred_device_id="GPU-does-not-matter",
            allow_cpu_fallback=False,
        ),
        repository_root=layout["repository_root"],
        runtime_root=layout["runtime_root"],
    )
    try:
        assert backend.primary_runtime_kind == "cpu"
        assert backend.has_runtime("cpu")
        assert not backend.has_runtime("gpu")
        assert [worker.runtime_kind for worker in _FakeWorker.created] == ["cpu"]
    finally:
        backend.close()


def test_factory_honors_preferred_stable_device_and_disables_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    _install_fakes(monkeypatch, layout)

    backend = build_ocr_execution_backend(
        config=_config(
            layout["data_root"],
            preference=OcrPreference.PREFER_GPU,
            preferred_device_id="GPU-qualified",
            allow_cpu_fallback=False,
        ),
        repository_root=layout["repository_root"],
        runtime_root=layout["runtime_root"],
    )
    try:
        assert backend.primary_runtime_kind == "gpu"
        assert backend.has_runtime("gpu")
        assert not backend.has_runtime("cpu")
        assert [worker.runtime_kind for worker in _FakeWorker.created] == ["gpu"]
    finally:
        backend.close()


def test_factory_does_not_substitute_an_unselected_gpu(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    _install_fakes(monkeypatch, layout)

    backend = build_ocr_execution_backend(
        config=_config(
            layout["data_root"],
            preference=OcrPreference.AUTO,
            preferred_device_id="GPU-not-present",
            allow_cpu_fallback=True,
        ),
        repository_root=layout["repository_root"],
        runtime_root=layout["runtime_root"],
    )
    try:
        assert backend.primary_runtime_kind == "cpu"
        assert backend.has_runtime("cpu")
        assert not backend.has_runtime("gpu")
        assert [worker.runtime_kind for worker in _FakeWorker.created] == ["cpu"]
    finally:
        backend.close()


@pytest.mark.parametrize("drift", ["lock", "worker"])
def test_factory_recomputes_source_contract_hashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    layout = _fixture_layout(tmp_path)
    _install_fakes(monkeypatch, layout)
    if drift == "lock":
        (layout["repository_root"] / "ocr-runtime" / "requirements-cpu.lock").write_text(
            "paddlepaddle==3.3.2\npaddleocr==3.7.0\npaddlex==3.7.2\n",
            encoding="utf-8",
        )
    else:
        (
            layout["repository_root"] / "ocr-runtime" / "src" / "dahe_ocr_worker" / "engine.py"
        ).write_text("BUILD = 2\n", encoding="utf-8")

    with pytest.raises(OcrRuntimeCompositionError):
        build_ocr_execution_backend(
            config=_config(layout["data_root"]),
            repository_root=layout["repository_root"],
            runtime_root=layout["runtime_root"],
        )
    assert _FakeWorker.created == []


def test_factory_rejects_installed_worker_source_drift_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    _install_fakes(monkeypatch, layout)
    monkeypatch.setattr(
        runtime_factory,
        "installed_worker_source_sha256",
        lambda **_kwargs: "9" * 64,
    )

    with pytest.raises(OcrRuntimeCompositionError, match="inventory"):
        build_ocr_execution_backend(
            config=_config(layout["data_root"]),
            repository_root=layout["repository_root"],
            runtime_root=layout["runtime_root"],
        )

    assert _FakeWorker.created == []


def test_factory_rejects_inventory_or_model_drift_before_starting_workers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    _install_fakes(monkeypatch, layout)
    layout["inventories"][RuntimeKind.CPU]["unexpected-package"] = "1"

    with pytest.raises(OcrRuntimeCompositionError, match="inventory"):
        build_ocr_execution_backend(
            config=_config(layout["data_root"]),
            repository_root=layout["repository_root"],
            runtime_root=layout["runtime_root"],
        )
    assert _FakeWorker.created == []

    layout = _fixture_layout(tmp_path / "model-drift")
    _install_fakes(monkeypatch, layout)
    (layout["models_dir"] / "PP-OCRv6_medium_det" / "inference.pdmodel").write_bytes(b"changed")
    with pytest.raises(OcrRuntimeCompositionError, match="model"):
        build_ocr_execution_backend(
            config=_config(layout["data_root"]),
            repository_root=layout["repository_root"],
            runtime_root=layout["runtime_root"],
        )
    assert _FakeWorker.created == []


def test_factory_closes_started_worker_when_later_hello_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _fixture_layout(tmp_path)
    _install_fakes(monkeypatch, layout)
    _FakeWorker.fail_hello_for = "cpu"

    with pytest.raises(OcrRuntimeCompositionError, match="handshake"):
        build_ocr_execution_backend(
            config=_config(layout["data_root"]),
            repository_root=layout["repository_root"],
            runtime_root=layout["runtime_root"],
        )

    assert len(_FakeWorker.created) == 2
    assert all(worker.closed for worker in _FakeWorker.created)
