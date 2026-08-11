from __future__ import annotations

import hashlib
import importlib
import io
import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


@contextmanager
def _worker_main(project_root: Path) -> Iterator[ModuleType]:
    worker_src = str(project_root / "ocr-runtime" / "src")
    sys.path.insert(0, worker_src)
    try:
        yield importlib.import_module("dahe_ocr_worker.__main__")
    finally:
        sys.path.remove(worker_src)
        for module_name in tuple(sys.modules):
            if module_name == "dahe_ocr_worker" or module_name.startswith("dahe_ocr_worker."):
                sys.modules.pop(module_name, None)


def _command(module: ModuleType, payload: bytes) -> object:
    return module.WorkerCommand(
        command_id="unicode-image",
        operation="extract",
        image_sha256=hashlib.sha256(payload).hexdigest(),
        relative_path="证据/装货磅单.png",
        pipeline_fingerprint="1" * 64,
        runtime_fingerprint="2" * 64,
        profile_id="cpu-portable",
    )


def test_worker_resolves_hashed_images_below_the_limit_in_a_unicode_data_root(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "大禾数据"
    image = data_root / "证据" / "装货磅单.png"
    image.parent.mkdir(parents=True)
    payload = b"synthetic-image"
    image.write_bytes(payload)

    with _worker_main(project_root) as module:
        snapshot = module._read_verified_image(
            data_root.resolve(),
            _command(module, payload),
        )

    assert snapshot == payload


def test_worker_ocr_input_remains_the_bytes_that_were_hashed(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "大禾数据"
    image = data_root / "证据" / "装货磅单.png"
    image.parent.mkdir(parents=True)
    original = b"first-immutable-snapshot"
    image.write_bytes(original)

    with _worker_main(project_root) as module:
        snapshot = module._read_verified_image(
            data_root.resolve(),
            _command(module, original),
        )
        image.write_bytes(b"replacement-after-verification")

    assert snapshot == original
    assert snapshot != image.read_bytes()


def test_worker_rejects_an_image_above_the_byte_limit_before_ocr(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "data"
    image = data_root / "证据" / "装货磅单.png"
    image.parent.mkdir(parents=True)
    payload = b"too-large"
    image.write_bytes(payload)

    with _worker_main(project_root) as module:
        monkeypatch.setattr(module, "MAX_IMAGE_BYTES", len(payload) - 1)
        with pytest.raises(module.WorkerProtocolViolation, match="byte limit"):
            module._read_verified_image(
                data_root.resolve(),
                _command(module, payload),
            )


def test_worker_exits_after_one_inference_failure(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "data"
    image = data_root / "evidence" / "ticket.png"
    image.parent.mkdir(parents=True)
    payload = b"synthetic-image"
    image.write_bytes(payload)
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    manifest = models_dir / "model-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    runtime_fingerprint = "2" * 64
    profile_id = "gpu-failure-test"
    command = {
        "protocol_version": 1,
        "command_id": "inference-failure",
        "operation": "extract",
        "image_sha256": hashlib.sha256(payload).hexdigest(),
        "relative_path": "evidence/ticket.png",
        "pipeline_fingerprint": "1" * 64,
        "runtime_fingerprint": runtime_fingerprint,
        "profile_id": profile_id,
    }
    stdin_bytes = (json.dumps(command, separators=(",", ":")).encode("utf-8") + b"\n") * 2
    fake_stdin = io.TextIOWrapper(io.BytesIO(stdin_bytes), encoding="utf-8")
    extract_calls = 0
    output_lines: list[str] = []

    class FailingEngine:
        def __init__(self, _config: object) -> None:
            return None

        def extract(self, _image_bytes: bytes) -> dict[str, object]:
            nonlocal extract_calls
            extract_calls += 1
            raise RuntimeError("synthetic CUDA inference failure")

    class FakeProtocolStdout:
        @staticmethod
        def write_line(line: str) -> None:
            output_lines.append(line)

    @contextmanager
    def fake_isolation() -> Iterator[FakeProtocolStdout]:
        yield FakeProtocolStdout()

    with _worker_main(project_root) as module:
        monkeypatch.setattr(
            module,
            "_parser",
            lambda: SimpleNamespace(
                parse_args=lambda: SimpleNamespace(
                    runtime_kind="gpu",
                    data_root=data_root,
                    models_dir=models_dir,
                    model_manifest=manifest,
                    runtime_fingerprint=runtime_fingerprint,
                    profile_id=profile_id,
                    device_index=0,
                    precision="fp16",
                    batch_size=6,
                    cpu_threads=4,
                )
            ),
        )
        monkeypatch.setattr(module, "PaddleEngine", FailingEngine)
        monkeypatch.setattr(
            module,
            "load_and_verify_model_manifest",
            lambda **_kwargs: {},
        )
        monkeypatch.setattr(
            module,
            "install_python_network_guard",
            lambda: None,
        )
        monkeypatch.setattr(
            module,
            "isolated_protocol_stdout",
            fake_isolation,
        )
        monkeypatch.setattr(module.sys, "stdin", fake_stdin)

        exit_code = module.main()

    assert exit_code == 43
    assert extract_calls == 1
    assert len(output_lines) == 1
    assert json.loads(output_lines[0])["status"] == "error"
