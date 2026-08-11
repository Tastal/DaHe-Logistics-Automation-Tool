from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.adapters.ocr.runtime_layout import ActiveOcrComposition
from tools import bootstrap_ocr


def test_managed_path_must_be_a_child_of_runtime_root(tmp_path: Path) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()

    assert bootstrap_ocr._assert_managed_path(
        runtime_root / "ocr-cpu",
        runtime_root=runtime_root,
    ) == (runtime_root / "ocr-cpu").resolve()

    with pytest.raises(SystemExit, match="outside"):
        bootstrap_ocr._assert_managed_path(
            runtime_root,
            runtime_root=runtime_root,
        )
    with pytest.raises(SystemExit, match="outside"):
        bootstrap_ocr._assert_managed_path(
            tmp_path / "other",
            runtime_root=runtime_root,
        )


def _active(
    runtime_root: Path,
    *,
    gpu: bool,
) -> ActiveOcrComposition:
    cpu = runtime_root / "active" / "ocr-cpu"
    models = runtime_root / "active" / "models"
    qualification = runtime_root / "active" / "qualification.json"
    cpu.mkdir(parents=True)
    models.mkdir(parents=True)
    qualification.write_text("{}", encoding="utf-8")
    gpu_path = runtime_root / "active" / "ocr-gpu" if gpu else None
    if gpu_path is not None:
        gpu_path.mkdir()
    return ActiveOcrComposition(
        generation_id="0" * 32,
        generation_dir=runtime_root / "active",
        cpu_runtime=cpu,
        gpu_runtime=gpu_path,
        models_dir=models,
        qualification_path=qualification,
    )


def test_gpu_only_partial_upgrade_is_rejected() -> None:
    with pytest.raises(SystemExit, match="GPU-only"):
        bootstrap_ocr._runtime_kinds_for_request("gpu", active=None)


def test_cpu_partial_upgrade_cannot_drop_an_active_gpu(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    active = _active(runtime_root, gpu=True)

    with pytest.raises(SystemExit, match="runtime=all"):
        bootstrap_ocr._runtime_kinds_for_request("cpu", active=active)

    assert bootstrap_ocr._runtime_kinds_for_request(
        "all",
        active=active,
    ) == ("cpu", "gpu")


def test_failed_model_provisioning_never_mutates_active_models(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    generation = runtime_root / "generations" / ("1" * 32)
    generation.mkdir(parents=True)
    active = _active(runtime_root, gpu=True)
    marker = active.models_dir / "identity.txt"
    marker.write_text("old-models", encoding="utf-8")

    def fail_provision(**kwargs: object) -> None:
        staging = Path(str(kwargs["candidate_cache_root"]))
        (staging / "official_models").mkdir(parents=True)
        (staging / "official_models" / "partial").write_bytes(b"partial")
        raise RuntimeError("download interrupted")

    monkeypatch.setattr(bootstrap_ocr, "_provision_models", fail_provision)

    with pytest.raises(RuntimeError, match="interrupted"):
        bootstrap_ocr._stage_models(
            runtime_root=runtime_root,
            generation_dir=generation,
            cpu_python=tmp_path / "python.exe",
            active=active,
            provision=True,
            model_source="aistudio",
        )

    assert marker.read_text(encoding="utf-8") == "old-models"
    assert not (generation / "model-cache").exists()
    assert not tuple(runtime_root.glob(".model-staging-*"))


def test_qualification_must_bind_every_runtime_in_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "qualification.json").write_text("{}", encoding="utf-8")
    generation = tmp_path / "generation"
    monkeypatch.setattr(
        bootstrap_ocr,
        "load_qualification_bundle",
        lambda _path: SimpleNamespace(
            reports=(
                SimpleNamespace(
                    runtime_kind=SimpleNamespace(value="cpu")
                ),
            )
        ),
    )

    with pytest.raises(SystemExit, match="every runtime"):
        bootstrap_ocr._publish_qualification(
            runtime_kinds=("cpu", "gpu"),
            output_dir=output,
            generation_dir=generation,
        )


def _mock_bootstrap_candidates(
    monkeypatch: pytest.MonkeyPatch,
    *,
    runtime_root: Path,
    fail_qualification: bool,
) -> None:
    monkeypatch.setattr(
        bootstrap_ocr,
        "EXPECTED_MAIN_PYTHON",
        Path(sys.executable).resolve(),
    )
    monkeypatch.setattr(
        bootstrap_ocr,
        "_parser",
        lambda: SimpleNamespace(
            parse_args=lambda: SimpleNamespace(
                runtime="all",
                runtime_root=runtime_root,
                provision_models=False,
                model_source="aistudio",
                precision="fp16",
                batch_size=6,
            )
        ),
    )

    def build_candidate(
        runtime_kind: str,
        *,
        runtime_root: Path,
        generation_dir: Path,
    ) -> Path:
        del runtime_root
        candidate = generation_dir / f"ocr-{runtime_kind}"
        (candidate / "Scripts").mkdir(parents=True)
        (candidate / "Scripts" / "python.exe").write_bytes(b"fake")
        (candidate / "runtime-installation.json").write_text(
            f'{{"runtime_kind":"{runtime_kind}"}}',
            encoding="utf-8",
        )
        return candidate

    def stage_models(**kwargs: object) -> Path:
        generation = Path(str(kwargs["generation_dir"]))
        models = generation / "model-cache" / "official_models"
        models.mkdir(parents=True)
        (models / "model-manifest.json").write_text(
            '{"model":"qualified"}',
            encoding="utf-8",
        )
        return models

    def qualify(*_args: object, **_kwargs: object) -> None:
        if fail_qualification:
            raise RuntimeError("synthetic smoke failure")

    def publish(**kwargs: object) -> Path:
        generation = Path(str(kwargs["generation_dir"]))
        qualification = generation / "qualification" / "qualification.json"
        qualification.parent.mkdir()
        qualification.write_text(
            '{"reports":['
            '{"runtime_kind":"cpu"},'
            '{"runtime_kind":"gpu"}'
            "]}",
            encoding="utf-8",
        )
        return qualification

    monkeypatch.setattr(bootstrap_ocr, "_build_candidate", build_candidate)
    monkeypatch.setattr(bootstrap_ocr, "_stage_models", stage_models)
    monkeypatch.setattr(bootstrap_ocr, "_qualify_composition", qualify)
    monkeypatch.setattr(bootstrap_ocr, "_publish_qualification", publish)


def test_bootstrap_publishes_one_complete_mocked_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    _mock_bootstrap_candidates(
        monkeypatch,
        runtime_root=runtime_root,
        fail_qualification=False,
    )

    bootstrap_ocr.main()

    active = bootstrap_ocr.resolve_active_composition(
        runtime_root,
        allow_legacy=False,
    )
    assert active.generation_id is not None
    assert active.gpu_runtime is not None
    assert (runtime_root / "active-composition.json").is_file()


def test_bootstrap_smoke_failure_leaves_no_partial_active_pointer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    _mock_bootstrap_candidates(
        monkeypatch,
        runtime_root=runtime_root,
        fail_qualification=True,
    )

    with pytest.raises(RuntimeError, match="smoke failure"):
        bootstrap_ocr.main()

    assert not (runtime_root / "active-composition.json").exists()
    assert not tuple((runtime_root / "generations").glob("*"))


def test_candidate_qualification_publishes_requested_gpu_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(bootstrap_ocr, "_run", commands.append)

    bootstrap_ocr._qualify_composition(
        ("cpu", "gpu"),
        runtime_root=tmp_path / "runtime",
        generation_dir=tmp_path / "generation",
        models_dir=tmp_path / "models",
        output_dir=tmp_path / "qualification",
        precision="fp16",
        batch_size=6,
    )

    command = commands[0]
    assert command[command.index("--precision") + 1] == "fp16"
    assert command[command.index("--batch-size") + 1] == "6"
