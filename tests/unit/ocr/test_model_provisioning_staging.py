from __future__ import annotations

from pathlib import Path

import pytest

from tools.provision_ocr_models import _prepare_candidate_cache


def test_model_provisioning_can_only_create_a_new_managed_staging_cache(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    active = runtime_root / "model-cache"
    active.mkdir()
    (active / "identity.txt").write_text("active", encoding="utf-8")
    candidate = runtime_root / f".model-staging-{'1' * 32}"

    prepared = _prepare_candidate_cache(
        runtime_root=runtime_root,
        candidate_cache_root=candidate,
    )

    assert prepared == candidate.resolve()
    assert prepared.is_dir()
    assert (active / "identity.txt").read_text(encoding="utf-8") == "active"


@pytest.mark.parametrize(
    "candidate_name",
    [
        "model-cache",
        ".model-staging-invalid",
    ],
)
def test_model_provisioning_rejects_active_or_unmanaged_targets(
    tmp_path: Path,
    candidate_name: str,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()

    with pytest.raises(SystemExit, match="staging"):
        _prepare_candidate_cache(
            runtime_root=runtime_root,
            candidate_cache_root=runtime_root / candidate_name,
        )


def test_model_provisioning_rejects_preexisting_staging_content(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    candidate = runtime_root / f".model-staging-{'1' * 32}"
    candidate.mkdir()
    (candidate / "partial-download").write_bytes(b"partial")

    with pytest.raises(SystemExit, match="new managed"):
        _prepare_candidate_cache(
            runtime_root=runtime_root,
            candidate_cache_root=candidate,
        )
