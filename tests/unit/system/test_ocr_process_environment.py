from __future__ import annotations

from pathlib import Path

import pytest

from dahe.system.supervision import build_isolated_child_environment


def test_ocr_child_environment_is_whitelisted_and_offline(
    tmp_path: Path,
) -> None:
    inherited = {
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "COMSPEC": r"C:\Windows\System32\cmd.exe",
        "ProgramFiles": r"C:\Program Files",
        "ProgramFiles(x86)": r"C:\Program Files (x86)",
        "NUMBER_OF_PROCESSORS": "16",
        "HTTP_PROXY": "http://secret-proxy.invalid",
        "HTTPS_PROXY": "http://secret-proxy.invalid",
        "AWS_SECRET_ACCESS_KEY": "secret",
        "PADDLE_PDX_MODEL_SOURCE": "huggingface",
        "CUDA_VISIBLE_DEVICES": "7",
    }

    environment = build_isolated_child_environment(
        runtime_dir=tmp_path,
        inherited=inherited,
        overrides={
            "MKL_NUM_THREADS": "4",
            "OMP_NUM_THREADS": "4",
            "PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK": "True",
            "PADDLE_PDX_DISABLE_DEVICE_FALLBACK": "True",
        },
    )

    assert environment["SYSTEMROOT"] == r"C:\Windows"
    assert environment["ProgramFiles"] == r"C:\Program Files"
    assert environment["ProgramFiles(x86)"] == r"C:\Program Files (x86)"
    assert environment["PYTHONUTF8"] == "1"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["HF_HUB_OFFLINE"] == "1"
    assert environment["TRANSFORMERS_OFFLINE"] == "1"
    assert environment["PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK"] == "True"
    assert environment["OMP_NUM_THREADS"] == "4"
    assert environment["MKL_NUM_THREADS"] == "4"
    assert "HTTP_PROXY" not in environment
    assert "HTTPS_PROXY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "PADDLE_PDX_MODEL_SOURCE" not in environment
    assert "CUDA_VISIBLE_DEVICES" not in environment
    assert Path(environment["TEMP"]).parent == tmp_path.resolve()
    assert Path(environment["USERPROFILE"]).parent == tmp_path.resolve()


def test_ocr_child_environment_rejects_unapproved_overrides(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not allowed"):
        build_isolated_child_environment(
            runtime_dir=tmp_path,
            inherited={},
            overrides={"HTTP_PROXY": "http://proxy.invalid"},
        )

    with pytest.raises(ValueError, match="integer from 1 to 8"):
        build_isolated_child_environment(
            runtime_dir=tmp_path,
            inherited={},
            overrides={"OMP_NUM_THREADS": "99"},
        )
