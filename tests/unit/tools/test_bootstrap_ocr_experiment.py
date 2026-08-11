from __future__ import annotations

from tools import bootstrap_ocr_experiment as module
from tools.ocr_experiment import load_experiment_manifest


def test_bootstrap_requirements_match_approved_manifest() -> None:
    manifest = load_experiment_manifest()

    assert module.locked_requirements(manifest) == {
        "cleanvision": "cleanvision==0.3.7",
        "rapidocr": "rapidocr==3.9.2",
        "rapidocr_backend": "onnxruntime==1.28.0",
    }


def test_package_locks_are_complete_and_contain_no_local_paths() -> None:
    manifest = load_experiment_manifest()

    cleanvision = module.locked_package_inventory("cleanvision")
    rapidocr = module.locked_package_inventory("rapidocr")

    assert "cleanvision==0.3.7" in cleanvision
    assert "rapidocr==3.9.2" in rapidocr
    assert "onnxruntime==1.28.0" in rapidocr
    combined = (*cleanvision, *rapidocr)
    assert all(
        " @ " not in item and "file:" not in item.casefold()
        for item in combined
    )
    assert module._sanitized_freeze(
        [
            "rapidocr @ file:///temporary/rapidocr.whl",
            "onnxruntime @ file:///temporary/onnxruntime.whl",
            "pip==25.0.1",
        ],
        manifest,
    ) == ("onnxruntime==1.28.0", "rapidocr==3.9.2")
