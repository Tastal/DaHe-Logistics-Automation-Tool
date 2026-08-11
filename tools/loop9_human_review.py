from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dahe import __version__
from dahe.adapters.chengfeng.live_contract_selection import (
    LiveContractSelectionError,
    load_selected_live_read_contract,
)
from dahe.adapters.files.shadow_selection_manifest import (
    FormalShadowSelectionStore,
    FormalShadowSelectionStoreError,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.application.template_studio.fingerprints import (
    current_template_pipeline_build_fingerprint,
)
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_human_review import (
    Loop9HumanReviewError,
    load_loop9_review_package,
    prepare_loop9_review_package,
    replay_loop9_review,
    seal_loop9_review,
    write_loop9_review_evidence,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare, seal, and replay identity-free Loop 9 offline human "
            "review evidence without connecting to Chengfeng."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare", allow_abbrev=False)
    prepare.add_argument("--data-root", type=_absolute_path, required=True)
    prepare.add_argument(
        "--source-batch",
        type=_absolute_path,
        required=True,
    )
    prepare.add_argument(
        "--dataset-manifest",
        type=_absolute_path,
        required=True,
    )
    prepare.add_argument(
        "--formal-selection",
        type=_absolute_path,
        required=True,
    )
    prepare.add_argument(
        "--image-root",
        type=_absolute_path,
        required=True,
    )
    prepare.add_argument(
        "--auxiliary",
        type=_absolute_path,
        required=True,
    )
    prepare.add_argument(
        "--output-dir",
        type=_absolute_path,
        required=True,
    )

    seal = commands.add_parser("seal", allow_abbrev=False)
    seal.add_argument("--data-root", type=_absolute_path, required=True)
    seal.add_argument("--package-dir", type=_absolute_path, required=True)
    seal.add_argument(
        "--review-answers",
        type=_absolute_path,
        required=True,
    )
    seal.add_argument("--output", type=_absolute_path, required=True)

    replay = commands.add_parser("replay", allow_abbrev=False)
    replay.add_argument("--data-root", type=_absolute_path, required=True)
    replay.add_argument("--package-dir", type=_absolute_path, required=True)
    replay.add_argument("--seal", type=_absolute_path, required=True)
    replay.add_argument(
        "--isolation-evidence",
        type=_absolute_path,
        required=True,
    )
    replay.add_argument("--output", type=_absolute_path, required=True)
    return parser


def _resolved_data_root(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise Loop9HumanReviewError(
            "data root must be a real absolute directory"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9HumanReviewError("data root is unavailable") from exc
    if resolved != path or not resolved.is_dir():
        raise Loop9HumanReviewError(
            "data root must be a real absolute directory"
        )
    return resolved


def _verify_current_selection_authority(
    *,
    data_root: Path,
    selection: FormalShadowSelectionManifest,
) -> None:
    try:
        selected_contract = load_selected_live_read_contract(data_root)
    except LiveContractSelectionError as exc:
        raise Loop9HumanReviewError(
            "active settlement contract is unavailable"
        ) from exc
    batch = selection.batch_manifest
    if (
        batch.source_build_sha256
        != current_loop9_build_sha256(ROOT)
        or batch.pipeline_fingerprint
        != current_template_pipeline_build_fingerprint(
            application_version=__version__,
        )
        or batch.contract_canonical_sha256
        != selected_contract.manifest.canonical_sha256
        or batch.contract_file_sha256
        != selected_contract.contract_file_sha256
        or batch.contract_selection_sha256
        != selected_contract.selection_sha256
    ):
        raise Loop9HumanReviewError(
            "formal selection does not match current authority"
        )


def _load_active_selection_by_sha(
    *,
    data_root: Path,
    selection_sha256: str,
) -> FormalShadowSelectionManifest:
    try:
        selected_contract = load_selected_live_read_contract(data_root)
        current_build = current_loop9_build_sha256(ROOT)
        store = FormalShadowSelectionStore(data_root)
        candidate = store.load_manifest(selection_sha256)
        if (
            candidate.target_kind
            is ShadowBatchTargetKind.CURRENT_LOCKED_50
        ):
            selection = store.load_active_current_locked_manifest(
                selection_sha256
            )
        else:
            selection = store.load_active_real_shadow_manifest(
                selection_sha256,
                expected_current_build_sha256=current_build,
                expected_settlement_contract_sha256=(
                    selected_contract.manifest.canonical_sha256
                ),
            )
    except (
        FormalShadowSelectionStoreError,
        LiveContractSelectionError,
    ) as exc:
        raise Loop9HumanReviewError(
            "formal selection is not the active authority"
        ) from exc
    _verify_current_selection_authority(
        data_root=data_root,
        selection=selection,
    )
    return selection


def _load_active_selection(
    *,
    data_root: Path,
    path: Path,
) -> FormalShadowSelectionManifest:
    expected_root = data_root / "loop9-formal-selections"
    try:
        resolved = path.resolve(strict=True)
        expected_root = expected_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9HumanReviewError(
            "formal selection manifest is unavailable"
        ) from exc
    if (
        path.is_symlink()
        or not resolved.is_file()
        or resolved.parent != expected_root
        or resolved.suffix != ".json"
        or len(resolved.stem) != 64
        or any(character not in "0123456789abcdef" for character in resolved.stem)
    ):
        raise Loop9HumanReviewError(
            "formal selection must be a content-addressed DaHe manifest"
        )
    return _load_active_selection_by_sha(
        data_root=data_root,
        selection_sha256=resolved.stem,
    )


def _verify_active_package_authority(
    *,
    data_root: Path,
    package_dir: Path,
) -> None:
    package = load_loop9_review_package(package_dir)
    selection = _load_active_selection_by_sha(
        data_root=data_root,
        selection_sha256=(
            package.formal_selection.canonical_sha256
        ),
    )
    if (
        selection.to_payload()
        != package.formal_selection.to_payload()
    ):
        raise Loop9HumanReviewError(
            "review package formal selection binding changed"
        )


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    data_root = _resolved_data_root(arguments.data_root)
    if arguments.command == "prepare":
        package = prepare_loop9_review_package(
            source_batch_path=arguments.source_batch,
            dataset_manifest_path=arguments.dataset_manifest,
            formal_selection=_load_active_selection(
                data_root=data_root,
                path=arguments.formal_selection,
            ),
            image_root=arguments.image_root,
            auxiliary_path=arguments.auxiliary,
            output_dir=arguments.output_dir,
        )
        print(
            json.dumps(
                {
                    "canonical_sha256": package.payload["canonical_sha256"],
                    "output": arguments.output_dir.name,
                    "review_kind": package.payload["review_kind"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command == "seal":
        _verify_active_package_authority(
            data_root=data_root,
            package_dir=arguments.package_dir,
        )
        seal = seal_loop9_review(
            package_dir=arguments.package_dir,
            review_answers_path=arguments.review_answers,
            output_path=arguments.output,
        )
        print(
            json.dumps(
                {
                    "canonical_sha256": seal["canonical_sha256"],
                    "output": arguments.output.name,
                    "status": "sealed",
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    _verify_active_package_authority(
        data_root=data_root,
        package_dir=arguments.package_dir,
    )
    evidence = replay_loop9_review(
        package_dir=arguments.package_dir,
        seal_path=arguments.seal,
        isolation_evidence_path=arguments.isolation_evidence,
    )
    write_loop9_review_evidence(
        output_path=arguments.output,
        payload=evidence,
    )
    print(
        json.dumps(
            {
                "canonical_sha256": evidence["canonical_sha256"],
                "output": arguments.output.name,
                "replay_passed": True,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
