from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from dahe import __version__
from dahe.adapters.chengfeng.live_contract_selection import (
    LiveContractSelectionError,
    load_selected_live_read_contract,
)
from dahe.adapters.files.shadow_batch_manifest import (
    ShadowBatchManifestStore,
    ShadowBatchManifestStoreError,
)
from dahe.adapters.files.shadow_selection_manifest import (
    FormalShadowSelectionStore,
    FormalShadowSelectionStoreError,
)
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchManifest,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.application.template_studio.fingerprints import (
    current_template_pipeline_build_fingerprint,
)
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_draft_suggestions import (
    Loop9DraftSuggestionError,
    build_blank_draft_template,
    load_draft_document,
    persist_new_draft_document,
    seal_independent_draft_suggestions,
    verify_current_locked_source_binding,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build identity-bound, non-truth Loop 9 visual draft "
            "suggestions entirely offline."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "seal"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument(
            "--data-root",
            type=_absolute_path,
            required=True,
        )
        command.add_argument(
            "--formal-selection",
            type=_absolute_path,
            required=True,
        )
        command.add_argument(
            "--source-batch",
            type=_absolute_path,
            required=True,
        )
        if name == "seal":
            command.add_argument(
                "--draft",
                type=_absolute_path,
                required=True,
            )
        command.add_argument(
            "--output",
            type=_absolute_path,
            required=True,
        )
    return parser


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    reparse_flag = getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _resolved_data_root(path: Path) -> Path:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or _is_reparse_point(path)
    ):
        raise Loop9DraftSuggestionError(
            "data root must be a real absolute directory"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9DraftSuggestionError(
            "data root is unavailable"
        ) from exc
    if (
        resolved != Path(os.path.abspath(os.fspath(path)))
        or not resolved.is_dir()
    ):
        raise Loop9DraftSuggestionError(
            "data root must be a real absolute directory"
        )
    return resolved


def _exact_content_addressed_path(
    *,
    path: Path,
    expected_root: Path,
    label: str,
) -> tuple[Path, str]:
    try:
        resolved = path.resolve(strict=True)
        root = expected_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9DraftSuggestionError(
            f"{label} is unavailable"
        ) from exc
    if (
        path.is_symlink()
        or _is_reparse_point(path)
        or not resolved.is_file()
        or resolved.parent != root
        or resolved.suffix != ".json"
        or _SHA256.fullmatch(resolved.stem) is None
    ):
        raise Loop9DraftSuggestionError(
            f"{label} must be a content-addressed DaHe manifest"
        )
    return resolved, resolved.stem


def _load_current_locked_authority(
    *,
    data_root: Path,
    formal_selection_path: Path,
    source_batch_path: Path,
) -> tuple[
    FormalShadowSelectionManifest,
    ChengfengShadowBatchManifest,
]:
    selection_path, selection_sha256 = _exact_content_addressed_path(
        path=formal_selection_path,
        expected_root=data_root / "loop9-formal-selections",
        label="formal selection",
    )
    batch_path, batch_sha256 = _exact_content_addressed_path(
        path=source_batch_path,
        expected_root=data_root / "chengfeng-shadow-batches",
        label="source batch",
    )
    if selection_path != formal_selection_path:
        raise Loop9DraftSuggestionError(
            "formal selection path is unsafe"
        )
    if batch_path != source_batch_path:
        raise Loop9DraftSuggestionError("source batch path is unsafe")
    try:
        selection = FormalShadowSelectionStore(
            data_root
        ).load_active_current_locked_manifest(selection_sha256)
        source_batch = ShadowBatchManifestStore(
            data_root / "chengfeng-shadow-batches"
        ).load(batch_sha256)
        selected_contract = load_selected_live_read_contract(data_root)
    except (
        FormalShadowSelectionStoreError,
        ShadowBatchManifestStoreError,
        LiveContractSelectionError,
    ) as exc:
        raise Loop9DraftSuggestionError(
            "current locked source authority is unavailable"
        ) from exc
    verify_current_locked_source_binding(
        formal_selection=selection,
        source_batch=source_batch,
    )
    if (
        source_batch.source_build_sha256
        != current_loop9_build_sha256(ROOT)
        or source_batch.pipeline_fingerprint
        != current_template_pipeline_build_fingerprint(
            application_version=__version__,
        )
        or source_batch.contract_canonical_sha256
        != selected_contract.manifest.canonical_sha256
        or source_batch.contract_file_sha256
        != selected_contract.contract_file_sha256
        or source_batch.contract_selection_sha256
        != selected_contract.selection_sha256
    ):
        raise Loop9DraftSuggestionError(
            "current locked source does not match current authority"
        )
    return selection, source_batch


def _summary(
    *,
    command: str,
    output: Path,
    payload: dict[str, object],
) -> None:
    print(
        json.dumps(
            {
                "artifact_kind": payload["kind"],
                "canonical_sha256": payload.get("canonical_sha256"),
                "command": command,
                "output": os.fspath(output),
                "source_binding_sha256": payload.get(
                    "source_binding_sha256"
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    try:
        data_root = _resolved_data_root(arguments.data_root)
        selection, source_batch = _load_current_locked_authority(
            data_root=data_root,
            formal_selection_path=arguments.formal_selection,
            source_batch_path=arguments.source_batch,
        )
        if arguments.command == "init":
            payload = build_blank_draft_template(
                formal_selection=selection,
                source_batch=source_batch,
            )
        else:
            payload = seal_independent_draft_suggestions(
                formal_selection=selection,
                source_batch=source_batch,
                draft=load_draft_document(arguments.draft),
            )
        output = persist_new_draft_document(
            output=arguments.output,
            payload=payload,
        )
    except Loop9DraftSuggestionError as exc:
        raise SystemExit(str(exc)) from exc
    _summary(
        command=arguments.command,
        output=output,
        payload=payload,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
