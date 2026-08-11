from __future__ import annotations

import argparse
import json
import os
import re
import sys
from contextlib import ExitStack
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
from dahe.adapters.ocr.locked_set_evaluator import (
    LocalOcrLockedImageEvaluator,
)
from dahe.adapters.ocr.runtime_factory import build_ocr_execution_backend
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchManifest,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.application.template_studio.fingerprints import (
    current_template_pipeline_build_fingerprint,
    current_template_pipeline_build_manifest,
)
from dahe.application.template_studio.formal_development_authority import (
    build_current_formal_development_authority,
)
from dahe.bootstrap import prepare_startup_environment
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.system.instance_lock import SingleInstanceGuard
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_locked_gate import (
    CurrentLockedGateAuthorityStore,
    Loop9CurrentLockedGateError,
)
from dahe.verification.loop9_machine_results import (
    Loop9MachineResultError,
    build_formal_machine_result_manifest,
    build_shadow_review_auxiliary,
    evaluate_sealed_machine_results,
    formal_human_truth_binding_from_seal,
    formal_machine_authority_from_evaluator,
    persist_machine_result_manifest,
    persist_machine_truth_evaluation,
    persist_shadow_review_auxiliary,
    read_scheduler_batch_projection,
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
            "Build and evaluate offline Loop 9 CPU/GPU machine evidence. "
            "This tool never connects to Chengfeng."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", allow_abbrev=False)
    run.add_argument("--data-root", type=_absolute_path, required=True)
    run.add_argument("--source-batch", type=_absolute_path, required=True)
    run.add_argument(
        "--source-selection",
        type=_absolute_path,
        required=True,
        help=(
            "Exact content-addressed active formal selection that owns "
            "the source batch."
        ),
    )
    run.add_argument("--job-id", required=True)
    run.add_argument("--timeout-seconds", type=float, default=180.0)
    run.add_argument("--package-dir", type=_absolute_path)
    run.add_argument("--seal", type=_absolute_path)

    evaluate = commands.add_parser("evaluate", allow_abbrev=False)
    evaluate.add_argument("--data-root", type=_absolute_path, required=True)
    evaluate.add_argument("--package-dir", type=_absolute_path, required=True)
    evaluate.add_argument("--seal", type=_absolute_path, required=True)
    evaluate.add_argument(
        "--machine-result",
        type=_absolute_path,
        required=True,
    )
    evaluate.add_argument(
        "--locked-selection",
        type=_absolute_path,
        help=(
            "Exact content-addressed current_locked_50 selection. "
            "Required for the locked-set evaluation and invalid for the "
            "30-item shadow evaluation."
        ),
    )
    return parser


def _load_batch(
    *,
    data_root: Path,
    path: Path,
) -> ChengfengShadowBatchManifest:
    expected_root = (data_root / "chengfeng-shadow-batches").resolve()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9MachineResultError("source batch manifest is unavailable") from exc
    if (
        path.is_symlink()
        or not resolved.is_file()
        or resolved.parent != expected_root
        or resolved.suffix != ".json"
        or _SHA256.fullmatch(resolved.stem) is None
    ):
        raise Loop9MachineResultError("source batch must be a content-addressed DaHe manifest")
    try:
        return ShadowBatchManifestStore(expected_root).load(resolved.stem)
    except ShadowBatchManifestStoreError as exc:
        raise Loop9MachineResultError("source batch manifest is invalid") from exc


def _config(data_root: Path) -> AppConfig:
    return AppConfig(
        runtime_profile=RuntimeProfile.DEVELOPMENT,
        data_root=data_root,
    )


def _load_locked_selection(
    *,
    data_root: Path,
    path: Path,
) -> FormalShadowSelectionManifest:
    selection_sha256 = _selection_path_sha256(
        data_root=data_root,
        path=path,
        label="locked-selection",
    )
    try:
        selection = FormalShadowSelectionStore(
            data_root
        ).load_active_current_locked_manifest(selection_sha256)
    except FormalShadowSelectionStoreError as exc:
        raise Loop9MachineResultError(
            "locked-selection manifest is invalid"
        ) from exc
    _verify_current_selection_authority(
        data_root=data_root,
        selection=selection,
        label="locked-selection",
    )
    return selection


def _selection_path_sha256(
    *,
    data_root: Path,
    path: Path,
    label: str,
) -> str:
    expected_root = (data_root / "loop9-formal-selections").resolve()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Loop9MachineResultError(
            f"{label} manifest is unavailable"
        ) from exc
    if (
        path.is_symlink()
        or not resolved.is_file()
        or resolved.parent != expected_root
        or resolved.suffix != ".json"
        or _SHA256.fullmatch(resolved.stem) is None
    ):
        raise Loop9MachineResultError(
            f"{label} must be a content-addressed DaHe manifest"
        )
    return resolved.stem


def _verify_current_selection_authority(
    *,
    data_root: Path,
    selection: FormalShadowSelectionManifest,
    label: str,
) -> None:
    try:
        selected_contract = load_selected_live_read_contract(data_root)
    except LiveContractSelectionError as exc:
        raise Loop9MachineResultError(
            f"{label} active settlement contract is unavailable"
        ) from exc
    batch = selection.batch_manifest
    if batch.source_build_sha256 != current_loop9_build_sha256(ROOT):
        raise Loop9MachineResultError(
            f"{label} does not belong to the current build"
        )
    if (
        batch.pipeline_fingerprint
        != current_template_pipeline_build_fingerprint(
            application_version=__version__,
        )
    ):
        raise Loop9MachineResultError(
            f"{label} does not belong to the current OCR pipeline"
        )
    if (
        batch.contract_canonical_sha256
        != selected_contract.manifest.canonical_sha256
        or batch.contract_file_sha256
        != selected_contract.contract_file_sha256
        or batch.contract_selection_sha256
        != selected_contract.selection_sha256
    ):
        raise Loop9MachineResultError(
            f"{label} does not match the active settlement contract"
        )


def _load_active_run_selection(
    *,
    data_root: Path,
    path: Path,
    batch: ChengfengShadowBatchManifest,
) -> FormalShadowSelectionManifest:
    selection_sha256 = _selection_path_sha256(
        data_root=data_root,
        path=path,
        label="source selection",
    )
    store = FormalShadowSelectionStore(data_root)
    try:
        selected_contract = load_selected_live_read_contract(data_root)
    except LiveContractSelectionError as exc:
        raise Loop9MachineResultError(
            "source selection active settlement contract is unavailable"
        ) from exc
    current_build = current_loop9_build_sha256(ROOT)
    try:
        if (
            batch.target_kind
            is ShadowBatchTargetKind.CURRENT_LOCKED_50
        ):
            selection = store.load_active_current_locked_manifest(
                selection_sha256
            )
        elif (
            batch.target_kind
            is ShadowBatchTargetKind.REAL_SHADOW_30
        ):
            selection = store.load_active_real_shadow_manifest(
                selection_sha256,
                expected_current_build_sha256=current_build,
                expected_settlement_contract_sha256=(
                    selected_contract.manifest.canonical_sha256
                ),
            )
        else:
            raise Loop9MachineResultError(
                "source selection target is invalid"
            )
    except FormalShadowSelectionStoreError as exc:
        raise Loop9MachineResultError(
            "source selection is not the active formal authority"
        ) from exc
    if (
        selection.target_kind is not batch.target_kind
        or selection.batch_manifest.canonical_sha256
        != batch.canonical_sha256
    ):
        raise Loop9MachineResultError(
            "source selection does not own the source batch"
        )
    _verify_current_selection_authority(
        data_root=data_root,
        selection=selection,
        label="source selection",
    )
    return selection


def _run(arguments: argparse.Namespace) -> dict[str, object]:
    config = _config(arguments.data_root)
    data_root = prepare_startup_environment(config, ROOT)
    batch = _load_batch(data_root=data_root, path=arguments.source_batch)
    if (arguments.package_dir is None) != (arguments.seal is None):
        raise Loop9MachineResultError(
            "review package and human truth seal must be provided together"
        )
    human_truth_binding = (
        None
        if arguments.package_dir is None
        else formal_human_truth_binding_from_seal(
            package_dir=arguments.package_dir,
            seal_path=arguments.seal,
            batch=batch,
        )
    )
    if batch.target_kind is ShadowBatchTargetKind.CURRENT_LOCKED_50 and human_truth_binding is None:
        raise Loop9MachineResultError("current locked formal run requires --package-dir and --seal")
    source_selection = _load_active_run_selection(
        data_root=data_root,
        path=arguments.source_selection,
        batch=batch,
    )
    if not isinstance(arguments.timeout_seconds, float) or arguments.timeout_seconds <= 0:
        raise Loop9MachineResultError("OCR evaluation timeout must be positive")
    with ExitStack() as stack:
        guard = stack.enter_context(
            SingleInstanceGuard(
                data_root,
                config.port,
                __version__,
            )
        )
        runtime = SqliteRuntime(
            data_root=data_root,
            project_root=ROOT,
            instance_id=guard.instance_id,
        )
        stack.callback(runtime.close)
        scheduler = read_scheduler_batch_projection(
            data_root=data_root,
            batch=batch,
            job_id=arguments.job_id,
        )
        development_authority = build_current_formal_development_authority(runtime)
        backend = build_ocr_execution_backend(
            config=config,
            repository_root=ROOT,
        )
        stack.callback(backend.close)
        application_build = current_template_pipeline_build_manifest(
            application_version=__version__,
        )
        evaluator = LocalOcrLockedImageEvaluator(
            backend=backend,
            templates=development_authority.shadow_templates,
            application_build_sha256=(application_build.canonical_sha256),
            application_build_manifest=application_build,
            timeout_seconds=arguments.timeout_seconds,
        )
        authority = formal_machine_authority_from_evaluator(
            current_loop9_build_sha256=current_loop9_build_sha256(ROOT),
            development_authority_sha256=(development_authority.authority_sha256),
            evaluator=evaluator,
        )
        manifest = build_formal_machine_result_manifest(
            batch=batch,
            source_selection=source_selection,
            scheduler=scheduler,
            authority=authority,
            evaluator=evaluator,
            human_truth_binding=human_truth_binding,
        )
        machine_path = persist_machine_result_manifest(
            data_root=data_root,
            payload=manifest,
        )
        auxiliary_path: Path | None = None
        if batch.target_kind is ShadowBatchTargetKind.REAL_SHADOW_30:
            auxiliary = build_shadow_review_auxiliary(manifest)
            auxiliary_path = persist_shadow_review_auxiliary(
                data_root=data_root,
                payload=auxiliary,
            )
    return {
        "canonical_sha256": manifest["canonical_sha256"],
        "human_truth_binding_sha256": (
            None if human_truth_binding is None else human_truth_binding.binding_sha256
        ),
        "item_count": manifest["item_count"],
        "machine_result": os.fspath(machine_path),
        "source_selection_sha256": (
            source_selection.canonical_sha256
        ),
        "shadow_review_auxiliary": (None if auxiliary_path is None else os.fspath(auxiliary_path)),
        "successful_runtime_observation_count": manifest["successful_runtime_observation_count"],
        "technical_failure_count": manifest["technical_failure_count"],
    }


def _evaluate(arguments: argparse.Namespace) -> dict[str, object]:
    try:
        data_root = arguments.data_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9MachineResultError("formal data root is unavailable") from exc
    evidence = evaluate_sealed_machine_results(
        package_dir=arguments.package_dir,
        seal_path=arguments.seal,
        machine_result_path=arguments.machine_result,
    )
    review_kind = evidence.get("review_kind")
    locked_selection_path = arguments.locked_selection
    if review_kind == ShadowBatchTargetKind.CURRENT_LOCKED_50.value:
        if locked_selection_path is None:
            raise Loop9MachineResultError(
                "current locked evaluation requires --locked-selection"
            )
        locked_selection = _load_locked_selection(
            data_root=data_root,
            path=locked_selection_path,
        )
    elif review_kind == ShadowBatchTargetKind.REAL_SHADOW_30.value:
        if locked_selection_path is not None:
            raise Loop9MachineResultError(
                "--locked-selection is only valid for current_locked_50"
            )
        locked_selection = None
    else:
        raise Loop9MachineResultError(
            "machine truth evaluation target is invalid"
        )
    output = persist_machine_truth_evaluation(
        data_root=data_root,
        payload=evidence,
    )
    gate_sha256: str | None = None
    if (
        locked_selection is not None
        and evidence.get("gate_passed") is True
    ):
        try:
            selected_contract = load_selected_live_read_contract(
                data_root
            )
            gate = CurrentLockedGateAuthorityStore(data_root).publish(
                locked_selection=locked_selection,
                package_dir=arguments.package_dir,
                seal_path=arguments.seal,
                evaluation_path=output,
                expected_current_build_sha256=(
                    current_loop9_build_sha256(ROOT)
                ),
                expected_settlement_contract_sha256=(
                    selected_contract.manifest.canonical_sha256
                ),
            )
        except (
            LiveContractSelectionError,
            Loop9CurrentLockedGateError,
        ) as exc:
            raise Loop9MachineResultError(
                "current locked Gate could not be published"
            ) from exc
        gate_sha256 = gate.canonical_sha256
    return {
        "canonical_sha256": evidence["canonical_sha256"],
        "current_locked_gate_sha256": gate_sha256,
        "gate_passed": evidence["gate_passed"],
        "output": os.fspath(output),
        "review_kind": review_kind,
    }


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    result = _run(arguments) if arguments.command == "run" else _evaluate(arguments)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
