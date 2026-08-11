from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from dahe import __version__
from dahe.adapters.chengfeng.daily_contract_selection import (
    DailyContractSelectionError,
    SelectedDailyReadContract,
    load_selected_daily_read_contract,
)
from dahe.adapters.chengfeng.live_contract_selection import (
    LiveContractSelectionError,
    load_selected_live_read_contract,
)
from dahe.adapters.chengfeng.live_contract_validation import (
    LiveContractValidationError,
)
from dahe.adapters.chengfeng.live_contract_validation import (
    _load_result as _load_live_validation_result,
)
from dahe.adapters.files.shadow_batch_manifest import (
    ShadowBatchManifestStore,
    ShadowBatchManifestStoreError,
)
from dahe.adapters.files.shadow_selection_manifest import (
    FormalShadowSelectionStore,
    FormalShadowSelectionStoreError,
)
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.identity_authority import (
    load_loop9_identity_authority,
    load_or_create_loop9_identity_authority,
)
from dahe.application.chengfeng.shadow_batch import (
    ChengfengShadowBatchManifest,
    ShadowBatchTargetKind,
)
from dahe.application.chengfeng.shadow_selection import (
    FormalShadowSelectionManifest,
)
from dahe.application.template_studio.fingerprints import (
    current_template_pipeline_build_fingerprint,
)
from dahe.application.template_studio.formal_development_authority import (
    load_formal_development_authority,
)
from dahe.verification.daily_snapshot_validation import (
    DailyContractSelectionBinding,
)
from dahe.verification.loop9_build import current_loop9_build_sha256
from dahe.verification.loop9_dataset_artifacts import (
    CURRENT_DAILY_DATASET_ID,
    Loop9DailyTripletInventory,
    Loop9DatasetArtifactError,
    build_daily_triplet_inventory,
    build_discovery_dataset_manifest,
    build_formal_dataset_manifest,
    build_legacy_loop7_exclusion_inventory,
    merge_loop9_exclusion_inventories,
    rebuild_current_daily_dataset_artifacts_from_store,
)
from dahe.verification.loop9_dataset_isolation import (
    ExclusionKind,
    load_loop9_exclusion_inventory,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (
    ROOT / ".venv" / "Scripts" / "python.exe"
).resolve()
_MAX_JSON_BYTES = 10 * 1024 * 1024
_IDENTITY_NAMESPACE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")
_WINDOWS_ALLOWED_PRIVILEGED_SIDS = {
    "S-1-5-18",  # LocalSystem
    "S-1-5-32-544",  # Built-in Administrators
}


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return Path(os.path.abspath(os.fspath(path)))


def _dataset_id(value: str) -> str:
    if (
        not value
        or value != value.strip()
        or len(value) > 100
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("dataset identity is invalid")
    return value


def _identity_namespace(value: str) -> str:
    if _IDENTITY_NAMESPACE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("identity namespace is invalid")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build strict, replayable Loop 9 dataset and exclusion artifacts "
            "without connecting to Chengfeng."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    discovery = commands.add_parser(
        "discovery",
        allow_abbrev=False,
        help="bind one sanitized development validation sample",
    )
    discovery.add_argument(
        "--validation-evidence",
        type=_absolute_path,
        required=True,
    )
    discovery.add_argument(
        "--development-inventory",
        type=_absolute_path,
        required=True,
    )
    discovery.add_argument("--dataset-id", type=_dataset_id, required=True)
    discovery.add_argument("--output", type=_absolute_path, required=True)

    formal = commands.add_parser(
        "formal",
        allow_abbrev=False,
        help="convert a sealed current_locked_50 or real_shadow_30 batch",
    )
    formal.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    formal.add_argument(
        "--shadow-batch",
        type=_absolute_path,
        required=True,
    )
    formal.add_argument(
        "--formal-selection",
        type=_absolute_path,
        required=True,
    )
    formal.add_argument("--dataset-id", type=_dataset_id, required=True)
    formal.add_argument("--output", type=_absolute_path, required=True)

    merge = commands.add_parser(
        "merge-exclusions",
        allow_abbrev=False,
        help="merge compatible immutable exclusion inventories",
    )
    merge.add_argument(
        "--kind",
        choices=tuple(kind.value for kind in ExclusionKind),
        required=True,
    )
    merge.add_argument(
        "--inventory",
        action="append",
        type=_absolute_path,
        required=True,
    )
    merge.add_argument("--inventory-id", type=_dataset_id, required=True)
    merge.add_argument("--output", type=_absolute_path, required=True)

    legacy_loop7 = commands.add_parser(
        "legacy-loop7-exclusions",
        allow_abbrev=False,
        help=(
            "convert the sealed Loop 7 development authority into one "
            "installation-bound immutable exclusion inventory"
        ),
    )
    legacy_loop7.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    legacy_loop7.add_argument(
        "--source-development-authority",
        type=_absolute_path,
        required=True,
    )
    legacy_loop7.add_argument(
        "--inventory-id",
        type=_dataset_id,
        required=True,
    )
    legacy_loop7.add_argument(
        "--output",
        type=_absolute_path,
        required=True,
    )

    daily_inventory = commands.add_parser(
        "daily-inventory",
        allow_abbrev=False,
        help=(
            "bind three verified daily snapshots to their immutable local "
            "identity and image observations"
        ),
    )
    daily_inventory.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    daily_inventory.add_argument(
        "--daily-validation",
        type=_absolute_path,
        required=True,
    )
    daily_inventory.add_argument(
        "--output",
        type=_absolute_path,
        required=True,
    )

    daily_manifest = commands.add_parser(
        "daily-manifest",
        allow_abbrev=False,
        help=(
            "rebuild a current daily dataset manifest from the formal data "
            "root and schema-v5 validation evidence"
        ),
    )
    daily_manifest.add_argument(
        "--data-root",
        type=_absolute_path,
        required=True,
    )
    daily_manifest.add_argument(
        "--daily-validation",
        type=_absolute_path,
        required=True,
    )
    daily_manifest.add_argument(
        "--dataset-id",
        type=_dataset_id,
        choices=(CURRENT_DAILY_DATASET_ID,),
        required=True,
    )
    daily_manifest.add_argument(
        "--output",
        type=_absolute_path,
        required=True,
    )
    return parser


def _load_json(path: Path, label: str) -> object:
    if not path.is_absolute() or path.is_symlink():
        raise Loop9DatasetArtifactError(f"{label} path is unsafe")
    try:
        resolved = path.resolve(strict=True)
        if (
            resolved != path
            or not resolved.is_file()
            or resolved.stat().st_size > _MAX_JSON_BYTES
        ):
            raise Loop9DatasetArtifactError(f"{label} file is invalid")
        content = resolved.read_bytes()
    except OSError as exc:
        raise Loop9DatasetArtifactError(
            f"{label} file is unavailable"
        ) from exc
    if not content:
        raise Loop9DatasetArtifactError(f"{label} file is empty")

    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise Loop9DatasetArtifactError(
                    f"{label} contains duplicate JSON fields"
                )
            result[key] = value
        return result

    try:
        return json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
        )
    except Loop9DatasetArtifactError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Loop9DatasetArtifactError(
            f"{label} file is not UTF-8 JSON"
        ) from exc


def _validated_output(output: Path) -> Path:
    if output.exists() or output.is_symlink():
        raise Loop9DatasetArtifactError("output already exists")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise Loop9DatasetArtifactError(
            "output parent is unavailable"
        ) from exc
    if (
        not parent.is_dir()
        or output.parent.is_symlink()
        or output.resolve(strict=False).parent != parent
    ):
        raise Loop9DatasetArtifactError("output path is unsafe")
    return output.resolve(strict=False)


def _write_exclusive_atomic(
    output: Path,
    payload: dict[str, object],
) -> None:
    target = _validated_output(output)
    parent = target.parent
    temporary = parent / f".{target.name}.{uuid4().hex}.tmp"
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    try:
        with temporary.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError as exc:
            raise Loop9DatasetArtifactError(
                "output already exists"
            ) from exc
        except OSError as exc:
            raise Loop9DatasetArtifactError(
                "output could not be published atomically"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _resolved_data_root(data_root: Path) -> Path:
    if not data_root.is_absolute() or data_root.is_symlink():
        raise Loop9DatasetArtifactError(
            "data root must be a real absolute directory"
        )
    try:
        root = data_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9DatasetArtifactError("data root is unavailable") from exc
    if root != data_root or not root.is_dir():
        raise Loop9DatasetArtifactError(
            "data root must be a real absolute directory"
        )
    return root


def _inside_root(path: Path, root: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise Loop9DatasetArtifactError(f"{label} path is unsafe")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise Loop9DatasetArtifactError(
            f"{label} must remain inside the DaHe data root"
        ) from exc
    if resolved != path or not resolved.is_file():
        raise Loop9DatasetArtifactError(f"{label} path is unsafe")
    current = resolved.parent
    while current != root:
        if current.is_symlink():
            raise Loop9DatasetArtifactError(f"{label} path is unsafe")
        current = current.parent
    return resolved


def _identity_key_acl_is_restricted(path: Path) -> bool:
    if os.name != "nt":
        try:
            return stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
        except OSError:
            return False
    script = r"""
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('DAHE_KEY_AUDIT_PATH')
$acl = Get-Acl -LiteralPath $path
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$owner = $acl.Owner
try {
  $owner = ([System.Security.Principal.NTAccount]$acl.Owner).Translate(
    [System.Security.Principal.SecurityIdentifier]
  ).Value
} catch {}
$access = @($acl.Access | ForEach-Object {
  $sid = $_.IdentityReference.Translate(
    [System.Security.Principal.SecurityIdentifier]
  ).Value
  [PSCustomObject]@{
    sid = $sid
    type = $_.AccessControlType.ToString()
  }
})
[PSCustomObject]@{
  current = $current
  owner = $owner
  access = $access
} | ConvertTo-Json -Compress -Depth 4
"""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    environment = dict(os.environ)
    environment["DAHE_KEY_AUDIT_PATH"] = os.fspath(path)
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
        if completed.returncode != 0:
            return False
        payload = json.loads(completed.stdout)
    except (
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ):
        return False
    if not isinstance(payload, dict):
        return False
    current_sid = payload.get("current")
    owner_sid = payload.get("owner")
    if not isinstance(current_sid, str):
        return False
    allowed = {
        current_sid,
        *_WINDOWS_ALLOWED_PRIVILEGED_SIDS,
    }
    if owner_sid not in allowed:
        return False
    access = payload.get("access")
    if not isinstance(access, list):
        return False
    for item in access:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("sid"), str)
            or not isinstance(item.get("type"), str)
        ):
            return False
        if item["type"] == "Allow" and item["sid"] not in allowed:
            return False
    return True


def _load_identity_key(
    *,
    data_root: Path,
    identity_key: Path,
) -> bytes:
    root = _resolved_data_root(data_root)
    key_path = _inside_root(
        identity_key,
        root,
        label="identity key",
    )
    try:
        before = key_path.stat()
    except OSError as exc:
        raise Loop9DatasetArtifactError(
            "identity key is unavailable"
        ) from exc
    if not 16 <= before.st_size <= 4096:
        raise Loop9DatasetArtifactError(
            "identity key size is invalid"
        )
    if not _identity_key_acl_is_restricted(key_path):
        raise Loop9DatasetArtifactError(
            "identity key permissions are too broad"
        )
    try:
        key = key_path.read_bytes()
        after = key_path.stat()
    except OSError as exc:
        raise Loop9DatasetArtifactError(
            "identity key is unavailable"
        ) from exc
    if (
        len(key) != before.st_size
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or after.st_ino != before.st_ino
    ):
        raise Loop9DatasetArtifactError(
            "identity key changed while it was being read"
        )
    return key


class _DataRootImageReader:
    def __init__(self, data_root: Path) -> None:
        evidence = data_root / "evidence"
        if evidence.is_symlink():
            raise Loop9DatasetArtifactError(
                "daily evidence root is unsafe"
            )
        try:
            self._root = evidence.resolve(strict=True)
        except OSError as exc:
            raise Loop9DatasetArtifactError(
                "daily evidence root is unavailable"
            ) from exc
        if not self._root.is_dir():
            raise Loop9DatasetArtifactError(
                "daily evidence root is unavailable"
            )

    def read_verified_image(self, image_sha256: str) -> bytes:
        target = (
            self._root
            / "sha256"
            / image_sha256[:2]
            / image_sha256[2:4]
            / f"{image_sha256}.blob"
        )
        if target.is_symlink():
            raise Loop9DatasetArtifactError(
                "daily ticket image path is unsafe"
            )
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(self._root)
        except (OSError, ValueError) as exc:
            raise Loop9DatasetArtifactError(
                "daily ticket image is unavailable"
            ) from exc
        if resolved != target or not resolved.is_file():
            raise Loop9DatasetArtifactError(
                "daily ticket image path is unsafe"
            )
        try:
            return resolved.read_bytes()
        except OSError as exc:
            raise Loop9DatasetArtifactError(
                "daily ticket image is unavailable"
            ) from exc


def _daily_selection_binding(
    selected: SelectedDailyReadContract,
) -> DailyContractSelectionBinding:
    return DailyContractSelectionBinding(
        contract_canonical_sha256=selected.manifest.canonical_sha256,
        contract_file_sha256=selected.contract_file_sha256,
        freeze_evidence_sha256=selected.freeze_evidence_sha256,
        selection_sha256=selected.selection_sha256,
        source_discovery_sha256=(
            selected.manifest.source_discovery_sha256
        ),
    )


def _build_daily_inventory_from_data_root(
    *,
    data_root: Path,
    daily_validation_path: Path,
    identity_salt: bytes,
    identity_namespace: str,
) -> Loop9DailyTripletInventory:
    validation_path = _inside_root(
        daily_validation_path,
        data_root,
        label="daily validation evidence",
    )
    validation = _load_json(
        validation_path,
        "daily validation evidence",
    )
    if not isinstance(validation, dict):
        raise Loop9DatasetArtifactError(
            "daily validation evidence must be an object"
        )
    try:
        contract_selection = _daily_selection_binding(
            load_selected_daily_read_contract(data_root)
        )
    except DailyContractSelectionError as exc:
        raise Loop9DatasetArtifactError(
            "selected daily contract evidence is unavailable"
        ) from exc
    snapshot_evidence = validation.get("snapshot_evidence")
    if not isinstance(snapshot_evidence, list) or len(snapshot_evidence) != 3:
        raise Loop9DatasetArtifactError(
            "daily validation evidence must bind three snapshots"
        )
    snapshot_ids: list[str] = []
    for item in snapshot_evidence:
        if not isinstance(item, dict) or not isinstance(
            item.get("snapshot_id"),
            str,
        ):
            raise Loop9DatasetArtifactError(
                "daily validation snapshot identity is invalid"
            )
        snapshot_ids.append(str(item["snapshot_id"]))
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=ROOT,
        instance_id=f"loop9-dataset-artifacts-{uuid4().hex}",
    )
    try:
        store = SqliteDailyStore(runtime)
        authorities = tuple(
            store.get_formal_snapshot_authority(snapshot_id)
            for snapshot_id in snapshot_ids
        )
        observations = {
            snapshot_id: store.list_snapshot_observations(snapshot_id)
            for snapshot_id in snapshot_ids
        }
        return build_daily_triplet_inventory(
            daily_validation=validation,
            contract_selection=contract_selection,
            authorities=authorities,
            observations_by_snapshot=observations,
            identity_salt=identity_salt,
            identity_namespace=identity_namespace,
            image_reader=_DataRootImageReader(data_root),
        )
    finally:
        runtime.close()


def _load_shadow_batch(path: Path) -> ChengfengShadowBatchManifest:
    if path.suffix != ".json" or re.fullmatch(
        r"[0-9a-f]{64}",
        path.stem,
    ) is None:
        raise Loop9DatasetArtifactError(
            "shadow batch manifest path is not content-addressed"
        )
    try:
        if path.resolve(strict=True) != path or path.is_symlink():
            raise Loop9DatasetArtifactError(
                "shadow batch manifest path is unsafe"
            )
        return ShadowBatchManifestStore(path.parent).load(path.stem)
    except Loop9DatasetArtifactError:
        raise
    except (OSError, ShadowBatchManifestStoreError) as exc:
        raise Loop9DatasetArtifactError(
            "shadow batch manifest is invalid"
        ) from exc


def _load_active_formal_selection(
    *,
    data_root: Path,
    path: Path,
    shadow_batch: ChengfengShadowBatchManifest,
) -> FormalShadowSelectionManifest:
    expected_root = data_root / "loop9-formal-selections"
    try:
        resolved = path.resolve(strict=True)
        expected_root = expected_root.resolve(strict=True)
    except OSError as exc:
        raise Loop9DatasetArtifactError(
            "formal selection manifest is unavailable"
        ) from exc
    if (
        path.is_symlink()
        or not resolved.is_file()
        or resolved.parent != expected_root
        or resolved.suffix != ".json"
        or re.fullmatch(r"[0-9a-f]{64}", resolved.stem) is None
    ):
        raise Loop9DatasetArtifactError(
            "formal selection must be a content-addressed DaHe manifest"
        )
    try:
        selected_contract = load_selected_live_read_contract(data_root)
        current_build = current_loop9_build_sha256(ROOT)
        store = FormalShadowSelectionStore(data_root)
        if (
            shadow_batch.target_kind
            is ShadowBatchTargetKind.CURRENT_LOCKED_50
        ):
            selection = store.load_active_current_locked_manifest(
                resolved.stem
            )
        else:
            selection = store.load_active_real_shadow_manifest(
                resolved.stem,
                expected_current_build_sha256=current_build,
                expected_settlement_contract_sha256=(
                    selected_contract.manifest.canonical_sha256
                ),
            )
    except (
        FormalShadowSelectionStoreError,
        LiveContractSelectionError,
    ) as exc:
        raise Loop9DatasetArtifactError(
            "active formal selection authority is invalid"
        ) from exc
    batch = selection.batch_manifest
    if (
        batch.to_payload() != shadow_batch.to_payload()
        or batch.source_build_sha256
        != current_build
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
        raise Loop9DatasetArtifactError(
            "formal selection does not match current authority"
        )
    return selection


def _load_sanitized_validation(path: Path) -> dict[str, object]:
    if not path.is_absolute() or path.is_symlink():
        raise Loop9DatasetArtifactError(
            "sanitized validation evidence path is unsafe"
        )
    try:
        _, document = _load_live_validation_result(path)
    except LiveContractValidationError as exc:
        raise Loop9DatasetArtifactError(
            "sanitized validation evidence is invalid"
        ) from exc
    return document


def _summary(
    *,
    artifact_kind: str,
    output: Path,
    canonical_sha256: str,
) -> None:
    print(
        json.dumps(
            {
                "artifact_kind": artifact_kind,
                "canonical_sha256": canonical_sha256,
                "output": output.name,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def main(argv: list[str] | None = None) -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    arguments = _parser().parse_args(argv)
    output = _validated_output(arguments.output)
    artifact_payload: dict[str, object]
    artifact_sha256: str

    if arguments.command == "discovery":
        discovery_manifest = build_discovery_dataset_manifest(
            dataset_id=arguments.dataset_id,
            validation_document=_load_sanitized_validation(
                arguments.validation_evidence
            ),
            development_inventory=load_loop9_exclusion_inventory(
                arguments.development_inventory
            ),
        )
        artifact_payload = discovery_manifest.to_payload()
        artifact_sha256 = discovery_manifest.canonical_sha256
    elif arguments.command == "formal":
        data_root = _resolved_data_root(arguments.data_root)
        shadow_batch = _load_shadow_batch(
            _inside_root(
                arguments.shadow_batch,
                data_root,
                label="shadow batch manifest",
            )
        )
        formal_manifest = build_formal_dataset_manifest(
            dataset_id=arguments.dataset_id,
            shadow_batch=shadow_batch,
            formal_selection=_load_active_formal_selection(
                data_root=data_root,
                path=arguments.formal_selection,
                shadow_batch=shadow_batch,
            ),
        )
        artifact_payload = formal_manifest.to_payload()
        artifact_sha256 = formal_manifest.canonical_sha256
    elif arguments.command == "merge-exclusions":
        exclusion_inventory = merge_loop9_exclusion_inventories(
            inventory_id=arguments.inventory_id,
            exclusion_kind=ExclusionKind(arguments.kind),
            inventories=tuple(
                load_loop9_exclusion_inventory(path)
                for path in arguments.inventory
            ),
        )
        artifact_payload = exclusion_inventory.to_payload()
        artifact_sha256 = exclusion_inventory.canonical_sha256
    elif arguments.command == "legacy-loop7-exclusions":
        data_root = _resolved_data_root(arguments.data_root)
        try:
            output.relative_to(data_root)
        except ValueError as exc:
            raise Loop9DatasetArtifactError(
                "legacy Loop 7 output must remain inside the DaHe data root"
            ) from exc
        identity_authority = load_loop9_identity_authority(data_root)
        exclusion_inventory = build_legacy_loop7_exclusion_inventory(
            inventory_id=arguments.inventory_id,
            source_authority=load_formal_development_authority(
                arguments.source_development_authority
            ),
            identity_context_sha256=(
                identity_authority.context_sha256
            ),
        )
        artifact_payload = exclusion_inventory.to_payload()
        artifact_sha256 = exclusion_inventory.canonical_sha256
    elif arguments.command == "daily-inventory":
        data_root = _resolved_data_root(arguments.data_root)
        try:
            output.relative_to(data_root)
        except ValueError as exc:
            raise Loop9DatasetArtifactError(
                "daily inventory output must remain inside the DaHe data root"
            ) from exc
        identity_authority = load_or_create_loop9_identity_authority(
            data_root
        )
        daily_inventory = _build_daily_inventory_from_data_root(
            data_root=data_root,
            daily_validation_path=arguments.daily_validation,
            identity_salt=identity_authority.salt,
            identity_namespace=identity_authority.namespace,
        )
        artifact_payload = daily_inventory.to_payload()
        artifact_sha256 = daily_inventory.canonical_sha256
    elif arguments.command == "daily-manifest":
        data_root = _resolved_data_root(arguments.data_root)
        try:
            output.relative_to(data_root)
        except ValueError as exc:
            raise Loop9DatasetArtifactError(
                "daily manifest output must remain inside the DaHe data root"
            ) from exc
        validation_path = _inside_root(
            arguments.daily_validation,
            data_root,
            label="daily validation evidence",
        )
        validation = _load_json(
            validation_path,
            "daily validation evidence",
        )
        rebuilt = rebuild_current_daily_dataset_artifacts_from_store(
            dataset_id=arguments.dataset_id,
            daily_validation=validation,
            data_root=data_root,
            project_root=ROOT,
            source_build_sha256=current_loop9_build_sha256(ROOT),
        )
        artifact_payload = rebuilt.manifest.to_payload()
        artifact_sha256 = rebuilt.manifest.canonical_sha256
    else:  # pragma: no cover - argparse makes this unreachable.
        raise Loop9DatasetArtifactError("unknown artifact command")

    _write_exclusive_atomic(output, artifact_payload)
    _summary(
        artifact_kind=arguments.command.removesuffix("-inventory"),
        output=output,
        canonical_sha256=artifact_sha256,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
