from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from dahe.application.chengfeng.shadow_batch import ShadowBatchTargetKind
from dahe.application.chengfeng.shadow_selection import (
    FormalSelectionExclusionSnapshot,
    FormalShadowSelectionContractError,
    FormalShadowSelectionManifest,
)
from dahe.application.chengfeng.shadow_selection_lifecycle import (
    FormalSelectionLifecycleContractError,
    FormalSelectionLifecycleEvent,
    FormalSelectionLifecycleNode,
    FormalSelectionLifecycleState,
)
from dahe.verification.image_similarity import (
    ImageSimilarityContractError,
    find_near_duplicate_candidates,
)
from dahe.verification.loop9_dataset_isolation import (
    Loop9DatasetExclusionInventory,
)
from dahe.verification.loop9_exclusion_authority import (
    Loop9VerifiedExclusionSnapshot,
)
from dahe.verification.loop9_locked_selection_rollover import (
    LockedSelectionCoverageFailureAttestation,
    Loop9LockedSelectionRolloverError,
    development_inventory_from_failed_locked_selection,
)

_ANCHOR_TABLE = "loop9_formal_selection_lifecycle_anchors"
_TARGET = ShadowBatchTargetKind.CURRENT_LOCKED_50
_MAX_JSON_BYTES = 20 * 1024 * 1024
_HEAD_SCHEMA_VERSION = 1
_ANCHOR_COLUMNS = (
    "target_kind",
    "sequence",
    "generation",
    "event_kind",
    "node_sha256",
    "previous_head_sha256",
    "selection_sha256",
    "predecessor_selection_sha256",
    "failure_attestation_sha256",
    "exclusion_inventory_sha256",
    "exclusion_authority_sha256",
    "exclusion_child_head_sha256",
    "source_build_sha256",
    "pipeline_fingerprint",
    "identity_context_sha256",
    "created_at",
)


class FormalSelectionLifecycleStoreError(RuntimeError):
    """Raised when formal selection lifecycle evidence is unsafe."""


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(
        attributes
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (_canonical_json(value) + "\n").encode("utf-8")


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle JSON contains duplicate keys"
            )
        result[key] = value
    return result


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )


def _safe_data_root(data_root: Path) -> Path:
    if not isinstance(data_root, Path) or not data_root.is_absolute():
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle data root must be absolute"
        )
    try:
        root = data_root.resolve(strict=True)
    except OSError as exc:
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle data root is unavailable"
        ) from exc
    if (
        root != data_root
        or data_root.is_symlink()
        or _is_reparse_point(data_root)
        or not root.is_dir()
    ):
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle data root is unsafe"
        )
    return root


def _ensure_directory(path: Path, *, root: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle store is unavailable"
        ) from exc
    if (
        resolved != path
        or path.is_symlink()
        or _is_reparse_point(path)
        or not resolved.is_dir()
    ):
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle store is unsafe"
        )


def _read_json(path: Path, *, label: str) -> dict[str, object]:
    if (
        not path.is_file()
        or path.is_symlink()
        or _is_reparse_point(path)
    ):
        raise FormalSelectionLifecycleStoreError(f"{label} is missing")
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise FormalSelectionLifecycleStoreError(
            f"{label} is unavailable"
        ) from exc
    if not content or len(content) > _MAX_JSON_BYTES:
        raise FormalSelectionLifecycleStoreError(f"{label} is invalid")
    try:
        value = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except FormalSelectionLifecycleStoreError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormalSelectionLifecycleStoreError(
            f"{label} is invalid"
        ) from exc
    if not isinstance(value, dict):
        raise FormalSelectionLifecycleStoreError(
            f"{label} must be an object"
        )
    return cast(dict[str, object], value)


def _write_once(path: Path, payload: object) -> None:
    content = _json_bytes(payload)
    if path.exists():
        if (
            not path.is_file()
            or path.is_symlink()
            or path.read_bytes() != content
        ):
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle immutable artifact conflicts"
            )
        return
    staging = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        with staging.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staging, path)
        except FileExistsError:
            if path.read_bytes() != content:
                raise FormalSelectionLifecycleStoreError(
                    "formal selection lifecycle immutable artifact conflicts"
                ) from None
        except OSError as exc:
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle artifact could not be published"
            ) from exc
    finally:
        staging.unlink(missing_ok=True)


def _replace_atomic(path: Path, payload: object) -> None:
    content = _json_bytes(payload)
    staging = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        with staging.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging, path)
    except OSError as exc:
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle head could not be published"
        ) from exc
    finally:
        staging.unlink(missing_ok=True)


def _node_from_row(row: sqlite3.Row) -> FormalSelectionLifecycleNode:
    try:
        node = FormalSelectionLifecycleNode(
            target_kind=ShadowBatchTargetKind(str(row["target_kind"])),
            sequence=int(row["sequence"]),
            generation=int(row["generation"]),
            event_kind=FormalSelectionLifecycleEvent(
                str(row["event_kind"])
            ),
            previous_head_sha256=(
                None
                if row["previous_head_sha256"] is None
                else str(row["previous_head_sha256"])
            ),
            selection_sha256=str(row["selection_sha256"]),
            predecessor_selection_sha256=(
                None
                if row["predecessor_selection_sha256"] is None
                else str(row["predecessor_selection_sha256"])
            ),
            failure_attestation_sha256=(
                None
                if row["failure_attestation_sha256"] is None
                else str(row["failure_attestation_sha256"])
            ),
            exclusion_inventory_sha256=(
                None
                if row["exclusion_inventory_sha256"] is None
                else str(row["exclusion_inventory_sha256"])
            ),
            exclusion_authority_sha256=str(
                row["exclusion_authority_sha256"]
            ),
            exclusion_child_head_sha256=str(
                row["exclusion_child_head_sha256"]
            ),
            source_build_sha256=str(row["source_build_sha256"]),
            pipeline_fingerprint=str(row["pipeline_fingerprint"]),
            identity_context_sha256=str(row["identity_context_sha256"]),
            created_at=str(row["created_at"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle SQLite anchor is invalid"
        ) from exc
    if node.canonical_sha256 != str(row["node_sha256"]):
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle SQLite anchor is inconsistent"
        )
    return node


def _validate_chain(
    nodes: Sequence[FormalSelectionLifecycleNode],
) -> None:
    if not nodes:
        return
    for index, node in enumerate(nodes):
        node.verify_integrity()
        if node.sequence != index + 1:
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle sequence is incomplete"
            )
        if index == 0:
            continue
        previous = nodes[index - 1]
        if node.previous_head_sha256 != previous.canonical_sha256:
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle fork is not allowed"
            )
        if previous.event_kind is FormalSelectionLifecycleEvent.ACTIVATED:
            if (
                node.event_kind
                is not FormalSelectionLifecycleEvent.INVALIDATED
                or node.generation != previous.generation
                or node.selection_sha256 != previous.selection_sha256
            ):
                raise FormalSelectionLifecycleStoreError(
                    "formal selection lifecycle event order is invalid"
                )
        elif (
            node.event_kind
            is not FormalSelectionLifecycleEvent.ACTIVATED
            or node.generation != previous.generation + 1
            or node.predecessor_selection_sha256
            != previous.selection_sha256
        ):
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle event order is invalid"
            )
        if (
            node.source_build_sha256 != previous.source_build_sha256
            or node.pipeline_fingerprint != previous.pipeline_fingerprint
            or node.identity_context_sha256
            != previous.identity_context_sha256
        ):
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle execution authority changed"
            )


def _head_payload(node: FormalSelectionLifecycleNode) -> dict[str, object]:
    body: dict[str, object] = {
        "active_selection_sha256": (
            node.selection_sha256
            if node.event_kind is FormalSelectionLifecycleEvent.ACTIVATED
            else None
        ),
        "event_kind": node.event_kind.value,
        "generation": node.generation,
        "head_sha256": node.canonical_sha256,
        "kind": "loop9_formal_selection_lifecycle_head",
        "schema_version": _HEAD_SCHEMA_VERSION,
        "sequence": node.sequence,
        "target_kind": node.target_kind.value,
    }
    return {**body, "canonical_sha256": _canonical_sha256(body)}


def _state_from_head(
    value: dict[str, object],
) -> FormalSelectionLifecycleState:
    expected = {
        "active_selection_sha256",
        "canonical_sha256",
        "event_kind",
        "generation",
        "head_sha256",
        "kind",
        "schema_version",
        "sequence",
        "target_kind",
    }
    body = {
        key: nested
        for key, nested in value.items()
        if key != "canonical_sha256"
    }
    if (
        set(value) != expected
        or value.get("kind")
        != "loop9_formal_selection_lifecycle_head"
        or value.get("schema_version") != _HEAD_SCHEMA_VERSION
        or value.get("target_kind") != _TARGET.value
        or value.get("canonical_sha256") != _canonical_sha256(body)
    ):
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle head integrity is invalid"
        )
    try:
        event = FormalSelectionLifecycleEvent(
            cast(str, value["event_kind"])
        )
        active = cast(str | None, value["active_selection_sha256"])
        state = FormalSelectionLifecycleState(
            target_kind=_TARGET,
            sequence=cast(int, value["sequence"]),
            generation=cast(int, value["generation"]),
            event_kind=event,
            head_sha256=cast(str, value["head_sha256"]),
            active_selection_sha256=active,
            canonical_sha256=cast(str, value["canonical_sha256"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle head integrity is invalid"
        ) from exc
    if (
        type(state.sequence) is not int
        or state.sequence < 1
        or type(state.generation) is not int
        or state.generation < 1
        or (
            event is FormalSelectionLifecycleEvent.ACTIVATED
            and active is None
        )
        or (
            event is FormalSelectionLifecycleEvent.INVALIDATED
            and active is not None
        )
    ):
        raise FormalSelectionLifecycleStoreError(
            "formal selection lifecycle head integrity is invalid"
        )
    return state


class FormalSelectionLifecycleStore:
    """Keep immutable locked-set generations anchored in SQLite and files."""

    def __init__(
        self,
        data_root: Path,
        *,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.data_root = _safe_data_root(data_root)
        self.root = (
            self.data_root
            / "loop9-formal-selections"
            / "lifecycle"
            / _TARGET.value
        )
        self.nodes_root = self.root / "nodes"
        self.head_path = self.root / "head.json"
        self._fault_injector = fault_injector

    def _prepare(self, *, create: bool) -> None:
        if create:
            _ensure_directory(self.root, root=self.data_root)
            _ensure_directory(self.nodes_root, root=self.data_root)
            return
        if (
            not self.root.is_dir()
            or self.root.is_symlink()
            or _is_reparse_point(self.root)
            or self.root.resolve() != self.root
            or not self.nodes_root.is_dir()
            or self.nodes_root.is_symlink()
            or _is_reparse_point(self.nodes_root)
            or self.nodes_root.resolve() != self.nodes_root
        ):
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle store is missing or unsafe"
            )

    @contextmanager
    def _connection(
        self,
        *,
        write: bool,
    ) -> Iterator[sqlite3.Connection]:
        database = self.data_root / "database" / "dahe.sqlite3"
        try:
            resolved = database.resolve(strict=True)
            resolved.relative_to(self.data_root)
            if (
                database.is_symlink()
                or _is_reparse_point(database)
                or not resolved.is_file()
            ):
                raise OSError
            connection = sqlite3.connect(
                f"{resolved.as_uri()}?mode={'rw' if write else 'ro'}",
                uri=True,
                timeout=5.0,
            )
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle SQLite anchor is unavailable"
            ) from exc
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            if not write:
                connection.execute("PRAGMA query_only=ON")
            table = connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = ?",
                (_ANCHOR_TABLE,),
            ).fetchone()
            if table is None:
                raise FormalSelectionLifecycleStoreError(
                    "formal selection lifecycle SQLite schema is missing"
                )
            yield connection
        except sqlite3.Error as exc:
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle SQLite anchor is invalid"
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _anchor_nodes(
        connection: sqlite3.Connection,
    ) -> tuple[FormalSelectionLifecycleNode, ...]:
        columns = ", ".join(_ANCHOR_COLUMNS)
        rows = connection.execute(
            f"SELECT {columns} FROM {_ANCHOR_TABLE} "
            "WHERE target_kind = ? ORDER BY sequence",
            (_TARGET.value,),
        ).fetchall()
        nodes = tuple(_node_from_row(row) for row in rows)
        _validate_chain(nodes)
        return nodes

    def _file_nodes(self) -> dict[str, FormalSelectionLifecycleNode]:
        if not self.nodes_root.exists():
            return {}
        paths = tuple(sorted(self.nodes_root.glob("*.json")))
        if any(
            path.is_symlink() or _is_reparse_point(path)
            for path in paths
        ):
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle node path is unsafe"
            )
        nodes: dict[str, FormalSelectionLifecycleNode] = {}
        for path in paths:
            try:
                node = FormalSelectionLifecycleNode.from_payload(
                    _read_json(
                        path,
                        label="formal selection lifecycle node",
                    )
                )
            except FormalSelectionLifecycleContractError as exc:
                raise FormalSelectionLifecycleStoreError(
                    "formal selection lifecycle node integrity is invalid"
                ) from exc
            if (
                path.name != f"{node.canonical_sha256}.json"
                or node.canonical_sha256 in nodes
            ):
                raise FormalSelectionLifecycleStoreError(
                    "formal selection lifecycle node path integrity is invalid"
                )
            nodes[node.canonical_sha256] = node
        return nodes

    def _strict_state(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[
        FormalSelectionLifecycleState | None,
        tuple[FormalSelectionLifecycleNode, ...],
    ]:
        anchors = self._anchor_nodes(connection)
        files = self._file_nodes()
        if not anchors:
            if files or self.head_path.exists():
                raise FormalSelectionLifecycleStoreError(
                    "formal selection lifecycle file and SQLite chains differ"
                )
            return None, ()
        if set(files) != {
            node.canonical_sha256 for node in anchors
        } or any(
            files[node.canonical_sha256].to_payload()
            != node.to_payload()
            for node in anchors
        ):
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle file and SQLite chains differ"
            )
        state = _state_from_head(
            _read_json(
                self.head_path,
                label="formal selection lifecycle head",
            )
        )
        tip = anchors[-1]
        if (
            state.head_sha256 != tip.canonical_sha256
            or state.sequence != tip.sequence
            or state.generation != tip.generation
            or state.event_kind is not tip.event_kind
            or state.active_selection_sha256
            != (
                tip.selection_sha256
                if tip.event_kind
                is FormalSelectionLifecycleEvent.ACTIVATED
                else None
            )
        ):
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle head is not the chain tip"
            )
        return state, anchors

    def load_state(self) -> FormalSelectionLifecycleState | None:
        if not self.root.exists():
            with self._connection(write=False) as connection:
                if self._anchor_nodes(connection):
                    raise FormalSelectionLifecycleStoreError(
                        "formal selection lifecycle file chain is missing"
                    )
            return None
        self._prepare(create=False)
        with self._connection(write=False) as connection:
            state, _ = self._strict_state(connection)
            return state

    def load_tip(self) -> FormalSelectionLifecycleNode | None:
        """Load the exact append-only tip after file/SQLite reconciliation."""

        if not self.root.exists():
            with self._connection(write=False) as connection:
                if self._anchor_nodes(connection):
                    raise FormalSelectionLifecycleStoreError(
                        "formal selection lifecycle file chain is missing"
                    )
            return None
        self._prepare(create=False)
        with self._connection(write=False) as connection:
            _, nodes = self._strict_state(connection)
        return None if not nodes else nodes[-1]

    def require_active_selection(
        self,
        canonical_sha256: str,
    ) -> FormalSelectionLifecycleNode:
        """Fail closed unless this exact selection is the reconciled active tip."""

        tip = self.load_tip()
        if (
            tip is None
            or tip.event_kind is not FormalSelectionLifecycleEvent.ACTIVATED
            or tip.selection_sha256 != canonical_sha256
        ):
            raise FormalSelectionLifecycleStoreError(
                "formal locked selection is not the active lifecycle generation"
            )
        return tip

    def _anchored_nodes_for_retry(
        self,
    ) -> tuple[FormalSelectionLifecycleNode, ...]:
        """Read the durable chain while allowing one interrupted file append."""

        self._prepare(create=True)
        with self._connection(write=False) as connection:
            anchors = self._anchor_nodes(connection)
        files = self._file_nodes()
        anchored_sha256s = {
            node.canonical_sha256 for node in anchors
        }
        if any(
            files.get(node.canonical_sha256) is None
            or files[node.canonical_sha256].to_payload()
            != node.to_payload()
            for node in anchors
        ):
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle file and SQLite chains differ"
            )
        unanchored = tuple(
            node
            for digest, node in files.items()
            if digest not in anchored_sha256s
        )
        if len(unanchored) > 1:
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle contains an unsafe fork"
            )
        if unanchored:
            staged = unanchored[0]
            expected_previous = (
                None if not anchors else anchors[-1].canonical_sha256
            )
            if (
                staged.sequence != len(anchors) + 1
                or staged.previous_head_sha256 != expected_previous
            ):
                raise FormalSelectionLifecycleStoreError(
                    "formal selection lifecycle contains an unsafe staged node"
                )
            _validate_chain((*anchors, staged))
        return anchors

    def _append(
        self,
        *,
        desired: FormalSelectionLifecycleNode,
        matches: Callable[[FormalSelectionLifecycleNode], bool],
    ) -> FormalSelectionLifecycleNode:
        self._prepare(create=True)
        with self._connection(write=True) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                anchors = self._anchor_nodes(connection)
                files = self._file_nodes()
                anchored_sha256s = {
                    node.canonical_sha256 for node in anchors
                }
                for node in anchors:
                    file_node = files.get(node.canonical_sha256)
                    if (
                        file_node is None
                        or file_node.to_payload() != node.to_payload()
                    ):
                        raise FormalSelectionLifecycleStoreError(
                            "formal selection lifecycle file and SQLite chains differ"
                        )
                unanchored = tuple(
                    node
                    for digest, node in files.items()
                    if digest not in anchored_sha256s
                )
                if len(unanchored) > 1:
                    raise FormalSelectionLifecycleStoreError(
                        "formal selection lifecycle contains an unsafe fork"
                    )
                if (
                    desired.sequence == 1
                    and anchors
                    and matches(anchors[0])
                ):
                    connection.commit()
                    _replace_atomic(
                        self.head_path,
                        _head_payload(anchors[-1]),
                    )
                    return anchors[0]
                if anchors and matches(anchors[-1]):
                    node = anchors[-1]
                    connection.commit()
                    _replace_atomic(self.head_path, _head_payload(node))
                    return node
                candidate = desired
                if unanchored:
                    staged = unanchored[0]
                    if not matches(staged):
                        raise FormalSelectionLifecycleStoreError(
                            "formal selection lifecycle contains an unsafe staged node"
                        )
                    candidate = staged
                expected_previous = (
                    None if not anchors else anchors[-1].canonical_sha256
                )
                if (
                    candidate.sequence != len(anchors) + 1
                    or candidate.previous_head_sha256
                    != expected_previous
                ):
                    raise FormalSelectionLifecycleStoreError(
                        "formal selection lifecycle append is stale"
                    )
                prospective = (*anchors, candidate)
                _validate_chain(prospective)
                _write_once(
                    self.nodes_root
                    / f"{candidate.canonical_sha256}.json",
                    candidate.to_payload(),
                )
                if self._fault_injector is not None:
                    self._fault_injector("after_node_write")
                placeholders = ", ".join("?" for _ in _ANCHOR_COLUMNS)
                columns = ", ".join(_ANCHOR_COLUMNS)
                values = (
                    candidate.target_kind.value,
                    candidate.sequence,
                    candidate.generation,
                    candidate.event_kind.value,
                    candidate.canonical_sha256,
                    candidate.previous_head_sha256,
                    candidate.selection_sha256,
                    candidate.predecessor_selection_sha256,
                    candidate.failure_attestation_sha256,
                    candidate.exclusion_inventory_sha256,
                    candidate.exclusion_authority_sha256,
                    candidate.exclusion_child_head_sha256,
                    candidate.source_build_sha256,
                    candidate.pipeline_fingerprint,
                    candidate.identity_context_sha256,
                    candidate.created_at,
                )
                connection.execute(
                    f"INSERT INTO {_ANCHOR_TABLE} ({columns}) "
                    f"VALUES ({placeholders})",
                    values,
                )
                connection.commit()
                if self._fault_injector is not None:
                    self._fault_injector("after_anchor_commit")
                _replace_atomic(
                    self.head_path,
                    _head_payload(candidate),
                )
                return candidate
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise

    def bootstrap_current_locked_selection(
        self,
        selection: FormalShadowSelectionManifest,
    ) -> FormalSelectionLifecycleNode:
        try:
            selection.verify_integrity()
        except FormalShadowSelectionContractError as exc:
            raise FormalSelectionLifecycleStoreError(
                "formal locked selection integrity is invalid"
            ) from exc
        if selection.target_kind is not _TARGET:
            raise FormalSelectionLifecycleStoreError(
                "only current_locked_50 can enter this lifecycle"
            )
        batch = selection.batch_manifest
        desired = FormalSelectionLifecycleNode(
            target_kind=_TARGET,
            sequence=1,
            generation=1,
            event_kind=FormalSelectionLifecycleEvent.ACTIVATED,
            previous_head_sha256=None,
            selection_sha256=selection.canonical_sha256,
            predecessor_selection_sha256=None,
            failure_attestation_sha256=None,
            exclusion_inventory_sha256=None,
            exclusion_authority_sha256=(
                selection.full_history_exclusion_authority_sha256
            ),
            exclusion_child_head_sha256=(
                selection.exclusion_child_index_head_sha256
            ),
            source_build_sha256=batch.source_build_sha256,
            pipeline_fingerprint=batch.pipeline_fingerprint,
            identity_context_sha256=batch.identity_context_sha256,
            created_at=_utc_now(),
        )
        return self._append(
            desired=desired,
            matches=lambda node: (
                node.sequence == 1
                and node.event_kind
                is FormalSelectionLifecycleEvent.ACTIVATED
                and node.selection_sha256 == selection.canonical_sha256
            ),
        )

    @staticmethod
    def _verify_exclusion_coverage(
        *,
        selection: FormalShadowSelectionManifest,
        inventory: Loop9DatasetExclusionInventory,
        snapshot: Loop9VerifiedExclusionSnapshot,
    ) -> None:
        platform = {
            item.platform_waybill_id_digest
            for item in selection.batch_manifest.items
        }
        images = {
            image.sha256
            for item in selection.batch_manifest.items
            for image in item.images
        }
        fingerprints = {
            image.sha256: image.perceptual_fingerprint.to_record()
            for item in selection.batch_manifest.items
            for image in item.images
        }
        inventory_fingerprints = {
            value.content_sha256: value.to_record()
            for value in inventory.perceptual_fingerprints
        }
        snapshot_fingerprints = {
            value.content_sha256: value.to_record()
            for value in snapshot.excluded_perceptual_fingerprints
        }
        if (
            set(inventory.platform_identity_sha256s) != platform
            or set(inventory.image_sha256s) != images
            or inventory_fingerprints != fingerprints
            or inventory.scope_exclusion_tokens
            or inventory.identity_context_sha256
            != selection.batch_manifest.identity_context_sha256
            or not platform.issubset(
                snapshot.excluded_platform_identity_sha256s
            )
            or not images.issubset(snapshot.excluded_image_sha256s)
            or any(
                snapshot_fingerprints.get(digest) != fingerprint
                for digest, fingerprint in fingerprints.items()
            )
            or snapshot.identity_context_sha256
            != selection.batch_manifest.identity_context_sha256
            or snapshot.expected_current_build_sha256
            != selection.batch_manifest.source_build_sha256
            or snapshot.expected_settlement_contract_sha256
            != selection.batch_manifest.contract_canonical_sha256
            or snapshot.expected_settlement_selection_sha256
            != selection.batch_manifest.contract_selection_sha256
        ):
            raise FormalSelectionLifecycleStoreError(
                "verified exclusion authority does not cover the failed selection"
            )

    def invalidate_current_locked_selection(
        self,
        *,
        selection: FormalShadowSelectionManifest,
        failure_attestation: LockedSelectionCoverageFailureAttestation,
        exclusion_inventory: Loop9DatasetExclusionInventory,
        exclusion_snapshot: Loop9VerifiedExclusionSnapshot,
    ) -> FormalSelectionLifecycleNode:
        try:
            failure_attestation.verify_integrity()
            failure_attestation.verify_selection(selection)
            expected_inventory = (
                development_inventory_from_failed_locked_selection(
                    selection=selection,
                    failure_attestation=failure_attestation,
                )
            )
        except Loop9LockedSelectionRolloverError as exc:
            raise FormalSelectionLifecycleStoreError(str(exc)) from exc
        if (
            expected_inventory.canonical_sha256
            != exclusion_inventory.canonical_sha256
        ):
            raise FormalSelectionLifecycleStoreError(
                "failed selection exclusion inventory does not match"
            )
        self._verify_exclusion_coverage(
            selection=selection,
            inventory=exclusion_inventory,
            snapshot=exclusion_snapshot,
        )
        nodes = self._anchored_nodes_for_retry()
        if not nodes:
            raise FormalSelectionLifecycleStoreError(
                "formal selection lifecycle is unavailable"
            )
        tip = nodes[-1]
        if tip.event_kind is FormalSelectionLifecycleEvent.INVALIDATED:
            if (
                tip.selection_sha256 == selection.canonical_sha256
                and tip.failure_attestation_sha256
                == failure_attestation.canonical_sha256
                and tip.exclusion_inventory_sha256
                == exclusion_inventory.canonical_sha256
                and tip.exclusion_authority_sha256
                == exclusion_snapshot.authority_sha256
                and tip.exclusion_child_head_sha256
                == exclusion_snapshot.child_index_head_sha256
            ):
                return self._append(
                    desired=tip,
                    matches=lambda node: (
                        node.canonical_sha256 == tip.canonical_sha256
                    ),
                )
            raise FormalSelectionLifecycleStoreError(
                "formal selection is already invalidated by different evidence"
            )
        if tip.selection_sha256 != selection.canonical_sha256:
            raise FormalSelectionLifecycleStoreError(
                "active formal selection belongs to another generation"
            )
        desired = FormalSelectionLifecycleNode(
            target_kind=_TARGET,
            sequence=tip.sequence + 1,
            generation=tip.generation,
            event_kind=FormalSelectionLifecycleEvent.INVALIDATED,
            previous_head_sha256=tip.canonical_sha256,
            selection_sha256=selection.canonical_sha256,
            predecessor_selection_sha256=None,
            failure_attestation_sha256=(
                failure_attestation.canonical_sha256
            ),
            exclusion_inventory_sha256=(
                exclusion_inventory.canonical_sha256
            ),
            exclusion_authority_sha256=exclusion_snapshot.authority_sha256,
            exclusion_child_head_sha256=(
                exclusion_snapshot.child_index_head_sha256
            ),
            source_build_sha256=(
                selection.batch_manifest.source_build_sha256
            ),
            pipeline_fingerprint=(
                selection.batch_manifest.pipeline_fingerprint
            ),
            identity_context_sha256=(
                selection.batch_manifest.identity_context_sha256
            ),
            created_at=_utc_now(),
        )
        return self._append(
            desired=desired,
            matches=lambda node: (
                node.event_kind
                is FormalSelectionLifecycleEvent.INVALIDATED
                and node.selection_sha256 == selection.canonical_sha256
                and node.failure_attestation_sha256
                == failure_attestation.canonical_sha256
                and node.exclusion_inventory_sha256
                == exclusion_inventory.canonical_sha256
                and node.exclusion_authority_sha256
                == exclusion_snapshot.authority_sha256
                and node.exclusion_child_head_sha256
                == exclusion_snapshot.child_index_head_sha256
            ),
        )

    def activate_replacement(
        self,
        *,
        selection: FormalShadowSelectionManifest,
        exclusion_snapshot: (
            Loop9VerifiedExclusionSnapshot
            | FormalSelectionExclusionSnapshot
        ),
    ) -> FormalSelectionLifecycleNode:
        try:
            selection.verify_integrity()
        except FormalShadowSelectionContractError as exc:
            raise FormalSelectionLifecycleStoreError(
                "replacement formal selection integrity is invalid"
            ) from exc
        nodes = self._anchored_nodes_for_retry()
        if not nodes:
            raise FormalSelectionLifecycleStoreError(
                "replacement requires an invalidated locked selection"
            )
        invalidated = nodes[-1]
        if invalidated.event_kind is FormalSelectionLifecycleEvent.ACTIVATED:
            if (
                invalidated.generation > 1
                and invalidated.selection_sha256
                == selection.canonical_sha256
                and invalidated.exclusion_authority_sha256
                == exclusion_snapshot.authority_sha256
                and invalidated.exclusion_child_head_sha256
                == exclusion_snapshot.child_index_head_sha256
            ):
                return self._append(
                    desired=invalidated,
                    matches=lambda node: (
                        node.canonical_sha256
                        == invalidated.canonical_sha256
                    ),
                )
            raise FormalSelectionLifecycleStoreError(
                "replacement requires an invalidated locked selection"
            )
        if len(nodes) < 2:
            raise FormalSelectionLifecycleStoreError(
                "replacement lifecycle predecessor is unavailable"
            )
        prior_activation = nodes[-2]
        if (
            selection.target_kind is not _TARGET
            or selection.full_history_exclusion_authority_sha256
            != exclusion_snapshot.authority_sha256
            or selection.exclusion_child_index_head_sha256
            != exclusion_snapshot.child_index_head_sha256
            or selection.batch_manifest.source_build_sha256
            != invalidated.source_build_sha256
            or selection.batch_manifest.pipeline_fingerprint
            != invalidated.pipeline_fingerprint
            or selection.batch_manifest.identity_context_sha256
            != invalidated.identity_context_sha256
        ):
            raise FormalSelectionLifecycleStoreError(
                "replacement selection authority does not match the lifecycle"
            )
        old_selection_sha = invalidated.selection_sha256
        if prior_activation.selection_sha256 != old_selection_sha:
            raise FormalSelectionLifecycleStoreError(
                "invalidated lifecycle selection is inconsistent"
            )
        # The full old manifest is verified by the caller/store integration.
        # The snapshot binding proves its exact identities and perceptual
        # fingerprints were committed before the replacement was selected.
        if (
            invalidated.exclusion_authority_sha256
            != exclusion_snapshot.authority_sha256
            or invalidated.exclusion_child_head_sha256
            != exclusion_snapshot.child_index_head_sha256
        ):
            raise FormalSelectionLifecycleStoreError(
                "replacement exclusion authority is stale"
            )
        replacement_images = {
            image.sha256
            for item in selection.batch_manifest.items
            for image in item.images
        }
        replacement_platform = {
            item.platform_waybill_id_digest
            for item in selection.batch_manifest.items
        }
        if replacement_images.intersection(
            exclusion_snapshot.excluded_image_sha256s
        ) or replacement_platform.intersection(
            exclusion_snapshot.excluded_platform_identity_sha256s
        ):
            raise FormalSelectionLifecycleStoreError(
                "replacement selection overlaps excluded evidence"
            )
        try:
            excluded_fingerprints = (
                exclusion_snapshot.excluded_perceptual_fingerprints
            )
            if excluded_fingerprints and any(
                find_near_duplicate_candidates(
                    probe=image.perceptual_fingerprint,
                    inventory=excluded_fingerprints,
                )
                for item in selection.batch_manifest.items
                for image in item.images
            ):
                raise FormalSelectionLifecycleStoreError(
                    "replacement selection overlaps perceptually excluded evidence"
                )
        except ImageSimilarityContractError as exc:
            raise FormalSelectionLifecycleStoreError(
                "replacement perceptual exclusion evidence is invalid"
            ) from exc
        desired = FormalSelectionLifecycleNode(
            target_kind=_TARGET,
            sequence=invalidated.sequence + 1,
            generation=invalidated.generation + 1,
            event_kind=FormalSelectionLifecycleEvent.ACTIVATED,
            previous_head_sha256=invalidated.canonical_sha256,
            selection_sha256=selection.canonical_sha256,
            predecessor_selection_sha256=old_selection_sha,
            failure_attestation_sha256=None,
            exclusion_inventory_sha256=None,
            exclusion_authority_sha256=exclusion_snapshot.authority_sha256,
            exclusion_child_head_sha256=(
                exclusion_snapshot.child_index_head_sha256
            ),
            source_build_sha256=(
                selection.batch_manifest.source_build_sha256
            ),
            pipeline_fingerprint=(
                selection.batch_manifest.pipeline_fingerprint
            ),
            identity_context_sha256=(
                selection.batch_manifest.identity_context_sha256
            ),
            created_at=_utc_now(),
        )
        return self._append(
            desired=desired,
            matches=lambda node: (
                node.event_kind
                is FormalSelectionLifecycleEvent.ACTIVATED
                and node.generation == invalidated.generation + 1
                and node.selection_sha256 == selection.canonical_sha256
                and node.predecessor_selection_sha256
                == old_selection_sha
            ),
        )
