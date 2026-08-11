from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from dahe.application.chengfeng.shadow_batch import ShadowBatchTargetKind

SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FormalSelectionLifecycleContractError(ValueError):
    """Raised when a formal selection lifecycle record is inconsistent."""


class FormalSelectionLifecycleEvent(StrEnum):
    ACTIVATED = "activated"
    INVALIDATED = "invalidated"


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


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise FormalSelectionLifecycleContractError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _optional_sha256(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label=label)


def _timestamp(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.endswith("Z")
        or len(value) > 40
        or any(ord(character) < 32 for character in value)
    ):
        raise FormalSelectionLifecycleContractError(
            "lifecycle creation time is invalid"
        )
    return value


@dataclass(frozen=True, slots=True)
class FormalSelectionLifecycleNode:
    target_kind: ShadowBatchTargetKind
    sequence: int
    generation: int
    event_kind: FormalSelectionLifecycleEvent
    previous_head_sha256: str | None
    selection_sha256: str
    predecessor_selection_sha256: str | None
    failure_attestation_sha256: str | None
    exclusion_inventory_sha256: str | None
    exclusion_authority_sha256: str
    exclusion_child_head_sha256: str
    source_build_sha256: str
    pipeline_fingerprint: str
    identity_context_sha256: str
    created_at: str
    schema_version: int = SCHEMA_VERSION
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            self.target_kind
            is not ShadowBatchTargetKind.CURRENT_LOCKED_50
            or type(self.sequence) is not int
            or self.sequence < 1
            or type(self.generation) is not int
            or self.generation < 1
            or not isinstance(
                self.event_kind,
                FormalSelectionLifecycleEvent,
            )
            or self.schema_version != SCHEMA_VERSION
        ):
            raise FormalSelectionLifecycleContractError(
                "formal selection lifecycle node shape is invalid"
            )
        _optional_sha256(
            self.previous_head_sha256,
            label="previous lifecycle head",
        )
        for label, value in (
            ("selection SHA-256", self.selection_sha256),
            (
                "exclusion authority SHA-256",
                self.exclusion_authority_sha256,
            ),
            (
                "exclusion child head SHA-256",
                self.exclusion_child_head_sha256,
            ),
            ("source build SHA-256", self.source_build_sha256),
            ("pipeline fingerprint", self.pipeline_fingerprint),
            ("identity context SHA-256", self.identity_context_sha256),
        ):
            _sha256(value, label=label)
        _optional_sha256(
            self.predecessor_selection_sha256,
            label="predecessor selection SHA-256",
        )
        _optional_sha256(
            self.failure_attestation_sha256,
            label="failure attestation SHA-256",
        )
        _optional_sha256(
            self.exclusion_inventory_sha256,
            label="exclusion inventory SHA-256",
        )
        _timestamp(self.created_at)
        if self.sequence == 1:
            if (
                self.generation != 1
                or self.event_kind
                is not FormalSelectionLifecycleEvent.ACTIVATED
                or self.previous_head_sha256 is not None
                or self.predecessor_selection_sha256 is not None
                or self.failure_attestation_sha256 is not None
                or self.exclusion_inventory_sha256 is not None
            ):
                raise FormalSelectionLifecycleContractError(
                    "formal selection lifecycle genesis is invalid"
                )
        elif self.previous_head_sha256 is None:
            raise FormalSelectionLifecycleContractError(
                "formal selection lifecycle node has no predecessor"
            )
        if self.event_kind is FormalSelectionLifecycleEvent.ACTIVATED:
            if (
                self.failure_attestation_sha256 is not None
                or self.exclusion_inventory_sha256 is not None
                or (
                    self.generation > 1
                    and self.predecessor_selection_sha256 is None
                )
            ):
                raise FormalSelectionLifecycleContractError(
                    "formal selection activation evidence is invalid"
                )
        elif (
            self.sequence == 1
            or self.predecessor_selection_sha256 is not None
            or self.failure_attestation_sha256 is None
            or self.exclusion_inventory_sha256 is None
        ):
            raise FormalSelectionLifecycleContractError(
                "formal selection invalidation evidence is invalid"
            )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "created_at": self.created_at,
            "event_kind": self.event_kind.value,
            "exclusion_authority_sha256": (
                self.exclusion_authority_sha256
            ),
            "exclusion_child_head_sha256": (
                self.exclusion_child_head_sha256
            ),
            "exclusion_inventory_sha256": (
                self.exclusion_inventory_sha256
            ),
            "failure_attestation_sha256": (
                self.failure_attestation_sha256
            ),
            "generation": self.generation,
            "identity_context_sha256": self.identity_context_sha256,
            "pipeline_fingerprint": self.pipeline_fingerprint,
            "predecessor_selection_sha256": (
                self.predecessor_selection_sha256
            ),
            "previous_head_sha256": self.previous_head_sha256,
            "schema_version": self.schema_version,
            "selection_sha256": self.selection_sha256,
            "sequence": self.sequence,
            "source_build_sha256": self.source_build_sha256,
            "target_kind": self.target_kind.value,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise FormalSelectionLifecycleContractError(
                "formal selection lifecycle node integrity is invalid"
            )

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> FormalSelectionLifecycleNode:
        if not isinstance(value, dict):
            raise FormalSelectionLifecycleContractError(
                "formal selection lifecycle node must be an object"
            )
        expected = {
            "canonical_sha256",
            "created_at",
            "event_kind",
            "exclusion_authority_sha256",
            "exclusion_child_head_sha256",
            "exclusion_inventory_sha256",
            "failure_attestation_sha256",
            "generation",
            "identity_context_sha256",
            "pipeline_fingerprint",
            "predecessor_selection_sha256",
            "previous_head_sha256",
            "schema_version",
            "selection_sha256",
            "sequence",
            "source_build_sha256",
            "target_kind",
        }
        if set(value) != expected:
            raise FormalSelectionLifecycleContractError(
                "formal selection lifecycle node contract is invalid"
            )
        try:
            node = cls(
                target_kind=ShadowBatchTargetKind(
                    cast(str, value["target_kind"])
                ),
                sequence=cast(int, value["sequence"]),
                generation=cast(int, value["generation"]),
                event_kind=FormalSelectionLifecycleEvent(
                    cast(str, value["event_kind"])
                ),
                previous_head_sha256=cast(
                    str | None,
                    value["previous_head_sha256"],
                ),
                selection_sha256=cast(str, value["selection_sha256"]),
                predecessor_selection_sha256=cast(
                    str | None,
                    value["predecessor_selection_sha256"],
                ),
                failure_attestation_sha256=cast(
                    str | None,
                    value["failure_attestation_sha256"],
                ),
                exclusion_inventory_sha256=cast(
                    str | None,
                    value["exclusion_inventory_sha256"],
                ),
                exclusion_authority_sha256=cast(
                    str,
                    value["exclusion_authority_sha256"],
                ),
                exclusion_child_head_sha256=cast(
                    str,
                    value["exclusion_child_head_sha256"],
                ),
                source_build_sha256=cast(
                    str,
                    value["source_build_sha256"],
                ),
                pipeline_fingerprint=cast(
                    str,
                    value["pipeline_fingerprint"],
                ),
                identity_context_sha256=cast(
                    str,
                    value["identity_context_sha256"],
                ),
                created_at=cast(str, value["created_at"]),
                schema_version=cast(int, value["schema_version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, FormalSelectionLifecycleContractError):
                raise
            raise FormalSelectionLifecycleContractError(
                "formal selection lifecycle node contract is invalid"
            ) from exc
        if value["canonical_sha256"] != node.canonical_sha256:
            raise FormalSelectionLifecycleContractError(
                "formal selection lifecycle node integrity is invalid"
            )
        return node

@dataclass(frozen=True, slots=True)
class FormalSelectionLifecycleState:
    target_kind: ShadowBatchTargetKind
    sequence: int
    generation: int
    event_kind: FormalSelectionLifecycleEvent
    head_sha256: str
    active_selection_sha256: str | None
    canonical_sha256: str
