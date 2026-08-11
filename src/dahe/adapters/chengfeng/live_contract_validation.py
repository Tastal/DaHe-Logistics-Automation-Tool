from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from dahe.adapters.chengfeng.browser_runtime import SettlementListProbe
from dahe.adapters.chengfeng.daily_contract_selection import (
    SelectedDailyReadContract,
)
from dahe.adapters.chengfeng.live_contract_selection import (
    SelectedLiveReadContract,
)
from dahe.application.chengfeng.shadow_batch import (
    chengfeng_shadow_identity_context_sha256,
)
from dahe.ports.chengfeng import (
    CURRENT_PENDING_SETTLEMENT_SCOPE,
    BrowserCommandAuthority,
    ChengfengReadPort,
    DetailCandidateUnavailableError,
    TicketReference,
    WaybillDetail,
    WaybillPage,
)
from dahe.verification.image_similarity import (
    ImagePerceptualFingerprint,
    ImageSimilarityContractError,
    build_image_fingerprint,
)
from dahe.verification.loop9_dataset_isolation import (
    ExclusionKind,
    Loop9DatasetExclusionInventory,
    Loop9DatasetIsolationError,
    platform_identity_sha256,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ACCESS_WINDOW_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_MAXIMUM_DETAIL_ATTEMPTS = 5
_BASE_DOCUMENT_KEYS = {
    "access_window_id",
    "build_sha256",
    "canonical_sha256",
    "classification",
    "contract_canonical_sha256",
    "contract_file_sha256",
    "detail_attempt_count",
    "forbidden_request_count",
    "freeze_evidence_sha256",
    "gate_passed",
    "images",
    "kind",
    "list_empty_confirmation_performed",
    "list_item_count",
    "operation_counts",
    "page_native_probe",
    "platform_write_request_count",
    "raw_request_values_retained",
    "raw_response_values_retained",
    "redirect_count",
    "schema_version",
    "selection_sha256",
    "signed_image_urls_retained",
    "source_discovery_sha256",
    "validated_at",
}
_V4_DOCUMENT_KEYS = _BASE_DOCUMENT_KEYS | {
    "daily_business_date",
    "daily_contract_canonical_sha256",
    "daily_contract_file_sha256",
    "daily_contract_freeze_evidence_sha256",
    "daily_contract_selection_sha256",
    "daily_contract_source_discovery_sha256",
    "daily_list_item_count",
    "daily_query_scope_sha256",
    "settlement_empty_evidence_sha256",
    "shared_detail_image_validation_sha256",
    "validation_mode",
}
_SETTLEMENT_EMPTY_KEYS = {
    "access_window_id",
    "build_sha256",
    "canonical_sha256",
    "classification",
    "contract_canonical_sha256",
    "contract_file_sha256",
    "empty_confirmed",
    "forbidden_request_count",
    "freeze_evidence_sha256",
    "kind",
    "page_native_probe",
    "platform_write_request_count",
    "raw_request_values_retained",
    "raw_response_values_retained",
    "read_count",
    "read_item_counts",
    "read_total_counts",
    "redirect_count",
    "schema_version",
    "selection_sha256",
    "source_discovery_sha256",
}
_SHARED_VALIDATION_KEYS = {
    "access_window_id",
    "build_sha256",
    "canonical_sha256",
    "classification",
    "daily_business_date",
    "daily_contract_canonical_sha256",
    "daily_contract_file_sha256",
    "daily_contract_freeze_evidence_sha256",
    "daily_contract_selection_sha256",
    "daily_contract_source_discovery_sha256",
    "daily_list_item_count",
    "daily_query_scope_sha256",
    "detail_attempt_count",
    "development_exclusion_inventory_sha256",
    "development_exclusion_sha256",
    "forbidden_request_count",
    "image_count",
    "images",
    "kind",
    "platform_identity_sha256",
    "platform_write_request_count",
    "raw_business_values_retained",
    "raw_image_bytes_retained",
    "raw_request_values_retained",
    "raw_response_values_retained",
    "redirect_count",
    "schema_version",
    "settlement_contract_canonical_sha256",
    "settlement_contract_file_sha256",
    "settlement_contract_freeze_evidence_sha256",
    "settlement_contract_selection_sha256",
    "settlement_contract_source_discovery_sha256",
    "signed_image_urls_retained",
}
_EXCLUSION_BINDING_KEYS = {
    "access_window_id",
    "build_sha256",
    "canonical_sha256",
    "classification",
    "contract_canonical_sha256",
    "image_count",
    "identity_context_sha256",
    "inventory_sha256",
    "kind",
    "platform_identity_count",
    "raw_business_values_retained",
    "raw_image_bytes_retained",
    "raw_platform_identity_retained",
    "schema_version",
    "selection_sha256",
    "source_discovery_sha256",
}
_LEGACY_EXCLUSION_BINDING_KEYS = (
    _EXCLUSION_BINDING_KEYS - {"identity_context_sha256"}
)


class LiveContractValidationError(RuntimeError):
    """Raised when the selected live contract cannot prove its read surface."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "validation_failed",
    ) -> None:
        super().__init__(message)
        self.code = code


class LiveContractValidationPort(Protocol):
    @property
    def selection_sha256(self) -> str: ...

    def existing_for_access_window(
        self,
        access_window_id: str,
    ) -> LiveContractValidationResult | None: ...

    def has_successful_validation(
        self,
        build_sha256: str,
    ) -> bool: ...

    def validate(
        self,
        *,
        authority: BrowserCommandAuthority,
        access_window_id: str,
        build_sha256: str,
        settlement_probe: SettlementListProbe | None = None,
    ) -> LiveContractValidationResult: ...


@dataclass(frozen=True, slots=True)
class DailyContractValidationCandidatePage:
    """One in-memory daily candidate page; raw identities are never persisted."""

    business_date: str
    query_scope_sha256: str
    page_number: int
    page_size: int
    total: int
    platform_waybill_ids: tuple[str, ...]
    read_attempt_count: int = 1


class DailyContractValidationSource(Protocol):
    @property
    def selected(self) -> SelectedDailyReadContract: ...

    def prepare_and_list(
        self,
        *,
        authority: BrowserCommandAuthority,
    ) -> DailyContractValidationCandidatePage: ...


@dataclass(frozen=True, slots=True)
class LiveContractValidationResult:
    evidence_id: str
    canonical_sha256: str
    selection_sha256: str
    list_item_count: int
    detail_attempt_count: int
    image_count: int
    evidence_path: Path
    development_exclusion_sha256: str | None = None
    development_exclusion_inventory_sha256: str | None = None
    identity_context_sha256: str | None = None


class LiveContractValidationRunner:
    """Validate one selected contract without retaining platform values."""

    def __init__(
        self,
        *,
        connector: ChengfengReadPort,
        selected: SelectedLiveReadContract,
        data_root: Path,
        clock: Callable[[], datetime],
        identity_salt: bytes,
        identity_namespace: str,
        daily_source: DailyContractValidationSource | None = None,
    ) -> None:
        self._connector = connector
        self._selected = selected
        self._root = _evidence_root(data_root)
        self._exclusion_root = _evidence_subdirectory(
            data_root,
            "platform-read-contract-validation-exclusions",
        )
        self._inventory_root = _evidence_subdirectory(
            data_root,
            "loop9-development-exclusions",
        )
        self._settlement_empty_root = _evidence_subdirectory(
            data_root,
            "platform-read-contract-validation-settlement-empty",
        )
        self._shared_validation_root = _evidence_subdirectory(
            data_root,
            "platform-read-contract-shared-validation",
        )
        self._clock = clock
        self._identity_salt = identity_salt
        self._identity_namespace = identity_namespace
        self._daily_source = daily_source
        try:
            self._identity_context_sha256 = (
                chengfeng_shadow_identity_context_sha256(
                    salt=identity_salt,
                    namespace=identity_namespace,
                )
            )
            platform_identity_sha256(
                identity_salt=identity_salt,
                identity_namespace=identity_namespace,
                source_identity="identity-contract-smoke",
            )
        except (TypeError, ValueError, Loop9DatasetIsolationError) as exc:
            raise LiveContractValidationError(
                "platform identity authority is invalid"
            ) from exc

    @property
    def selection_sha256(self) -> str:
        return self._selected.selection_sha256

    def existing_for_access_window(
        self,
        access_window_id: str,
    ) -> LiveContractValidationResult | None:
        _require_access_window_id(access_window_id)
        matches: list[LiveContractValidationResult] = []
        for path in self._root.glob("*.json"):
            if path.is_symlink() or path.resolve().parent != self._root:
                raise LiveContractValidationError(
                    "contract validation evidence directory is unsafe"
                )
            result, document = _load_result(path)
            if document["access_window_id"] == access_window_id:
                matches.append(result)
        if len(matches) > 1:
            raise LiveContractValidationError(
                "access window has multiple contract validation records"
            )
        return None if not matches else matches[0]

    def has_successful_validation(
        self,
        build_sha256: str,
    ) -> bool:
        _require_sha256(build_sha256, label="build")
        matched = False
        for path in self._root.glob("*.json"):
            if path.is_symlink() or path.resolve().parent != self._root:
                raise LiveContractValidationError(
                    "contract validation evidence directory is unsafe"
                )
            result, document = _load_result(path)
            if (
                document["build_sha256"] == build_sha256
                and result.selection_sha256
                == self._selected.selection_sha256
                and document["contract_canonical_sha256"]
                == self._selected.manifest.canonical_sha256
                and result.development_exclusion_sha256 is not None
                and result.development_exclusion_inventory_sha256
                is not None
                and result.identity_context_sha256
                == self._identity_context_sha256
                and (
                    document.get("validation_mode")
                    != "settlement_empty_daily_nonempty"
                    or (
                        self._daily_source is not None
                        and document.get(
                            "daily_contract_canonical_sha256"
                        )
                        == self._daily_source.selected.manifest.canonical_sha256
                        and document.get(
                            "daily_contract_selection_sha256"
                        )
                        == self._daily_source.selected.selection_sha256
                    )
                )
            ):
                matched = True
        return matched

    def _write_settlement_empty_evidence(
        self,
        *,
        access_window_id: str,
        build_sha256: str,
        pages: tuple[WaybillPage, ...],
        settlement_probe: SettlementListProbe | None,
    ) -> str:
        if (
            len(pages) != 2
            or any(page.items or page.total != 0 for page in pages)
        ):
            raise LiveContractValidationError(
                "settlement empty evidence requires two empty reads"
            )
        body: dict[str, object] = {
            "schema_version": 1,
            "kind": "loop9_settlement_empty_read_evidence",
            "classification": "development_only",
            "access_window_id": access_window_id,
            "build_sha256": build_sha256,
            "contract_canonical_sha256": (
                self._selected.manifest.canonical_sha256
            ),
            "contract_file_sha256": self._selected.contract_file_sha256,
            "freeze_evidence_sha256": self._selected.freeze_evidence_sha256,
            "selection_sha256": self._selected.selection_sha256,
            "source_discovery_sha256": (
                self._selected.manifest.source_discovery_sha256
            ),
            "read_count": 2,
            "read_item_counts": [len(page.items) for page in pages],
            "read_total_counts": [page.total for page in pages],
            "page_native_probe": _settlement_probe_payload(
                settlement_probe
            ),
            "empty_confirmed": True,
            "forbidden_request_count": 0,
            "platform_write_request_count": 0,
            "redirect_count": 0,
            "raw_request_values_retained": False,
            "raw_response_values_retained": False,
        }
        canonical_sha256 = hashlib.sha256(_canonical(body)).hexdigest()
        _write_once(
            self._settlement_empty_root / f"{canonical_sha256}.json",
            _canonical(
                {**body, "canonical_sha256": canonical_sha256}
            )
            + b"\n",
        )
        return canonical_sha256

    def validate(
        self,
        *,
        authority: BrowserCommandAuthority,
        access_window_id: str,
        build_sha256: str,
        settlement_probe: SettlementListProbe | None = None,
    ) -> LiveContractValidationResult:
        _require_access_window_id(access_window_id)
        _require_sha256(build_sha256, label="build")
        existing = self.existing_for_access_window(access_window_id)
        if existing is not None:
            if (
                existing.identity_context_sha256
                != self._identity_context_sha256
            ):
                raise LiveContractValidationError(
                    "legacy validation evidence cannot satisfy the current "
                    "platform identity contract",
                    code="legacy_identity_evidence",
                )
            return existing
        page = self._connector.list_waybills(
            authority=authority,
            scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
            page_number=1,
            page_size=20,
        )
        settlement_pages = [page]
        list_attempt_count = 1
        if not page.items:
            page = self._connector.list_waybills(
                authority=authority,
                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                page_number=1,
                page_size=20,
            )
            settlement_pages.append(page)
            list_attempt_count += 1
        if (
            settlement_probe is not None
            and page.total != settlement_probe.total_count
        ):
            raise LiveContractValidationError(
                "page-native settlement count disagrees with direct replay",
                code="page_native_replay_mismatch",
            )
        validation_mode = "settlement_nonempty"
        settlement_empty_evidence_sha256: str | None = None
        daily_page: DailyContractValidationCandidatePage | None = None
        candidate_ids = tuple(
            summary.platform_waybill_id for summary in page.items
        )
        if not page.items:
            settlement_empty_evidence_sha256 = (
                self._write_settlement_empty_evidence(
                    access_window_id=access_window_id,
                    build_sha256=build_sha256,
                    pages=tuple(settlement_pages),
                    settlement_probe=settlement_probe,
                )
            )
            if self._daily_source is None:
                raise LiveContractValidationError(
                    "pending-settlement list was empty in two consecutive reads",
                    code="pending_list_empty_confirmed",
                )
            daily_page = self._daily_source.prepare_and_list(
                authority=authority,
            )
            _validate_daily_candidate_page(daily_page)
            if not daily_page.platform_waybill_ids:
                raise LiveContractValidationError(
                    "daily shared validation list is empty",
                    code="daily_shared_validation_empty",
                )
            validation_mode = "settlement_empty_daily_nonempty"
            candidate_ids = daily_page.platform_waybill_ids
        selected_detail: WaybillDetail | None = None
        detail_attempt_count = 0
        for platform_waybill_id in candidate_ids[:_MAXIMUM_DETAIL_ATTEMPTS]:
            detail_attempt_count += 1
            try:
                detail = self._connector.get_waybill_detail(
                    authority=authority,
                    platform_waybill_id=platform_waybill_id,
                )
            except DetailCandidateUnavailableError:
                continue
            if _ticket_slots(detail.tickets) == {"loading", "unloading"}:
                selected_detail = detail
                break
        if selected_detail is None:
            raise LiveContractValidationError(
                "no bounded detail candidate contains both ticket images",
                code="detail_candidate_missing",
            )
        images: list[dict[str, object]] = []
        fingerprints: list[ImagePerceptualFingerprint] = []
        for ticket in sorted(selected_detail.tickets, key=lambda item: item.slot):
            downloaded = self._connector.download_ticket_image(
                authority=authority,
                ticket_ref=ticket.ticket_ref,
            )
            if (
                downloaded.ticket_ref != ticket.ticket_ref
                or not downloaded.content
                or not downloaded.media_type.startswith("image/")
                or hashlib.sha256(downloaded.content).hexdigest()
                != downloaded.sha256
            ):
                raise LiveContractValidationError(
                    "ticket image result failed integrity validation",
                    code="image_integrity_failed",
                )
            try:
                fingerprints.append(
                    build_image_fingerprint(downloaded.content)
                )
            except ImageSimilarityContractError as exc:
                raise LiveContractValidationError(
                    "ticket image fingerprint failed",
                    code="image_fingerprint_failed",
                ) from exc
            images.append(
                {
                    "slot": ticket.slot,
                    "sha256": downloaded.sha256,
                    "media_type": downloaded.media_type,
                    "byte_size": len(downloaded.content),
                }
            )
        if len(images) != 2:
            raise LiveContractValidationError(
                "contract validation did not receive two ticket images",
                code="image_pair_incomplete",
            )
        development_exclusion = Loop9DatasetExclusionInventory(
            inventory_id=(
                f"live-contract-validation-{access_window_id}"
            ),
            exclusion_kind=ExclusionKind.DEVELOPMENT,
            platform_identity_sha256s=(
                platform_identity_sha256(
                    identity_salt=self._identity_salt,
                    identity_namespace=self._identity_namespace,
                    source_identity=(
                        selected_detail.platform_waybill_id
                    ),
                ),
            ),
            image_sha256s=tuple(
                str(image["sha256"]) for image in images
            ),
            scope_exclusion_tokens=(),
            perceptual_fingerprints=tuple(fingerprints),
            identity_context_sha256=self._identity_context_sha256,
        )
        inventory_path = (
            self._inventory_root
            / f"{development_exclusion.canonical_sha256}.json"
        )
        _write_once(
            inventory_path,
            _canonical(development_exclusion.to_payload()) + b"\n",
        )
        exclusion_body: dict[str, object] = {
            "schema_version": 2,
            "kind": "loop9_live_contract_validation_exclusion",
            "classification": "development_only",
            "access_window_id": access_window_id,
            "build_sha256": build_sha256,
            "selection_sha256": self._selected.selection_sha256,
            "contract_canonical_sha256": (
                self._selected.manifest.canonical_sha256
            ),
            "source_discovery_sha256": (
                self._selected.manifest.source_discovery_sha256
            ),
            "inventory_sha256": (
                development_exclusion.canonical_sha256
            ),
            "platform_identity_count": 1,
            "image_count": 2,
            "identity_context_sha256": self._identity_context_sha256,
            "raw_platform_identity_retained": False,
            "raw_business_values_retained": False,
            "raw_image_bytes_retained": False,
        }
        exclusion_sha256 = hashlib.sha256(
            _canonical(exclusion_body)
        ).hexdigest()
        exclusion_document = {
            **exclusion_body,
            "canonical_sha256": exclusion_sha256,
        }
        exclusion_path = (
            self._exclusion_root / f"{exclusion_sha256}.json"
        )
        _write_once(
            exclusion_path,
            _canonical(exclusion_document) + b"\n",
        )
        shared_validation_sha256: str | None = None
        daily_selected = (
            None if self._daily_source is None else self._daily_source.selected
        )
        if daily_page is not None:
            if daily_selected is None:
                raise LiveContractValidationError(
                    "daily shared validation authority is unavailable"
                )
            shared_body: dict[str, object] = {
                "schema_version": 1,
                "kind": "loop9_shared_detail_image_validation",
                "classification": "development_only",
                "access_window_id": access_window_id,
                "build_sha256": build_sha256,
                "settlement_contract_canonical_sha256": (
                    self._selected.manifest.canonical_sha256
                ),
                "settlement_contract_file_sha256": (
                    self._selected.contract_file_sha256
                ),
                "settlement_contract_freeze_evidence_sha256": (
                    self._selected.freeze_evidence_sha256
                ),
                "settlement_contract_selection_sha256": (
                    self._selected.selection_sha256
                ),
                "settlement_contract_source_discovery_sha256": (
                    self._selected.manifest.source_discovery_sha256
                ),
                "daily_contract_canonical_sha256": (
                    daily_selected.manifest.canonical_sha256
                ),
                "daily_contract_file_sha256": (
                    daily_selected.contract_file_sha256
                ),
                "daily_contract_freeze_evidence_sha256": (
                    daily_selected.freeze_evidence_sha256
                ),
                "daily_contract_selection_sha256": (
                    daily_selected.selection_sha256
                ),
                "daily_contract_source_discovery_sha256": (
                    daily_selected.manifest.source_discovery_sha256
                ),
                "daily_business_date": daily_page.business_date,
                "daily_query_scope_sha256": (
                    daily_page.query_scope_sha256
                ),
                "daily_list_item_count": len(
                    daily_page.platform_waybill_ids
                ),
                "detail_attempt_count": detail_attempt_count,
                "platform_identity_sha256": (
                    development_exclusion.platform_identity_sha256s[0]
                ),
                "image_count": len(images),
                "images": images,
                "development_exclusion_sha256": exclusion_sha256,
                "development_exclusion_inventory_sha256": (
                    development_exclusion.canonical_sha256
                ),
                "forbidden_request_count": 0,
                "platform_write_request_count": 0,
                "redirect_count": 0,
                "raw_request_values_retained": False,
                "raw_response_values_retained": False,
                "raw_business_values_retained": False,
                "raw_image_bytes_retained": False,
                "signed_image_urls_retained": False,
            }
            shared_validation_sha256 = hashlib.sha256(
                _canonical(shared_body)
            ).hexdigest()
            _write_once(
                self._shared_validation_root
                / f"{shared_validation_sha256}.json",
                _canonical(
                    {
                        **shared_body,
                        "canonical_sha256": (
                            shared_validation_sha256
                        ),
                    }
                )
                + b"\n",
            )
        validated_at = _aware_utc(self._clock())
        daily_contract_canonical_sha256 = (
            None
            if daily_page is None or daily_selected is None
            else daily_selected.manifest.canonical_sha256
        )
        daily_contract_file_sha256 = (
            None
            if daily_page is None or daily_selected is None
            else daily_selected.contract_file_sha256
        )
        daily_contract_freeze_evidence_sha256 = (
            None
            if daily_page is None or daily_selected is None
            else daily_selected.freeze_evidence_sha256
        )
        daily_contract_selection_sha256 = (
            None
            if daily_page is None or daily_selected is None
            else daily_selected.selection_sha256
        )
        daily_contract_source_discovery_sha256 = (
            None
            if daily_page is None or daily_selected is None
            else daily_selected.manifest.source_discovery_sha256
        )
        body: dict[str, object] = {
            "schema_version": 4,
            "kind": "loop9_live_read_contract_validation",
            "classification": "development_only",
            "validation_mode": validation_mode,
            "access_window_id": access_window_id,
            "build_sha256": build_sha256,
            "contract_canonical_sha256": (
                self._selected.manifest.canonical_sha256
            ),
            "contract_file_sha256": self._selected.contract_file_sha256,
            "freeze_evidence_sha256": self._selected.freeze_evidence_sha256,
            "selection_sha256": self._selected.selection_sha256,
            "source_discovery_sha256": (
                self._selected.manifest.source_discovery_sha256
            ),
            "validated_at": validated_at.isoformat(),
            "operation_counts": {
                "list_waybills": list_attempt_count,
                "list_daily_waybills": (
                    0
                    if daily_page is None
                    else daily_page.read_attempt_count
                ),
                "get_waybill_detail": detail_attempt_count,
                "download_ticket_image": len(images),
            },
            "list_empty_confirmation_performed": list_attempt_count == 2,
            "list_item_count": len(page.items),
            "page_native_probe": _settlement_probe_payload(
                settlement_probe
            ),
            "settlement_empty_evidence_sha256": (
                settlement_empty_evidence_sha256
            ),
            "shared_detail_image_validation_sha256": (
                shared_validation_sha256
            ),
            "daily_contract_canonical_sha256": (
                daily_contract_canonical_sha256
            ),
            "daily_contract_file_sha256": daily_contract_file_sha256,
            "daily_contract_freeze_evidence_sha256": (
                daily_contract_freeze_evidence_sha256
            ),
            "daily_contract_selection_sha256": (
                daily_contract_selection_sha256
            ),
            "daily_contract_source_discovery_sha256": (
                daily_contract_source_discovery_sha256
            ),
            "daily_business_date": (
                None if daily_page is None else daily_page.business_date
            ),
            "daily_query_scope_sha256": (
                None
                if daily_page is None
                else daily_page.query_scope_sha256
            ),
            "daily_list_item_count": (
                0
                if daily_page is None
                else len(daily_page.platform_waybill_ids)
            ),
            "detail_attempt_count": detail_attempt_count,
            "images": images,
            "development_exclusion_sha256": exclusion_sha256,
            "development_exclusion_inventory_sha256": (
                development_exclusion.canonical_sha256
            ),
            "identity_context_sha256": self._identity_context_sha256,
            "forbidden_request_count": 0,
            "platform_write_request_count": 0,
            "redirect_count": 0,
            "raw_request_values_retained": False,
            "raw_response_values_retained": False,
            "signed_image_urls_retained": False,
            "gate_passed": True,
        }
        canonical_sha256 = hashlib.sha256(_canonical(body)).hexdigest()
        document = {**body, "canonical_sha256": canonical_sha256}
        target = self._root / f"{canonical_sha256}.json"
        _write_once(target, _canonical(document) + b"\n")
        result, _ = _load_result(target)
        return result


def _ticket_slots(tickets: tuple[TicketReference, ...]) -> set[str]:
    slots = {ticket.slot for ticket in tickets}
    if len(slots) != len(tickets) or not slots <= {"loading", "unloading"}:
        raise LiveContractValidationError("detail ticket slots are invalid")
    return slots


def _settlement_probe_payload(
    probe: SettlementListProbe | None,
) -> dict[str, object] | None:
    if probe is None:
        return None
    return {
        "total_count": probe.total_count,
        "list_length": probe.list_length,
        "page_number": probe.page_number,
        "page_size": probe.page_size,
        "response_structure_sha256": probe.response_structure_sha256,
    }


def _validate_daily_candidate_page(
    page: DailyContractValidationCandidatePage,
) -> None:
    if not isinstance(page, DailyContractValidationCandidatePage):
        raise LiveContractValidationError(
            "daily shared validation page is invalid"
        )
    try:
        canonical_date = datetime.strptime(
            page.business_date,
            "%Y-%m-%d",
        ).date().isoformat()
    except (TypeError, ValueError) as exc:
        raise LiveContractValidationError(
            "daily shared validation business date is invalid"
        ) from exc
    if (
        canonical_date != page.business_date
        or _SHA256.fullmatch(page.query_scope_sha256) is None
        or type(page.page_number) is not int
        or page.page_number != 1
        or type(page.page_size) is not int
        or not 1 <= page.page_size <= 100
        or type(page.total) is not int
        or page.total < len(page.platform_waybill_ids)
        or type(page.read_attempt_count) is not int
        or not 1 <= page.read_attempt_count <= 7
        or len(page.platform_waybill_ids) > page.page_size
        or len(set(page.platform_waybill_ids))
        != len(page.platform_waybill_ids)
        or any(
            not isinstance(value, str)
            or not value
            or len(value) > 200
            for value in page.platform_waybill_ids
        )
    ):
        raise LiveContractValidationError(
            "daily shared validation page is invalid"
        )


def _load_result(
    path: Path,
) -> tuple[LiveContractValidationResult, dict[str, object]]:
    try:
        document = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveContractValidationError(
            "contract validation evidence is unreadable"
        ) from exc
    if not isinstance(document, dict):
        raise LiveContractValidationError(
            "contract validation evidence schema is invalid"
        )
    declared = document.get("canonical_sha256")
    body = {key: value for key, value in document.items() if key != "canonical_sha256"}
    schema_version = document.get("schema_version")
    expected_keys = _BASE_DOCUMENT_KEYS
    if schema_version == 4:
        expected_keys = _V4_DOCUMENT_KEYS
    if schema_version in {2, 3, 4}:
        expected_keys = expected_keys | {
            "development_exclusion_inventory_sha256",
            "development_exclusion_sha256",
        }
    if schema_version in {3, 4}:
        expected_keys = expected_keys | {"identity_context_sha256"}
    if (
        not isinstance(declared, str)
        or _SHA256.fullmatch(declared) is None
        or hashlib.sha256(_canonical(body)).hexdigest() != declared
        or path.stem != declared
        or schema_version not in {1, 2, 3, 4}
        or set(document) != expected_keys
        or document.get("kind") != "loop9_live_read_contract_validation"
        or document.get("classification") != "development_only"
        or document.get("gate_passed") is not True
        or document.get("platform_write_request_count") != 0
        or document.get("forbidden_request_count") != 0
        or document.get("redirect_count") != 0
        or document.get("raw_request_values_retained") is not False
        or document.get("raw_response_values_retained") is not False
        or document.get("signed_image_urls_retained") is not False
    ):
        raise LiveContractValidationError(
            "contract validation evidence integrity failed"
        )
    selection_sha256 = document.get("selection_sha256")
    build_sha256 = document.get("build_sha256")
    contract_sha256 = document.get("contract_canonical_sha256")
    source_discovery_sha256 = document.get(
        "source_discovery_sha256"
    )
    access_window_id = document.get("access_window_id")
    list_item_count = document.get("list_item_count")
    detail_attempt_count = document.get("detail_attempt_count")
    images = document.get("images")
    if (
        not isinstance(selection_sha256, str)
        or _SHA256.fullmatch(selection_sha256) is None
        or not isinstance(build_sha256, str)
        or _SHA256.fullmatch(build_sha256) is None
        or not isinstance(contract_sha256, str)
        or _SHA256.fullmatch(contract_sha256) is None
        or not isinstance(source_discovery_sha256, str)
        or _SHA256.fullmatch(source_discovery_sha256) is None
        or not isinstance(access_window_id, str)
        or _ACCESS_WINDOW_ID.fullmatch(access_window_id) is None
        or not isinstance(list_item_count, int)
        or list_item_count < 0
        or (schema_version != 4 and list_item_count < 1)
        or not isinstance(detail_attempt_count, int)
        or not 1 <= detail_attempt_count <= _MAXIMUM_DETAIL_ATTEMPTS
        or not isinstance(images, list)
        or len(images) != 2
    ):
        raise LiveContractValidationError(
            "contract validation evidence values are invalid"
        )
    image_slots: set[str] = set()
    for image in images:
        if (
            not isinstance(image, dict)
            or set(image) != {
                "byte_size",
                "media_type",
                "sha256",
                "slot",
            }
            or image.get("slot") not in {"loading", "unloading"}
            or not isinstance(image.get("sha256"), str)
            or _SHA256.fullmatch(str(image["sha256"])) is None
            or not isinstance(image.get("media_type"), str)
            or not str(image["media_type"]).startswith("image/")
            or type(image.get("byte_size")) is not int
            or int(image["byte_size"]) < 1
        ):
            raise LiveContractValidationError(
                "contract validation image evidence is invalid"
            )
        image_slots.add(str(image["slot"]))
    if image_slots != {"loading", "unloading"}:
        raise LiveContractValidationError(
            "contract validation image evidence is invalid"
        )
    development_exclusion_sha256: str | None = None
    development_inventory_sha256: str | None = None
    identity_context_sha256: str | None = None
    if schema_version in {2, 3, 4}:
        development_exclusion_sha256 = _document_sha256(
            document,
            "development_exclusion_sha256",
        )
        development_inventory_sha256 = _document_sha256(
            document,
            "development_exclusion_inventory_sha256",
        )
        _load_exclusion_binding(
            validation_path=path,
            exclusion_sha256=development_exclusion_sha256,
            inventory_sha256=development_inventory_sha256,
            access_window_id=access_window_id,
            build_sha256=build_sha256,
            selection_sha256=selection_sha256,
            contract_sha256=contract_sha256,
            source_discovery_sha256=source_discovery_sha256,
            expected_identity_context_sha256=(
                None
                if schema_version == 2
                else _document_sha256(
                    document,
                    "identity_context_sha256",
                )
            ),
        )
        if schema_version in {3, 4}:
            identity_context_sha256 = _document_sha256(
                document,
                "identity_context_sha256",
            )
    if schema_version == 4:
        _validate_v4_authority(
            validation_path=path,
            document=document,
        )
    return (
        LiveContractValidationResult(
            evidence_id=declared,
            canonical_sha256=declared,
            selection_sha256=selection_sha256,
            list_item_count=list_item_count,
            detail_attempt_count=detail_attempt_count,
            image_count=len(images),
            evidence_path=path,
            development_exclusion_sha256=(
                development_exclusion_sha256
            ),
            development_exclusion_inventory_sha256=(
                development_inventory_sha256
            ),
            identity_context_sha256=identity_context_sha256,
        ),
        document,
    )


def _validate_v4_authority(
    *,
    validation_path: Path,
    document: dict[str, object],
) -> None:
    mode = document.get("validation_mode")
    operation_counts = document.get("operation_counts")
    if (
        mode
        not in {
            "settlement_nonempty",
            "settlement_empty_daily_nonempty",
        }
        or not isinstance(operation_counts, dict)
        or set(operation_counts)
        != {
            "download_ticket_image",
            "get_waybill_detail",
            "list_daily_waybills",
            "list_waybills",
        }
        or operation_counts.get("download_ticket_image") != 2
        or operation_counts.get("get_waybill_detail")
        != document.get("detail_attempt_count")
    ):
        raise LiveContractValidationError(
            "contract validation v4 authority is invalid"
        )
    list_waybill_count = operation_counts.get("list_waybills")
    if (
        not isinstance(list_waybill_count, int)
        or isinstance(list_waybill_count, bool)
        or not 1 <= list_waybill_count <= 2
    ):
        raise LiveContractValidationError(
            "contract validation v4 authority is invalid"
        )
    daily_fields = (
        "daily_contract_canonical_sha256",
        "daily_contract_file_sha256",
        "daily_contract_freeze_evidence_sha256",
        "daily_contract_selection_sha256",
        "daily_contract_source_discovery_sha256",
        "daily_query_scope_sha256",
    )
    list_item_count = document.get("list_item_count")
    if (
        not isinstance(list_item_count, int)
        or isinstance(list_item_count, bool)
    ):
        raise LiveContractValidationError(
            "contract validation v4 authority is invalid"
        )
    if mode == "settlement_nonempty":
        if (
            list_item_count < 1
            or document.get("daily_list_item_count") != 0
            or operation_counts.get("list_daily_waybills") != 0
            or document.get("settlement_empty_evidence_sha256")
            is not None
            or document.get(
                "shared_detail_image_validation_sha256"
            )
            is not None
            or document.get("daily_business_date") is not None
            or any(document.get(field) is not None for field in daily_fields)
        ):
            raise LiveContractValidationError(
                "direct settlement validation authority is invalid"
            )
        return

    empty_sha256 = _document_sha256(
        document,
        "settlement_empty_evidence_sha256",
    )
    shared_sha256 = _document_sha256(
        document,
        "shared_detail_image_validation_sha256",
    )
    daily_list_item_count = document.get("daily_list_item_count")
    daily_business_date = document.get("daily_business_date")
    if (
        list_item_count != 0
        or document.get("list_empty_confirmation_performed") is not True
        or operation_counts.get("list_waybills") != 2
        or not isinstance(
            operation_counts.get("list_daily_waybills"),
            int,
        )
        or not 1
        <= int(operation_counts["list_daily_waybills"])
        <= 7
        or not isinstance(daily_list_item_count, int)
        or isinstance(daily_list_item_count, bool)
        or daily_list_item_count < 1
        or not isinstance(daily_business_date, str)
        or any(
            not isinstance(document.get(field), str)
            or _SHA256.fullmatch(str(document[field])) is None
            for field in daily_fields
        )
    ):
        raise LiveContractValidationError(
            "composite contract validation authority is invalid"
        )
    try:
        if (
            datetime.strptime(
                daily_business_date,
                "%Y-%m-%d",
            ).date().isoformat()
            != daily_business_date
        ):
            raise ValueError
    except ValueError as exc:
        raise LiveContractValidationError(
            "composite validation business date is invalid"
        ) from exc
    data_root = validation_path.parent.parent.resolve()
    empty = _load_content_addressed_json(
        data_root
        / "platform-read-contract-validation-settlement-empty"
        / f"{empty_sha256}.json",
        expected_sha256=empty_sha256,
        label="settlement empty evidence",
    )
    _validate_settlement_empty_child(
        child=empty,
        parent=document,
    )
    shared = _load_content_addressed_json(
        data_root
        / "platform-read-contract-shared-validation"
        / f"{shared_sha256}.json",
        expected_sha256=shared_sha256,
        label="shared detail image authority",
    )
    _validate_shared_validation_child(
        child=shared,
        parent=document,
    )


def _validate_settlement_empty_child(
    *,
    child: dict[str, object],
    parent: dict[str, object],
) -> None:
    if (
        set(child) != _SETTLEMENT_EMPTY_KEYS
        or child.get("schema_version") != 1
        or child.get("kind")
        != "loop9_settlement_empty_read_evidence"
        or child.get("classification") != "development_only"
        or child.get("access_window_id")
        != parent.get("access_window_id")
        or child.get("build_sha256") != parent.get("build_sha256")
        or child.get("contract_canonical_sha256")
        != parent.get("contract_canonical_sha256")
        or child.get("contract_file_sha256")
        != parent.get("contract_file_sha256")
        or child.get("freeze_evidence_sha256")
        != parent.get("freeze_evidence_sha256")
        or child.get("selection_sha256")
        != parent.get("selection_sha256")
        or child.get("source_discovery_sha256")
        != parent.get("source_discovery_sha256")
        or child.get("read_count") != 2
        or child.get("read_item_counts") != [0, 0]
        or child.get("read_total_counts") != [0, 0]
        or child.get("empty_confirmed") is not True
        or child.get("page_native_probe")
        != parent.get("page_native_probe")
        or child.get("forbidden_request_count") != 0
        or child.get("platform_write_request_count") != 0
        or child.get("redirect_count") != 0
        or child.get("raw_request_values_retained") is not False
        or child.get("raw_response_values_retained") is not False
    ):
        raise LiveContractValidationError(
            "settlement empty evidence binding is invalid"
        )


def _validate_shared_validation_child(
    *,
    child: dict[str, object],
    parent: dict[str, object],
) -> None:
    settlement_bindings = {
        "settlement_contract_canonical_sha256": (
            "contract_canonical_sha256"
        ),
        "settlement_contract_file_sha256": "contract_file_sha256",
        "settlement_contract_freeze_evidence_sha256": (
            "freeze_evidence_sha256"
        ),
        "settlement_contract_selection_sha256": "selection_sha256",
        "settlement_contract_source_discovery_sha256": (
            "source_discovery_sha256"
        ),
    }
    daily_bindings = {
        "daily_contract_canonical_sha256": (
            "daily_contract_canonical_sha256"
        ),
        "daily_contract_file_sha256": "daily_contract_file_sha256",
        "daily_contract_freeze_evidence_sha256": (
            "daily_contract_freeze_evidence_sha256"
        ),
        "daily_contract_selection_sha256": (
            "daily_contract_selection_sha256"
        ),
        "daily_contract_source_discovery_sha256": (
            "daily_contract_source_discovery_sha256"
        ),
    }
    if (
        set(child) != _SHARED_VALIDATION_KEYS
        or child.get("schema_version") != 1
        or child.get("kind")
        != "loop9_shared_detail_image_validation"
        or child.get("classification") != "development_only"
        or child.get("access_window_id")
        != parent.get("access_window_id")
        or child.get("build_sha256") != parent.get("build_sha256")
        or any(
            child.get(child_field) != parent.get(parent_field)
            for child_field, parent_field in {
                **settlement_bindings,
                **daily_bindings,
            }.items()
        )
        or child.get("daily_business_date")
        != parent.get("daily_business_date")
        or child.get("daily_query_scope_sha256")
        != parent.get("daily_query_scope_sha256")
        or child.get("daily_list_item_count")
        != parent.get("daily_list_item_count")
        or child.get("detail_attempt_count")
        != parent.get("detail_attempt_count")
        or child.get("image_count") != 2
        or child.get("images") != parent.get("images")
        or child.get("development_exclusion_sha256")
        != parent.get("development_exclusion_sha256")
        or child.get("development_exclusion_inventory_sha256")
        != parent.get("development_exclusion_inventory_sha256")
        or not isinstance(child.get("platform_identity_sha256"), str)
        or _SHA256.fullmatch(
            str(child["platform_identity_sha256"])
        )
        is None
        or child.get("forbidden_request_count") != 0
        or child.get("platform_write_request_count") != 0
        or child.get("redirect_count") != 0
        or child.get("raw_request_values_retained") is not False
        or child.get("raw_response_values_retained") is not False
        or child.get("raw_business_values_retained") is not False
        or child.get("raw_image_bytes_retained") is not False
        or child.get("signed_image_urls_retained") is not False
    ):
        raise LiveContractValidationError(
            "shared detail image authority binding is invalid"
        )


def _document_sha256(
    document: dict[str, object],
    field: str,
) -> str:
    value = document.get(field)
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise LiveContractValidationError(
            "contract validation exclusion identity is invalid"
        )
    return value


def _load_exclusion_binding(
    *,
    validation_path: Path,
    exclusion_sha256: str,
    inventory_sha256: str,
    access_window_id: str,
    build_sha256: str,
    selection_sha256: str,
    contract_sha256: str,
    source_discovery_sha256: str,
    expected_identity_context_sha256: str | None,
) -> None:
    data_root = validation_path.parent.parent.resolve()
    inventory_path = (
        data_root
        / "loop9-development-exclusions"
        / f"{inventory_sha256}.json"
    )
    exclusion_path = (
        data_root
        / "platform-read-contract-validation-exclusions"
        / f"{exclusion_sha256}.json"
    )
    inventory_payload = _load_content_addressed_json(
        inventory_path,
        expected_sha256=inventory_sha256,
        label="development exclusion inventory",
    )
    try:
        inventory = Loop9DatasetExclusionInventory.from_payload(
            inventory_payload
        )
    except Loop9DatasetIsolationError as exc:
        raise LiveContractValidationError(
            "contract validation exclusion inventory is invalid"
        ) from exc
    if (
        inventory.exclusion_kind is not ExclusionKind.DEVELOPMENT
        or len(inventory.platform_identity_sha256s) != 1
        or len(inventory.image_sha256s) != 2
        or len(inventory.perceptual_fingerprints) != 2
        or inventory.scope_exclusion_tokens
        or (
            expected_identity_context_sha256 is not None
            and (
                inventory.artifact_schema_version != 2
                or inventory.identity_context_sha256
                != expected_identity_context_sha256
            )
        )
    ):
        raise LiveContractValidationError(
            "contract validation exclusion inventory is incomplete"
        )
    exclusion = _load_content_addressed_json(
        exclusion_path,
        expected_sha256=exclusion_sha256,
        label="development exclusion binding",
    )
    if (
        set(exclusion)
        != (
            _EXCLUSION_BINDING_KEYS
            if expected_identity_context_sha256 is not None
            else _LEGACY_EXCLUSION_BINDING_KEYS
        )
        or exclusion.get("schema_version")
        != (2 if expected_identity_context_sha256 is not None else 1)
        or exclusion.get("kind")
        != "loop9_live_contract_validation_exclusion"
        or exclusion.get("classification") != "development_only"
        or exclusion.get("access_window_id") != access_window_id
        or exclusion.get("build_sha256") != build_sha256
        or exclusion.get("selection_sha256") != selection_sha256
        or exclusion.get("contract_canonical_sha256")
        != contract_sha256
        or exclusion.get("source_discovery_sha256")
        != source_discovery_sha256
        or exclusion.get("inventory_sha256") != inventory_sha256
        or exclusion.get("platform_identity_count") != 1
        or exclusion.get("image_count") != 2
        or (
            expected_identity_context_sha256 is not None
            and exclusion.get("identity_context_sha256")
            != expected_identity_context_sha256
        )
        or exclusion.get("raw_platform_identity_retained") is not False
        or exclusion.get("raw_business_values_retained") is not False
        or exclusion.get("raw_image_bytes_retained") is not False
    ):
        raise LiveContractValidationError(
            "contract validation exclusion binding is invalid"
        )


def _load_content_addressed_json(
    path: Path,
    *,
    expected_sha256: str,
    label: str,
) -> dict[str, object]:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.name != f"{expected_sha256}.json"
        or path.resolve().parent != path.parent.resolve()
    ):
        raise LiveContractValidationError(
            f"contract validation {label} is unavailable"
        )
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveContractValidationError(
            f"contract validation {label} is unreadable"
        ) from exc
    if not isinstance(payload, dict):
        raise LiveContractValidationError(
            f"contract validation {label} is invalid"
        )
    canonical = payload.get("canonical_sha256")
    body = {
        key: value
        for key, value in payload.items()
        if key != "canonical_sha256"
    }
    if (
        canonical != expected_sha256
        or hashlib.sha256(_canonical(body)).hexdigest()
        != expected_sha256
    ):
        raise LiveContractValidationError(
            f"contract validation {label} integrity failed"
        )
    return payload


def _evidence_root(data_root: Path) -> Path:
    return _evidence_subdirectory(
        data_root,
        "platform-read-contract-validation",
    )


def _evidence_subdirectory(
    data_root: Path,
    name: str,
) -> Path:
    if not data_root.is_absolute() or data_root.is_symlink():
        raise LiveContractValidationError(
            "data root must be an absolute normal directory"
        )
    resolved_data_root = data_root.resolve()
    root = resolved_data_root / name
    root.mkdir(parents=True, exist_ok=True)
    resolved = root.resolve()
    if (
        resolved_data_root not in resolved.parents
        or root.is_symlink()
        or not root.is_dir()
    ):
        raise LiveContractValidationError(
            "contract validation evidence directory is unsafe"
        )
    return resolved


def _write_once(path: Path, content: bytes) -> None:
    if path.exists():
        if path.is_symlink() or path.read_bytes() != content:
            raise LiveContractValidationError(
                "contract validation evidence identity collision"
            )
        return
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise LiveContractValidationError(
            "contract validation evidence could not be written"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise LiveContractValidationError(
            "contract validation timestamp must be timezone-aware"
        )
    return value.astimezone(UTC)


def _require_sha256(value: str, *, label: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise LiveContractValidationError(
            f"{label} SHA-256 is invalid"
        )


def _require_access_window_id(value: str) -> None:
    if _ACCESS_WINDOW_ID.fullmatch(value) is None:
        raise LiveContractValidationError("access window identity is invalid")
