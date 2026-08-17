from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserReadPayload,
    BrowserRuntimeError,
)
from dahe.adapters.chengfeng.daily_contract_selection import (
    SelectedDailyReadContract,
)
from dahe.adapters.chengfeng.daily_live_adapter import (
    ChengfengDailyContractValidationSource,
    ChengfengDailyDetailEvidenceAdapter,
    ChengfengDailyListAdapter,
)
from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.domain.daily.calendar import candidate_query_window
from dahe.domain.daily.models import DailyCandidate
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    BrowserContextClosedError,
    DownloadedTicketImage,
    PageContractChangedError,
    TicketReference,
    TransientNetworkError,
    WaybillDetail,
)
from dahe.ports.daily import (
    DailyDetailCaptureContractError,
    DailyDetailCaptureState,
)
from dahe.verification.loop9_request_audit import (
    PlatformReadAuditAuthority,
    PlatformReadAuditEvidenceStore,
)
from tests.unit.platform.test_loop9_daily_manifest import daily_manifest

BUILD_SHA = "a" * 64
SETTLEMENT_CONTRACT_SHA = "b" * 64
SETTLEMENT_SELECTION_SHA = "c" * 64
DAILY_SELECTION_SHA = "d" * 64


def _authority() -> BrowserCommandAuthority:
    return BrowserCommandAuthority(
        session_id="session-1",
        instance_id="instance-1",
        worker_id="daily-worker-1",
        job_id="daily-job-1",
        control_epoch=2,
        fencing_token="private-token",
    )


class _Authorizer:
    def __init__(self) -> None:
        self.calls: list[BrowserCommandAuthority] = []

    def authorize(self, authority: BrowserCommandAuthority) -> None:
        self.calls.append(authority)


class _Browser:
    def __init__(
        self,
        *,
        content: bytes | None = None,
        error: BrowserRuntimeError | None = None,
    ) -> None:
        self.content = content
        self.error = error
        self.requests: list[object] = []

    def read_daily(self, request: object) -> BrowserReadPayload:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        assert self.content is not None
        return BrowserReadPayload(
            content=self.content,
            sha256=hashlib.sha256(self.content).hexdigest(),
            media_type="application/json",
            byte_size=len(self.content),
            status_code=200,
        )


def test_daily_list_adapter_authorizes_and_decodes_only_bounded_fields() -> None:
    content = json.dumps(
        {
            "code": 200,
            "data": {
                "total": 1,
                "list": [
                    {
                        "id": 67011222,
                        "orderItemSn": "WB-20260729-001",
                        "carNumber": "陕A12345",
                        "originalDate": "2026-07-29 15:02:03",
                        "unapprovedField": "must not survive",
                    }
                ],
            },
        },
        ensure_ascii=False,
    ).encode()
    browser = _Browser(content=content)
    authorizer = _Authorizer()
    adapter = ChengfengDailyListAdapter(
        browser=browser,  # type: ignore[arg-type]
        manifest=daily_manifest(),
        authority=_authority(),
        authorizer=authorizer,
    )
    window = candidate_query_window(
        date(2026, 7, 29),
        now=datetime.fromisoformat("2026-07-29T18:00:00+08:00"),
    )

    page = adapter.list_waybills(
        query_window=window,
        receive_place="榆林",
        page_number=1,
        page_size=100,
    )

    assert page.total == 1
    assert page.items[0].platform_waybill_id == "67011222"
    assert page.items[0].vehicle_number == "陕A12345"
    assert page.items[0].platform_loading_time == datetime.fromisoformat(
        "2026-07-29T15:02:03+08:00"
    )
    request = browser.requests[0]
    assert dict(request.parameters)["loadEndTime"] == "2026-07-29 18:00:00"
    assert authorizer.calls == [_authority(), _authority()]


def test_daily_list_adapter_records_daily_contract_request_audit(
    tmp_path: Path,
) -> None:
    content = json.dumps(
        {"code": 200, "data": {"total": 0, "list": []}}
    ).encode()
    audit_store = PlatformReadAuditEvidenceStore(tmp_path)
    adapter = ChengfengDailyListAdapter(
        browser=_Browser(content=content),  # type: ignore[arg-type]
        manifest=daily_manifest(),
        authority=_authority(),
        authorizer=_Authorizer(),
        request_audit_store=audit_store,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=DAILY_SELECTION_SHA,
    )
    adapter.list_waybills(
        query_window=candidate_query_window(
            date(2026, 7, 29),
            now=datetime.fromisoformat("2026-07-29T18:00:00+08:00"),
        ),
        receive_place="榆林",
        page_number=1,
        page_size=100,
    )

    evidence = audit_store.seal(
        job_id="daily-job-1",
        authority=PlatformReadAuditAuthority(
            build_sha256=BUILD_SHA,
            settlement_contract_sha256=SETTLEMENT_CONTRACT_SHA,
            settlement_contract_selection_sha256=(
                SETTLEMENT_SELECTION_SHA
            ),
            daily_contract_sha256=daily_manifest().canonical_sha256,
            daily_contract_selection_sha256=DAILY_SELECTION_SHA,
        ),
        purpose="daily_snapshot",
        expected_succeeded_operations={"list_daily_waybills": 1},
    )
    assert evidence.operation_counts["list_daily_waybills"].succeeded == 1


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("browser_context_closed", BrowserContextClosedError),
        ("browser_worker_timeout", TransientNetworkError),
        ("browser_read_network_failed", TransientNetworkError),
        ("browser_read_contract_changed", PageContractChangedError),
        ("browser_read_staging_failed", PageContractChangedError),
        (
            "browser_daily_probe_start_mismatch",
            PageContractChangedError,
        ),
        (
            "browser_daily_probe_cache_unavailable",
            PageContractChangedError,
        ),
        (
            "browser_daily_scope_not_applied",
            PageContractChangedError,
        ),
    ],
)
def test_daily_list_adapter_maps_worker_failures_to_technical_errors(
    code: str,
    expected: type[Exception],
) -> None:
    adapter = ChengfengDailyListAdapter(
        browser=_Browser(error=BrowserRuntimeError("failed", code=code)),  # type: ignore[arg-type]
        manifest=daily_manifest(),
        authority=_authority(),
        authorizer=_Authorizer(),
    )

    with pytest.raises(expected):
        adapter.list_waybills(
            query_window=candidate_query_window(
                date(2026, 7, 29),
                now=datetime.fromisoformat("2026-07-29T18:00:00+08:00"),
            ),
            receive_place="榆林",
            page_number=1,
            page_size=100,
        )


def test_daily_list_adapter_preserves_safe_structure_diagnostic() -> None:
    observation = {
        "method": "POST",
        "origin": "https://pc.chengfengkuaiyun.com",
        "path": "/api/hz/orderItem/queryOrderItemListPC",
        "path_sha256": None,
        "query_keys": [],
        "request_fields": [
            {"path": "$.loadEndTime", "type": "string"},
            {"path": "$.loadStartTime", "type": "string"},
            {"path": "$.pageNumber", "type": "integer"},
            {"path": "$.pageSize", "type": "integer"},
            {"path": "$.receivePlace", "type": "string"},
        ],
        "resource_kind": "json_api",
        "response_status": 200,
        "content_kind": "json",
        "response_fields": [
            {"path": "$.data.list[].id", "type": "string"},
            {"path": "$.data.list[].optionalStatus", "type": "integer"},
            {"path": "$.data.list[].sn", "type": "string"},
            {"path": "$.data.total", "type": "integer"},
        ],
    }
    adapter = ChengfengDailyListAdapter(
        browser=_Browser(
            error=BrowserRuntimeError(
                "failed",
                code="browser_daily_response_contract_changed",
                safe_discovery=(observation,),
            )
        ),  # type: ignore[arg-type]
        manifest=daily_manifest(),
        authority=_authority(),
        authorizer=_Authorizer(),
    )

    with pytest.raises(PageContractChangedError) as raised:
        adapter.list_waybills(
            query_window=candidate_query_window(
                date(2026, 7, 29),
                now=datetime.fromisoformat("2026-07-29T18:00:00+08:00"),
            ),
            receive_place="榆林",
            page_number=1,
            page_size=20,
        )

    assert raised.value.safe_discovery == (observation,)


def test_daily_shared_validation_reuses_the_discovered_one_item_page(
    tmp_path: Path,
) -> None:
    manifest = daily_manifest()

    class ValidationBrowser(_Browser):
        def prepare_daily_from_automated(self) -> dict[str, object]:
            return {
                "method": "POST",
                "origin": manifest.origin,
                "path": manifest.path,
                "path_sha256": None,
                "query_keys": ["t"],
                "request_fields": [
                    {
                        "path": f"$.{name}",
                        "type": rule.type,
                    }
                    for name, rule in manifest.request_fields.items()
                ],
                "resource_kind": "json_api",
                "response_status": 200,
                "content_kind": "json",
                "response_fields": [
                    {
                        "path": field.path,
                        "type": {
                            "$.data.list[].carNumber": "string",
                            "$.data.list[].id": "string",
                            "$.data.list[].loadPunchDate": "string",
                            "$.data.list[].sn": "string",
                            "$.data.total": "integer",
                        }[field.path],
                    }
                    for field in manifest.response_fields
                ],
            }

    content = json.dumps(
        {
            "data": {
                "total": 1,
                "list": [
                    {
                        "id": "67011222",
                        "orderItemSn": "WB-20260729-001",
                        "carNumber": "陕A12345",
                        "originalDate": "2026-07-29 15:02:03",
                    }
                ],
            }
        },
        ensure_ascii=False,
    ).encode()
    browser = ValidationBrowser(content=content)
    selected = SelectedDailyReadContract(
        manifest=manifest,
        contract_file_sha256="b" * 64,
        freeze_evidence_sha256="c" * 64,
        selection_sha256="d" * 64,
        selection_path=tmp_path / "active-candidate.json",
    )
    source = ChengfengDailyContractValidationSource(
        browser=browser,  # type: ignore[arg-type]
        selected=selected,
        authorizer=_Authorizer(),
        clock=lambda: datetime.fromisoformat(
            "2026-07-30T20:00:00+08:00"
        ),
    )

    page = source.prepare_and_list(authority=_authority())

    assert page.total == 1
    assert page.page_size == 5
    assert len(browser.requests) == 1
    request = browser.requests[0]
    assert dict(request.parameters)["pageSize"] == 5


def test_daily_shared_validation_searches_bounded_completed_days(
    tmp_path: Path,
) -> None:
    manifest = daily_manifest()

    class ValidationBrowser(_Browser):
        def __init__(self) -> None:
            super().__init__()
            self.contents = [
                json.dumps(
                    {"data": {"total": 0, "list": []}}
                ).encode(),
                json.dumps(
                    {
                        "data": {
                            "total": 1,
                            "list": [
                                {
                                    "id": "67011222",
                                    "orderItemSn": "WB-20260728-001",
                                    "carNumber": "陕A12345",
                                    "originalDate": (
                                        "2026-07-28 15:02:03"
                                    ),
                                }
                            ],
                        }
                    },
                    ensure_ascii=False,
                ).encode(),
            ]

        def prepare_daily_from_automated(self) -> dict[str, object]:
            return {
                "method": "POST",
                "origin": manifest.origin,
                "path": manifest.path,
                "path_sha256": None,
                "query_keys": ["t"],
                "request_fields": [
                    {
                        "path": f"$.{name}",
                        "type": rule.type,
                    }
                    for name, rule in manifest.request_fields.items()
                ],
                "resource_kind": "json_api",
                "response_status": 200,
                "content_kind": "json",
                "response_fields": [
                    {
                        "path": field.path,
                        "type": {
                            "$.data.list[].carNumber": "string",
                            "$.data.list[].id": "string",
                            "$.data.list[].loadPunchDate": "string",
                            "$.data.list[].sn": "string",
                            "$.data.total": "integer",
                        }[field.path],
                    }
                    for field in manifest.response_fields
                ],
            }

        def read_daily(self, request: object) -> BrowserReadPayload:
            self.requests.append(request)
            content = self.contents.pop(0)
            return BrowserReadPayload(
                content=content,
                sha256=hashlib.sha256(content).hexdigest(),
                media_type="application/json",
                byte_size=len(content),
                status_code=200,
            )

    browser = ValidationBrowser()
    audit_store = PlatformReadAuditEvidenceStore(tmp_path)
    selected = SelectedDailyReadContract(
        manifest=manifest,
        contract_file_sha256="b" * 64,
        freeze_evidence_sha256="c" * 64,
        selection_sha256="d" * 64,
        selection_path=tmp_path / "active-candidate.json",
    )
    source = ChengfengDailyContractValidationSource(
        browser=browser,  # type: ignore[arg-type]
        selected=selected,
        authorizer=_Authorizer(),
        clock=lambda: datetime.fromisoformat(
            "2026-07-30T20:00:00+08:00"
        ),
        request_audit_store=audit_store,
        build_sha256=BUILD_SHA,
    )

    page = source.prepare_and_list(authority=_authority())

    assert page.business_date == "2026-07-28"
    assert page.platform_waybill_ids == ("67011222",)
    assert len(browser.requests) == 2
    starts = [
        dict(request.parameters)["loadStartTime"]
        for request in browser.requests
    ]
    assert starts == [
        "2026-07-29 14:00:00",
        "2026-07-28 14:00:00",
    ]
    evidence = audit_store.seal(
        job_id="daily-job-1",
        authority=PlatformReadAuditAuthority(
            build_sha256=BUILD_SHA,
            settlement_contract_sha256=SETTLEMENT_CONTRACT_SHA,
            settlement_contract_selection_sha256=(
                SETTLEMENT_SELECTION_SHA
            ),
            daily_contract_sha256=manifest.canonical_sha256,
            daily_contract_selection_sha256=(
                DAILY_SELECTION_SHA
            ),
        ),
        purpose="daily_validation",
        expected_succeeded_operations={
            "list_daily_waybills": 2,
        },
    )
    assert (
        evidence.operation_counts["list_daily_waybills"].succeeded
        == 2
    )


class _Connector:
    def __init__(self) -> None:
        self.detail_calls: list[str] = []
        self.image_calls: list[str] = []
        self.ticket_capability_authority_id = "generation-1"

    def ticket_image_capability_is_current(
        self,
        ticket_ref: str,
    ) -> bool:
        return ticket_ref.startswith("opaque-")

    def get_waybill_detail(
        self,
        *,
        authority: BrowserCommandAuthority,
        platform_waybill_id: str,
    ) -> WaybillDetail:
        assert authority == _authority()
        self.detail_calls.append(platform_waybill_id)
        return WaybillDetail(
            platform_waybill_id=platform_waybill_id,
            waybill_number="WB-20260729-001",
            vehicle_number="陕A12345",
            loading_net="33.08",
            unloading_net="33.04",
            tickets=(
                TicketReference(
                    slot="loading",
                    ticket_ref="opaque-loading",
                    media_type="application/octet-stream",
                ),
                TicketReference(
                    slot="unloading",
                    ticket_ref="opaque-unloading",
                    media_type="application/octet-stream",
                ),
            ),
        )

    def download_ticket_image(
        self,
        *,
        authority: BrowserCommandAuthority,
        ticket_ref: str,
    ) -> DownloadedTicketImage:
        assert authority == _authority()
        self.image_calls.append(ticket_ref)
        content = f"image:{ticket_ref}".encode()
        return DownloadedTicketImage(
            ticket_ref=ticket_ref,
            media_type="image/jpeg",
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )


def test_daily_detail_adapter_preserves_images_and_nullable_fields(
    tmp_path: Path,
) -> None:
    connector = _Connector()
    adapter = ChengfengDailyDetailEvidenceAdapter(
        connector=connector,  # type: ignore[arg-type]
        authority=_authority(),
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
        access_window_id="access-1",
    )
    loading_time = datetime.fromisoformat("2026-07-29T15:02:03+08:00")

    evidence = adapter.observe(
        candidate=DailyCandidate(
            platform_waybill_id="67011222",
            waybill_number="WB-20260729-001",
            vehicle_number="陕A12345",
            platform_loading_time=loading_time,
        )
    )

    assert evidence.fields.loading_time is None
    assert evidence.fields.vehicle_number == "陕A12345"
    assert evidence.fields.loading_net_tonnes == Decimal("33.08")
    assert evidence.fields.unloading_net_tonnes == Decimal("33.04")
    assert evidence.fields.shipping_mine is None
    assert evidence.fields.planned_date is None
    assert evidence.fields.coal_type is None
    assert evidence.fields.unloading_place is None
    assert evidence.fields.unloading_time is None
    assert evidence.loading_ticket_sha256 == hashlib.sha256(
        b"image:opaque-loading"
    ).hexdigest()
    assert evidence.unloading_ticket_sha256 == hashlib.sha256(
        b"image:opaque-unloading"
    ).hexdigest()
    assert connector.detail_calls == ["67011222"]
    assert connector.image_calls == ["opaque-loading", "opaque-unloading"]


def test_daily_detail_adapter_rejects_duplicate_or_unknown_ticket_slots(
    tmp_path: Path,
) -> None:
    class _InvalidConnector(_Connector):
        def get_waybill_detail(
            self,
            *,
            authority: BrowserCommandAuthority,
            platform_waybill_id: str,
        ) -> WaybillDetail:
            detail = super().get_waybill_detail(
                authority=authority,
                platform_waybill_id=platform_waybill_id,
            )
            return WaybillDetail(
                platform_waybill_id=detail.platform_waybill_id,
                waybill_number=detail.waybill_number,
                vehicle_number=detail.vehicle_number,
                loading_net=detail.loading_net,
                unloading_net=detail.unloading_net,
                tickets=(
                    TicketReference(
                        slot="other",
                        ticket_ref="opaque-other",
                        media_type="application/octet-stream",
                    ),
                ),
            )

    adapter = ChengfengDailyDetailEvidenceAdapter(
        connector=_InvalidConnector(),  # type: ignore[arg-type]
        authority=_authority(),
        evidence_store=ContentAddressedEvidenceStore(tmp_path / "evidence"),
        access_window_id="access-1",
    )

    with pytest.raises(PageContractChangedError):
        adapter.observe(
            candidate=DailyCandidate(
                platform_waybill_id="67011222",
                waybill_number="WB-20260729-001",
            )
        )


def test_daily_detail_adapter_refreshes_only_missing_slot_after_restart(
    tmp_path: Path,
) -> None:
    class _GenerationConnector(_Connector):
        def __init__(self) -> None:
            super().__init__()
            self.generation = 1
            self.ticket_capability_authority_id = "generation-1"

        def get_waybill_detail(
            self,
            *,
            authority: BrowserCommandAuthority,
            platform_waybill_id: str,
        ) -> WaybillDetail:
            assert authority == _authority()
            self.detail_calls.append(platform_waybill_id)
            suffix = str(self.generation)
            return WaybillDetail(
                platform_waybill_id=platform_waybill_id,
                waybill_number="WB-20260729-001",
                vehicle_number="TEST-01",
                loading_net="33.08",
                unloading_net="33.04",
                tickets=(
                    TicketReference(
                        slot="loading",
                        ticket_ref=f"loading-{suffix}",
                        media_type="image/jpeg",
                    ),
                    TicketReference(
                        slot="unloading",
                        ticket_ref=f"unloading-{suffix}",
                        media_type="image/jpeg",
                    ),
                ),
            )

        def ticket_image_capability_is_current(
            self,
            ticket_ref: str,
        ) -> bool:
            return ticket_ref.endswith(str(self.generation))

    connector = _GenerationConnector()
    evidence_store = ContentAddressedEvidenceStore(
        tmp_path / "evidence"
    )
    candidate = DailyCandidate(
        platform_waybill_id="67011222",
        waybill_number="WB-20260729-001",
        vehicle_number="TEST-01",
    )
    first_runtime = ChengfengDailyDetailEvidenceAdapter(
        connector=connector,  # type: ignore[arg-type]
        authority=_authority(),
        evidence_store=evidence_store,
        access_window_id="access-1",
    )

    detail_step = first_runtime.advance(
        candidate=candidate,
        state=None,
    )
    loading_step = first_runtime.advance(
        candidate=candidate,
        state=detail_step.state,
    )
    restored = DailyDetailCaptureState.from_payload(
        json.loads(json.dumps(loading_step.state.to_payload()))
    )
    loading_sha = restored.ticket("loading")
    assert loading_sha is not None
    assert loading_sha.image_sha256 is not None

    connector.generation = 2
    connector.ticket_capability_authority_id = "generation-2"
    restarted_runtime = ChengfengDailyDetailEvidenceAdapter(
        connector=connector,  # type: ignore[arg-type]
        authority=_authority(),
        evidence_store=evidence_store,
        access_window_id="access-2",
    )
    refresh_step = restarted_runtime.advance(
        candidate=candidate,
        state=restored,
    )

    assert refresh_step.evidence is None
    assert connector.detail_calls == ["67011222", "67011222"]
    assert connector.image_calls == ["loading-1"]
    assert (
        refresh_step.state.ticket("loading").ticket_ref  # type: ignore[union-attr]
        == "loading-1"
    )
    assert (
        refresh_step.state.ticket("unloading").ticket_ref  # type: ignore[union-attr]
        == "unloading-2"
    )
    assert refresh_step.state.detail_read_access_window_ids == (
        "access-1",
        "access-2",
    )

    completed = restarted_runtime.advance(
        candidate=candidate,
        state=refresh_step.state,
    )

    assert completed.evidence is not None
    assert connector.image_calls == ["loading-1", "unloading-2"]
    assert completed.state.image_read_access_window_ids == (
        ("loading", "access-1"),
        ("unloading", "access-2"),
    )


def test_daily_detail_checkpoint_rejects_url_capabilities() -> None:
    payload = {
        "capability_access_window_id": "access-1",
        "capability_authority_id": "generation-1",
        "detail_read_access_window_ids": ["access-1"],
        "fields": {
            "coal_type": None,
            "loading_net_tonnes": "33.08",
            "loading_time": None,
            "planned_date": None,
            "shipping_mine": None,
            "unloading_net_tonnes": "33.04",
            "unloading_place": None,
            "unloading_time": None,
            "vehicle_number": "TEST-01",
        },
        "image_read_access_window_ids": {},
        "platform_waybill_id": "67011222",
        "schema_version": 1,
        "tickets": [
            {
                "image_sha256": None,
                "media_type": "image/jpeg",
                "slot": "loading",
                "ticket_ref": (
                    "https://example.invalid/ticket.jpg?token=secret"
                ),
            }
        ],
        "waybill_number": "WB-20260729-001",
    }

    with pytest.raises(DailyDetailCaptureContractError):
        DailyDetailCaptureState.from_payload(payload)


def test_daily_detail_checkpoint_rejects_mismatched_read_authority() -> None:
    payload = {
        "capability_access_window_id": "access-2",
        "capability_authority_id": "generation-2",
        "detail_read_access_window_ids": ["access-1"],
        "fields": {
            "coal_type": None,
            "loading_net_tonnes": "33.08",
            "loading_time": None,
            "planned_date": None,
            "shipping_mine": None,
            "unloading_net_tonnes": "33.04",
            "unloading_place": None,
            "unloading_time": None,
            "vehicle_number": "TEST-01",
        },
        "image_read_access_window_ids": {},
        "platform_waybill_id": "67011222",
        "schema_version": 1,
        "tickets": [
            {
                "image_sha256": None,
                "media_type": "image/jpeg",
                "slot": "loading",
                "ticket_ref": "loading-2",
            }
        ],
        "waybill_number": "WB-20260729-001",
    }

    with pytest.raises(DailyDetailCaptureContractError):
        DailyDetailCaptureState.from_payload(payload)
