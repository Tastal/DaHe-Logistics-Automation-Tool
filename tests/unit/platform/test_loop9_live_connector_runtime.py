from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserOperationalBatchItem,
    BrowserReadPayload,
    BrowserRuntimeError,
)
from dahe.adapters.chengfeng.live_connector_runtime import LiveConnectorRuntime
from dahe.adapters.chengfeng.live_manifest import (
    LiveAuthorizedImageRequest,
    LiveAuthorizedRequest,
    LiveReadContractManifest,
)
from dahe.adapters.chengfeng.verified_connector import VerifiedChengfengConnector
from dahe.diagnostics.runtime_log import RuntimeLogStore
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    DetailCandidateUnavailableError,
    LoginRequiredError,
    PageContractChangedError,
    TicketImageCapabilityExpiredError,
    WaybillSummary,
)
from dahe.verification.loop9_request_audit import (
    PlatformReadAuditAuthority,
    PlatformReadAuditError,
    PlatformReadAuditEvidenceStore,
)

BUILD_SHA = "d" * 64
CONTRACT_SELECTION_SHA = "c" * 64


@pytest.mark.parametrize(
    ("browser_code", "diagnostic_code"),
    (
        (
            "browser_detail_data_null_success",
            "CF-BROWSER-DETAIL-DATA-NULL-SUCCESS",
        ),
        (
            "browser_detail_cardinality_changed",
            "CF-BROWSER-DETAIL-CARDINALITY-CHANGED",
        ),
        (
            "browser_detail_identity_mismatch",
            "CF-BROWSER-DETAIL-IDENTITY-MISMATCH",
        ),
    ),
)
def test_operational_batch_keeps_safe_detail_diagnostic(
    browser_code: str,
    diagnostic_code: str,
) -> None:
    with pytest.raises(PageContractChangedError) as raised:
        LiveConnectorRuntime._raise_operational_batch_error(
            BrowserRuntimeError("safe batch failure", code=browser_code)
        )

    assert raised.value.diagnostic_code == diagnostic_code


def test_operational_batch_classifies_disappeared_candidate() -> None:
    with pytest.raises(DetailCandidateUnavailableError):
        LiveConnectorRuntime._raise_operational_batch_error(
            BrowserRuntimeError(
                "candidate detail is no longer available",
                code="browser_detail_data_null_failure",
            )
        )


def test_operational_batch_classifies_auth_null_as_login_required() -> None:
    with pytest.raises(LoginRequiredError):
        LiveConnectorRuntime._raise_operational_batch_error(
            BrowserRuntimeError(
                "detail authorization expired",
                code="browser_detail_data_null_auth",
            )
        )


class _Authorizer:
    def __init__(self) -> None:
        self.calls = 0

    def authorize(self, authority: BrowserCommandAuthority) -> None:
        assert authority.control_epoch == 1
        self.calls += 1


class _Browser:
    def __init__(self) -> None:
        self.calls: list[LiveAuthorizedRequest | LiveAuthorizedImageRequest] = []

    def read(
        self,
        request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
    ) -> BrowserReadPayload:
        self.calls.append(request)
        operation = request.operation
        if operation == "list_waybills":
            if request.request.url.endswith(
                "queryClientAllFinishSettlementOrderItemListPC"
            ):
                content = json.dumps(
                    {
                        "data": {
                            "list": [
                                {
                                    "orderItemId": "101",
                                    "orderItemSn": "WB-001",
                                    "carNumber": "TEST-01",
                                }
                            ],
                            "total": "1",
                        }
                    }
                ).encode()
            else:
                content = json.dumps(
                    {
                        "data": {
                            "list": [
                                {
                                    "id": "101",
                                    "orderItemSn": "WB-001",
                                    "carNumber": "TEST-01",
                                }
                            ],
                            "pageNo": 1,
                            "pageSize": 30,
                            "total": 1,
                        }
                    }
                ).encode()
            media_type = "application/json"
        elif operation == "get_waybill_detail":
            content = json.dumps(
                {
                    "data": [
                        {
                            "id": "101",
                            "sn": "WB-001",
                            "carNumber": "TEST-01",
                            "originalTon": "30.00",
                            "currentTon": "29.80",
                            "originalTonImageUrl": (
                                "https://images.example.invalid/loading.jpg"
                                "?signature=loading-secret"
                            ),
                            "image": (
                                "https://images.example.invalid/unloading.jpg"
                                "?signature=unloading-secret"
                            ),
                        }
                    ]
                }
            ).encode()
            media_type = "application/json"
        else:
            content = b"\xff\xd8\xff\xe0synthetic-jpeg\xff\xd9"
            media_type = "image/jpeg"
        import hashlib

        return BrowserReadPayload(
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            media_type=media_type,
            byte_size=len(content),
            status_code=200,
        )


def _manifest() -> LiveReadContractManifest:
    return LiveReadContractManifest.model_validate_json(
        json.dumps(
            {
            "schema_version": 1,
            "contract_kind": "loop9_read_only",
            "run_mode": "shadow",
            "origin": "https://platform.example.invalid",
            "image_origins": ["https://images.example.invalid"],
            "source_discovery_sha256": "a" * 64,
            "source_observation_count": 5,
            "requests": [
                {
                    "operation": "list_waybills",
                    "method": "POST",
                    "path": (
                        "/api/order-center-server/app/clientOrderItem/"
                        "queryWaitSettlementOrderItemListPC"
                    ),
                    "parameters_location": "json",
                    "parameters": {
                        "pageNumber": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 10000,
                        },
                        "pageSize": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                        },
                        "order": {"type": "string", "allow_empty": True},
                        "settleQueryType": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 10000,
                        },
                    },
                    "response_fields": [
                        {"path": "$.data.list[].id", "types": ["string"]}
                    ],
                },
                {
                    "operation": "get_waybill_detail",
                    "method": "POST",
                    "path": (
                        "/api/order-center-server/app/clientOrderItem/"
                        "getOrderItemDetailsByIdPC"
                    ),
                    "parameters_location": "form",
                    "parameters": {"id": {"type": "string", "allow_empty": True}},
                    "response_fields": [
                        {"path": "$.data[].id", "types": ["string"]}
                    ],
                },
                {
                    "operation": "download_ticket_image",
                    "method": "GET",
                    "path": "/__response-derived-ticket-image__",
                    "parameters_location": "query",
                    "parameters": {"ticket_ref": {"type": "string"}},
                    "response_fields": [],
                },
            ],
            }
        ),
        strict=True,
    )


def _authority() -> BrowserCommandAuthority:
    return BrowserCommandAuthority(
        session_id="session-one",
        instance_id="instance-one",
        worker_id="worker-one",
        job_id="job-one",
        control_epoch=1,
        fencing_token="fencing-token-one",
    )


def test_live_runtime_uses_existing_verified_connector_and_opaque_ticket_refs(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )
    authority = _authority()

    page = connector.list_waybills(
        authority=authority,
        scope="current",
        page_number=1,
        page_size=30,
    )
    detail = connector.get_waybill_detail(
        authority=authority,
        platform_waybill_id="101",
    )

    assert page.items[0].waybill_number == "WB-001"
    assert detail.loading_net == "30.00"
    assert detail.unloading_net == "29.80"
    assert len(detail.tickets) == 2
    serialized = json.dumps(
        [ticket.ticket_ref for ticket in detail.tickets],
        ensure_ascii=False,
    )
    assert "https://" not in serialized
    assert "signature" not in serialized
    assert "secret" not in serialized
    assert browser.calls[0].request.parameters["order"] == "desc"
    assert browser.calls[0].request.parameters["settleQueryType"] == 1

    loading = connector.download_ticket_image(
        authority=authority,
        ticket_ref=detail.tickets[0].ticket_ref,
    )
    assert loading.media_type == "image/jpeg"
    assert loading.content.startswith(b"\xff\xd8\xff")
    image_request = browser.calls[-1]
    assert isinstance(image_request, LiveAuthorizedImageRequest)
    assert image_request.url_sha256
    assert authorizer.calls >= 9
    audit = PlatformReadAuditEvidenceStore(tmp_path).seal(
        job_id=authority.job_id,
        authority=PlatformReadAuditAuthority(
            build_sha256=BUILD_SHA,
            settlement_contract_sha256=_manifest().canonical_sha256,
            settlement_contract_selection_sha256=(
                CONTRACT_SELECTION_SHA
            ),
        ),
        purpose="real_shadow_30",
        expected_succeeded_operations={
            "list_waybills": 1,
            "get_waybill_detail": 1,
            "download_ticket_image": 1,
        },
    )
    assert audit.request_counts.succeeded == 3


def test_operational_batch_audits_private_detail_and_image_outcomes(
    tmp_path: Path,
) -> None:
    class BatchBrowser(_Browser):
        def read_operational_batch(
            self,
            requests: tuple[tuple[str, LiveAuthorizedRequest], ...],
            *,
            detail_concurrency: int,
            image_concurrency: int,
            active_job_id: str | None = None,
            progress_callback: object | None = None,
        ) -> tuple[BrowserOperationalBatchItem, ...]:
            assert detail_concurrency == 4
            assert image_concurrency == 6
            assert active_job_id is None
            assert progress_callback is None
            assert [identity for identity, _request in requests] == ["101"]
            detail_content = json.dumps(
                {
                    "data": [
                        {
                            "id": "101",
                            "sn": "WB-001",
                            "carNumber": "TEST-01",
                            "originalTon": "30.00",
                            "currentTon": "29.80",
                            "originalTonImageUrl": "worker-image:loading",
                            "image": "worker-image:unloading",
                        }
                    ]
                }
            ).encode()
            detail = BrowserReadPayload(
                content=detail_content,
                sha256=hashlib.sha256(detail_content).hexdigest(),
                media_type="application/json",
                byte_size=len(detail_content),
                status_code=200,
            )
            image = BrowserReadPayload(
                content=b"\xff\xd8\xff\xe0synthetic-jpeg\xff\xd9",
                sha256=hashlib.sha256(
                    b"\xff\xd8\xff\xe0synthetic-jpeg\xff\xd9"
                ).hexdigest(),
                media_type="image/jpeg",
                byte_size=len(b"\xff\xd8\xff\xe0synthetic-jpeg\xff\xd9"),
                status_code=200,
            )
            return (
                    BrowserOperationalBatchItem(
                        platform_waybill_id="101",
                        source_revision_sha256=("a" * 64),
                        detail=detail,
                    images=(("loading", image), ("unloading", image)),
                ),
            )

    browser = BatchBrowser()
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=browser,  # type: ignore[arg-type]
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )

    result = connector.read_waybill_batch(
        authority=_authority(),
        summaries=(
            WaybillSummary(
                platform_waybill_id="101",
                waybill_number="WB-001",
                vehicle_number="TEST-01",
            ),
        ),
        detail_concurrency=4,
        image_concurrency=6,
    )

    assert len(result) == 1
    audit = PlatformReadAuditEvidenceStore(tmp_path).seal(
        job_id="job-one",
        authority=PlatformReadAuditAuthority(
            build_sha256=BUILD_SHA,
            settlement_contract_sha256=_manifest().canonical_sha256,
            settlement_contract_selection_sha256=CONTRACT_SELECTION_SHA,
        ),
        purpose="operational_settlement",
        expected_succeeded_operations={
            "get_waybill_detail": 1,
            "download_ticket_image": 2,
        },
    )
    assert audit.request_counts.succeeded == 3


def test_live_runtime_decodes_the_distinct_historical_list_contract(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    authorizer = _Authorizer()
    connector = VerifiedChengfengConnector(
        runtime=LiveConnectorRuntime(
            browser=browser,
            manifest=_manifest(),
            data_root=tmp_path,
            authorizer=authorizer,
            build_sha256=BUILD_SHA,
            contract_selection_sha256=CONTRACT_SELECTION_SHA,
            clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
        ),
        data_root=tmp_path,
        authorizer=authorizer,
    )

    page = connector.list_waybills(
        authority=_authority(),
        scope="settled_history",
        page_number=1,
        page_size=100,
    )

    assert page.total == 1
    assert page.items[0].platform_waybill_id == "101"
    request = browser.calls[0]
    assert request.request.url.endswith(
        "queryClientAllFinishSettlementOrderItemListPC"
    )
    assert dict(request.request.parameters) == {
        "deptCode": "",
        "pageNumber": 1,
        "pageSize": 100,
        "sortParams": (),
    }


def test_live_runtime_generated_ticket_refs_cannot_look_like_phone_numbers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeUuid:
        def __init__(self, value: str) -> None:
            self.hex = value

    values = iter(
        (
            "a" * 32,
            "b" * 32,
            "c" * 32,
            "aa13812345678" + "b" * 19,
            "d" * 32,
            "e" * 32,
        )
    )
    monkeypatch.setattr(
        "dahe.adapters.chengfeng.live_connector_runtime.uuid4",
        lambda: FakeUuid(next(values)),
    )
    browser = _Browser()
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )

    detail = connector.get_waybill_detail(
        authority=_authority(),
        platform_waybill_id="101",
    )
    unloading = connector.download_ticket_image(
        authority=_authority(),
        ticket_ref=detail.tickets[1].ticket_ref,
    )

    assert unloading.content.startswith(b"\xff\xd8\xff")
    assert detail.tickets[1].ticket_ref.isascii()
    assert not any(character.isdigit() for character in detail.tickets[1].ticket_ref)


def test_live_runtime_logs_safe_payload_reason_and_classifies_contract_change(
    tmp_path: Path,
) -> None:
    class PaginationMismatchBrowser(_Browser):
        def read(
            self,
            request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
        ) -> BrowserReadPayload:
            payload = super().read(request)
            if request.operation != "list_waybills":
                return payload
            content = json.dumps(
                {
                    "data": {
                        "list": [],
                        "pageNo": 2,
                        "pageSize": 30,
                        "total": 0,
                    }
                }
            ).encode()
            import hashlib

            return BrowserReadPayload(
                content=content,
                sha256=hashlib.sha256(content).hexdigest(),
                media_type="application/json",
                byte_size=len(content),
                status_code=200,
            )

    store = RuntimeLogStore(tmp_path / "logs")
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=PaginationMismatchBrowser(),
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
        runtime_log_store=store,
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )

    with pytest.raises(PageContractChangedError):
        connector.list_waybills(
            authority=_authority(),
            scope="current",
            page_number=1,
            page_size=30,
        )

    events = store.query(source="chengfeng-connector", limit=10)["events"]
    assert len(events) == 1
    assert events[0]["event_code"] == "read_response_contract_changed"
    assert events[0]["diagnostic_code"] == "CF-LIVE-PAYLOAD-PAGINATION-MISMATCH"
    assert events[0]["message"] == (
        "Frozen Chengfeng read failed safely at list_query "
        "(pagination_mismatch)."
    )


def test_live_runtime_classifies_private_list_body_mismatch_as_contract_change(
    tmp_path: Path,
) -> None:
    class BodyMismatchBrowser(_Browser):
        def read(
            self,
            request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
        ) -> BrowserReadPayload:
            raise BrowserRuntimeError(
                "private list baseline changed",
                code="browser_session_list_body_fields_added",
                safe_discovery=(
                    {
                        "request_fields": [
                            {"path": "$.pageNumber", "type": "integer"},
                            {"path": "$.pageSize", "type": "integer"},
                        ]
                    },
                ),
            )

    authorizer = _Authorizer()
    store = RuntimeLogStore(tmp_path / "logs")
    runtime = LiveConnectorRuntime(
        browser=BodyMismatchBrowser(),
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
        runtime_log_store=store,
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )

    with pytest.raises(PageContractChangedError):
        connector.list_waybills(
            authority=_authority(),
            scope="current",
            page_number=1,
            page_size=30,
        )

    events = store.query(source="chengfeng-connector", limit=10)["events"]
    assert len(events) == 2
    structure_event = next(
        event
        for event in events
        if event["event_code"] == "read_request_structure_changed"
    )
    assert structure_event["message"].startswith(
        "Current locally reset Chengfeng list field paths: "
        "$.pageNumber,$.pageSize."
    )
    assert structure_event["diagnostic_code"] == (
        "CF-BROWSER-SESSION-LIST-BODY-FIELDS-ADDED"
    )
    diagnostics = tuple(
        (tmp_path / "platform-contract-diagnostics").glob("*.json")
    )
    assert len(diagnostics) == 1
    diagnostic = json.loads(diagnostics[0].read_text(encoding="utf-8"))
    assert diagnostic["kind"] == (
        "chengfeng_reset_list_structure_diagnostic"
    )
    assert diagnostic["request_values_retained"] is False


def test_live_runtime_rejects_unknown_or_expired_ticket_reference(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    authorizer = _Authorizer()
    now = datetime(2026, 7, 29, 8, 0, tzinfo=UTC)
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: now,
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )

    try:
        connector.download_ticket_image(
            authority=_authority(),
            ticket_ref="ticket-unknown",
        )
    except TicketImageCapabilityExpiredError:
        pass
    else:
        raise AssertionError("unknown ticket reference was accepted")

    assert not browser.calls


def test_live_runtime_rejects_ticket_ref_from_destroyed_runtime(
    tmp_path: Path,
) -> None:
    authorizer = _Authorizer()
    first = VerifiedChengfengConnector(
        runtime=LiveConnectorRuntime(
            browser=_Browser(),
            manifest=_manifest(),
            data_root=tmp_path,
            authorizer=authorizer,
            build_sha256=BUILD_SHA,
            contract_selection_sha256=CONTRACT_SELECTION_SHA,
            clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
        ),
        data_root=tmp_path,
        authorizer=authorizer,
    )
    detail = first.get_waybill_detail(
        authority=_authority(),
        platform_waybill_id="101",
    )
    stale_ref = detail.tickets[0].ticket_ref
    del first
    replacement_browser = _Browser()
    replacement = VerifiedChengfengConnector(
        runtime=LiveConnectorRuntime(
            browser=replacement_browser,
            manifest=_manifest(),
            data_root=tmp_path,
            authorizer=authorizer,
            build_sha256=BUILD_SHA,
            contract_selection_sha256=CONTRACT_SELECTION_SHA,
            clock=lambda: datetime(2026, 7, 29, 8, 1, tzinfo=UTC),
        ),
        data_root=tmp_path,
        authorizer=authorizer,
    )

    with pytest.raises(TicketImageCapabilityExpiredError):
        replacement.download_ticket_image(
            authority=_authority(),
            ticket_ref=stale_ref,
        )

    assert replacement_browser.calls == []


def test_live_runtime_invalidates_ticket_ref_after_browser_generation_changes(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    browser.capability_generation_id = "browser-generation-one"
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )
    detail = connector.get_waybill_detail(
        authority=_authority(),
        platform_waybill_id="101",
    )
    ticket_ref = detail.tickets[0].ticket_ref
    original_authority_id = connector.ticket_capability_authority_id

    assert connector.ticket_image_capability_is_current(ticket_ref) is True

    browser.capability_generation_id = "browser-generation-two"

    assert connector.ticket_capability_authority_id != original_authority_id
    assert connector.ticket_image_capability_is_current(ticket_ref) is False
    with pytest.raises(TicketImageCapabilityExpiredError):
        connector.download_ticket_image(
            authority=_authority(),
            ticket_ref=ticket_ref,
        )
    assert [
        request.operation for request in browser.calls
    ] == ["get_waybill_detail"]


def test_live_runtime_marks_near_expiry_ticket_ref_not_current(
    tmp_path: Path,
) -> None:
    now = [datetime(2026, 7, 29, 8, 0, tzinfo=UTC)]
    browser = _Browser()
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: now[0],
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )
    detail = connector.get_waybill_detail(
        authority=_authority(),
        platform_waybill_id="101",
    )
    ticket_ref = detail.tickets[0].ticket_ref

    assert connector.ticket_image_capability_is_current(ticket_ref) is True

    now[0] = datetime(2026, 7, 29, 8, 4, 56, tzinfo=UTC)

    assert connector.ticket_image_capability_is_current(ticket_ref) is False


def test_live_runtime_audits_unknown_operation_as_denied_before_network(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
    )
    payload = json.loads(
        json.dumps(
            {
                "protocol_version": 1,
                "command_id": "unknown-operation",
                "operation": "confirm_settlement",
                "authority": {
                    "session_id": "session-one",
                    "instance_id": "instance-one",
                    "worker_id": "worker-one",
                    "job_id": "job-unknown",
                    "control_epoch": 1,
                    "fencing_token": "fencing-token-one",
                },
                "parameters": {},
                "credential_reference": None,
            }
        )
    )

    with pytest.raises(ValueError):
        runtime.execute(json.dumps(payload) + "\n")

    assert browser.calls == []
    with pytest.raises(PlatformReadAuditError, match="not clean"):
        PlatformReadAuditEvidenceStore(tmp_path).seal(
            job_id="job-unknown",
            authority=PlatformReadAuditAuthority(
                build_sha256=BUILD_SHA,
                settlement_contract_sha256=_manifest().canonical_sha256,
                settlement_contract_selection_sha256=(
                    CONTRACT_SELECTION_SHA
                ),
            ),
            purpose="real_shadow_30",
            expected_succeeded_operations={},
        )
    serialized = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "platform-request-audit").rglob("*.json")
    )
    assert "confirm_settlement" not in serialized
    assert '"operation":"unsafe_operation"' in serialized


@pytest.mark.parametrize(
    "browser_error_code",
    (
        "browser_image_not_registered",
        "browser_image_origin_denied",
    ),
)
def test_live_runtime_audits_worker_image_policy_denial_before_network(
    tmp_path: Path,
    browser_error_code: str,
) -> None:
    class ImagePolicyDenyBrowser(_Browser):
        def read(
            self,
            request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
        ) -> BrowserReadPayload:
            if request.operation == "download_ticket_image":
                self.calls.append(request)
                raise BrowserRuntimeError(
                    "image policy denied before network",
                    code=browser_error_code,
                )
            return super().read(request)

    browser = ImagePolicyDenyBrowser()
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )
    authority = _authority()
    detail = connector.get_waybill_detail(
        authority=authority,
        platform_waybill_id="101",
    )

    with pytest.raises(PageContractChangedError):
        connector.download_ticket_image(
            authority=authority,
            ticket_ref=detail.tickets[0].ticket_ref,
        )

    events = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(
            (
                tmp_path
                / "platform-request-audit"
                / "events"
            ).rglob("*.json")
        )
    ]
    image_phases = [
        event["phase"]
        for event in events
        if event["operation"] == "download_ticket_image"
    ]
    assert image_phases == ["attempted", "denied"]
    with pytest.raises(PlatformReadAuditError, match="not clean"):
        PlatformReadAuditEvidenceStore(tmp_path).seal(
            job_id=authority.job_id,
            authority=PlatformReadAuditAuthority(
                build_sha256=BUILD_SHA,
                settlement_contract_sha256=(
                    _manifest().canonical_sha256
                ),
                settlement_contract_selection_sha256=(
                    CONTRACT_SELECTION_SHA
                ),
            ),
            purpose="real_shadow_30",
            expected_succeeded_operations={
                "get_waybill_detail": 1,
            },
        )


def test_live_runtime_classifies_worker_redirect_in_request_audit(
    tmp_path: Path,
) -> None:
    class RedirectBrowser(_Browser):
        def read(
            self,
            request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
        ) -> BrowserReadPayload:
            self.calls.append(request)
            raise BrowserRuntimeError(
                "redirect rejected",
                code="browser_read_redirect_rejected",
            )

    browser = RedirectBrowser()
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )

    with pytest.raises(PageContractChangedError):
        connector.list_waybills(
            authority=_authority(),
            scope="current",
            page_number=1,
            page_size=30,
        )

    with pytest.raises(PlatformReadAuditError, match="not clean"):
        PlatformReadAuditEvidenceStore(tmp_path).seal(
            job_id="job-one",
            authority=PlatformReadAuditAuthority(
                build_sha256=BUILD_SHA,
                settlement_contract_sha256=_manifest().canonical_sha256,
                settlement_contract_selection_sha256=(
                    CONTRACT_SELECTION_SHA
                ),
            ),
            purpose="real_shadow_30",
            expected_succeeded_operations={},
        )
    serialized = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "platform-request-audit" / "events").rglob(
            "*.json"
        )
    )
    assert '"phase":"redirect"' in serialized


def test_live_runtime_preserves_safe_detail_contract_diagnostic(
    tmp_path: Path,
) -> None:
    class DetailContractBrowser(_Browser):
        def read(
            self,
            request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
        ) -> BrowserReadPayload:
            self.calls.append(request)
            raise BrowserRuntimeError(
                "detail response shape changed",
                code="browser_detail_data_null_success",
            )

    browser = DetailContractBrowser()
    authorizer = _Authorizer()
    log_store = RuntimeLogStore(tmp_path / "logs")
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
        runtime_log_store=log_store,
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )

    with pytest.raises(PageContractChangedError) as raised:
        connector.get_waybill_detail(
            authority=_authority(),
            platform_waybill_id="101",
        )

    assert raised.value.diagnostic_code == "CF-PAGE-CONTRACT-CHANGED"
    events = log_store.query(
        source="chengfeng-connector",
        limit=10,
    )["events"]
    assert events[-1]["diagnostic_code"] == (
        "CF-BROWSER-DETAIL-DATA-NULL-SUCCESS"
    )


def test_live_runtime_treats_failed_null_detail_as_bounded_candidate_absence(
    tmp_path: Path,
) -> None:
    class MissingCandidateBrowser(_Browser):
        def read(
            self,
            request: LiveAuthorizedRequest | LiveAuthorizedImageRequest,
        ) -> BrowserReadPayload:
            self.calls.append(request)
            raise BrowserRuntimeError(
                "candidate detail is no longer available",
                code="browser_detail_data_null_failure",
            )

    browser = MissingCandidateBrowser()
    authorizer = _Authorizer()
    runtime = LiveConnectorRuntime(
        browser=browser,
        manifest=_manifest(),
        data_root=tmp_path,
        authorizer=authorizer,
        build_sha256=BUILD_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        clock=lambda: datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
    )
    connector = VerifiedChengfengConnector(
        runtime=runtime,
        data_root=tmp_path,
        authorizer=authorizer,
    )

    with pytest.raises(DetailCandidateUnavailableError):
        connector.get_waybill_detail(
            authority=_authority(),
            platform_waybill_id="101",
        )

    events = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(
            (
                tmp_path
                / "platform-request-audit"
                / "events"
            ).rglob("*.json")
        )
    ]
    assert [event["phase"] for event in events] == [
        "attempted",
        "allowed",
        "succeeded",
    ]
