from __future__ import annotations

import json
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image

from dahe.adapters.chengfeng.browser_runtime import SettlementListProbe
from dahe.adapters.chengfeng.daily_contract_selection import (
    SelectedDailyReadContract,
)
from dahe.adapters.chengfeng.live_contract_selection import (
    SelectedLiveReadContract,
)
from dahe.adapters.chengfeng.live_contract_validation import (
    DailyContractValidationCandidatePage,
    LiveContractValidationError,
    LiveContractValidationRunner,
)
from dahe.adapters.chengfeng.live_manifest import LiveReadContractManifest
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    DetailCandidateUnavailableError,
    DownloadedTicketImage,
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)
from dahe.verification.loop9_dataset_artifacts import (
    identity_context_sha256,
    platform_waybill_identity_digest,
)
from dahe.verification.loop9_dataset_isolation import (
    load_loop9_exclusion_inventory,
)
from tests.unit.platform.test_loop9_daily_manifest import daily_manifest

IDENTITY_KEY = b"loop9-live-validation-test-identity-key"
IDENTITY_NAMESPACE = "chengfeng:waybill"


class FakeConnector:
    def __init__(
        self,
        *,
        include_two_images: bool = True,
        empty_list_attempts: int = 0,
    ) -> None:
        self.include_two_images = include_two_images
        self.empty_list_attempts = empty_list_attempts
        self.calls: list[str] = []

    def list_waybills(
        self,
        *,
        authority: BrowserCommandAuthority,
        scope: str,
        page_number: int,
        page_size: int,
    ) -> WaybillPage:
        del authority
        self.calls.append(f"list:{scope}:{page_number}:{page_size}")
        if self.empty_list_attempts > 0:
            self.empty_list_attempts -= 1
            return WaybillPage(
                page_number=1,
                page_size=20,
                total=0,
                items=(),
            )
        return WaybillPage(
            page_number=1,
            page_size=20,
            total=1,
            items=(WaybillSummary("67011222", "secret-waybill", "secret-car"),),
        )

    def get_waybill_detail(
        self,
        *,
        authority: BrowserCommandAuthority,
        platform_waybill_id: str,
    ) -> WaybillDetail:
        del authority
        self.calls.append(f"detail:{platform_waybill_id}")
        tickets = [TicketReference("loading", "opaque-loading", "image/jpeg")]
        if self.include_two_images:
            tickets.append(
                TicketReference("unloading", "opaque-unloading", "image/jpeg")
            )
        return WaybillDetail(
            platform_waybill_id=platform_waybill_id,
            waybill_number="secret-waybill",
            vehicle_number="secret-car",
            loading_net="33.08",
            unloading_net="33.04",
            tickets=tuple(tickets),
        )

    def download_ticket_image(
        self,
        *,
        authority: BrowserCommandAuthority,
        ticket_ref: str,
    ) -> DownloadedTicketImage:
        del authority
        self.calls.append(f"image:{ticket_ref}")
        output = BytesIO()
        color = (
            (40, 80, 120)
            if ticket_ref == "opaque-loading"
            else (120, 80, 40)
        )
        Image.new("RGB", (32, 24), color).save(output, format="JPEG")
        content = output.getvalue()
        import hashlib

        return DownloadedTicketImage(
            ticket_ref=ticket_ref,
            media_type="image/jpeg",
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )


class FakeDailyValidationSource:
    def __init__(
        self,
        tmp_path: Path,
        *,
        empty: bool = False,
        selection_sha256: str = "8" * 64,
        read_attempt_count: int = 1,
    ) -> None:
        self.selected = SelectedDailyReadContract(
            manifest=daily_manifest(),
            contract_file_sha256="5" * 64,
            freeze_evidence_sha256="6" * 64,
            selection_sha256=selection_sha256,
            selection_path=tmp_path / "daily-selection.json",
        )
        self.empty = empty
        self.read_attempt_count = read_attempt_count
        self.calls: list[BrowserCommandAuthority] = []

    def prepare_and_list(
        self,
        *,
        authority: BrowserCommandAuthority,
    ) -> DailyContractValidationCandidatePage:
        self.calls.append(authority)
        return DailyContractValidationCandidatePage(
            business_date="2026-07-28",
            query_scope_sha256="7" * 64,
            page_number=1,
            page_size=20,
            total=0 if self.empty else 1,
            platform_waybill_ids=(
                () if self.empty else ("daily-secret-platform-id",)
            ),
            read_attempt_count=self.read_attempt_count,
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
                    "path": "/api/list",
                    "parameters_location": "json",
                    "parameters": {"pageNo": {"type": "integer", "minimum": 1}},
                    "response_fields": [{"path": "$.data", "types": ["string"]}],
                },
                {
                    "operation": "get_waybill_detail",
                    "method": "POST",
                    "path": "/api/detail",
                    "parameters_location": "json",
                    "parameters": {"id": {"type": "string"}},
                    "response_fields": [{"path": "$.data", "types": ["string"]}],
                },
                {
                    "operation": "download_ticket_image",
                    "method": "GET",
                    "path": "/object",
                    "parameters_location": "query",
                    "parameters": {"signature": {"type": "string"}},
                    "response_fields": [],
                },
            ],
            }
        )
    )


def _selected(tmp_path: Path) -> SelectedLiveReadContract:
    return SelectedLiveReadContract(
        manifest=_manifest(),
        contract_file_sha256="b" * 64,
        freeze_evidence_sha256="c" * 64,
        selection_sha256="d" * 64,
        selection_path=tmp_path / "selection.json",
    )


def _authority() -> BrowserCommandAuthority:
    return BrowserCommandAuthority(
        session_id="session",
        instance_id="instance",
        worker_id="worker",
        job_id="job",
        control_epoch=1,
        fencing_token="token",
    )


def test_validation_keeps_only_sanitized_counts_and_image_hashes(
    tmp_path: Path,
) -> None:
    connector = FakeConnector()
    runner = LiveContractValidationRunner(
        connector=connector,
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
    )
    result = runner.validate(
        authority=_authority(),
        access_window_id="Window_1-AbC",
        build_sha256="e" * 64,
    )

    document = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    serialized = json.dumps(document, ensure_ascii=False)
    assert result.image_count == 2
    assert result.development_exclusion_sha256 is not None
    assert result.development_exclusion_inventory_sha256 is not None
    assert result.detail_attempt_count == 1
    assert document["platform_write_request_count"] == 0
    assert document["forbidden_request_count"] == 0
    assert "secret-waybill" not in serialized
    assert "secret-car" not in serialized
    assert "67011222" not in serialized
    assert "33.08" not in serialized
    assert "33.04" not in serialized
    assert "opaque-loading" not in serialized
    assert runner.has_successful_validation("e" * 64) is True
    assert runner.has_successful_validation("f" * 64) is False

    exclusion_root = tmp_path / "loop9-development-exclusions"
    exclusion_files = tuple(exclusion_root.glob("*.json"))
    assert len(exclusion_files) == 1
    exclusion_text = exclusion_files[0].read_text(encoding="utf-8")
    assert "secret-waybill" not in exclusion_text
    assert "secret-car" not in exclusion_text
    assert "67011222" not in exclusion_text
    assert "opaque-loading" not in exclusion_text
    inventory = load_loop9_exclusion_inventory(exclusion_files[0].resolve())
    assert inventory.identity_context_sha256 == identity_context_sha256(
        salt=IDENTITY_KEY,
        namespace=IDENTITY_NAMESPACE,
    )
    assert inventory.platform_identity_sha256s == (
        platform_waybill_identity_digest(
            salt=IDENTITY_KEY,
            namespace=IDENTITY_NAMESPACE,
            source_identity="67011222",
        ),
    )

    replay = runner.validate(
        authority=_authority(),
        access_window_id="Window_1-AbC",
        build_sha256="e" * 64,
    )
    assert replay.canonical_sha256 == result.canonical_sha256
    assert connector.calls.count("list:current:1:20") == 1


def test_validation_binds_matching_page_native_probe_without_business_values(
    tmp_path: Path,
) -> None:
    runner = LiveContractValidationRunner(
        connector=FakeConnector(),
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
    )

    result = runner.validate(
        authority=_authority(),
        access_window_id="window-native",
        build_sha256="e" * 64,
        settlement_probe=SettlementListProbe(
            total_count=1,
            list_length=1,
            page_number=1,
            page_size=30,
            response_structure_sha256="f" * 64,
        ),
    )

    document = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    assert document["page_native_probe"] == {
        "total_count": 1,
        "list_length": 1,
        "page_number": 1,
        "page_size": 30,
        "response_structure_sha256": "f" * 64,
    }
    assert "secret-waybill" not in json.dumps(document)


def test_validation_rejects_page_native_and_direct_replay_count_mismatch(
    tmp_path: Path,
) -> None:
    runner = LiveContractValidationRunner(
        connector=FakeConnector(),
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
    )

    with pytest.raises(LiveContractValidationError) as raised:
        runner.validate(
            authority=_authority(),
            access_window_id="window-native",
            build_sha256="e" * 64,
            settlement_probe=SettlementListProbe(
                total_count=2,
                list_length=2,
                page_number=1,
                page_size=30,
                response_structure_sha256="f" * 64,
            ),
        )

    assert raised.value.code == "page_native_replay_mismatch"
    assert not tuple(
        (tmp_path / "platform-read-contract-validation").glob("*.json")
    )


def test_validation_fails_when_no_detail_has_both_ticket_images(
    tmp_path: Path,
) -> None:
    runner = LiveContractValidationRunner(
        connector=FakeConnector(include_two_images=False),
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
    )
    with pytest.raises(
        LiveContractValidationError,
        match="both ticket images",
    ):
        runner.validate(
            authority=_authority(),
            access_window_id="window-1",
            build_sha256="e" * 64,
        )
    assert not tuple(
        (tmp_path / "platform-read-contract-validation").glob("*.json")
    )


def test_validation_confirms_an_initial_empty_list_before_continuing(
    tmp_path: Path,
) -> None:
    connector = FakeConnector(empty_list_attempts=1)
    runner = LiveContractValidationRunner(
        connector=connector,
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
    )

    result = runner.validate(
        authority=_authority(),
        access_window_id="window-1",
        build_sha256="e" * 64,
    )

    document = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    assert connector.calls.count("list:current:1:20") == 2
    assert document["operation_counts"]["list_waybills"] == 2
    assert document["list_empty_confirmation_performed"] is True


def test_validation_stops_after_two_empty_list_results(tmp_path: Path) -> None:
    connector = FakeConnector(empty_list_attempts=2)
    runner = LiveContractValidationRunner(
        connector=connector,
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
    )

    with pytest.raises(LiveContractValidationError) as raised:
        runner.validate(
            authority=_authority(),
            access_window_id="window-1",
            build_sha256="e" * 64,
        )

    assert raised.value.code == "pending_list_empty_confirmed"
    assert connector.calls.count("list:current:1:20") == 2
    empty_evidence = tuple(
        (
            tmp_path
            / "platform-read-contract-validation-settlement-empty"
        ).glob("*.json")
    )
    assert len(empty_evidence) == 1
    empty_document = json.loads(
        empty_evidence[0].read_text(encoding="utf-8")
    )
    assert empty_document["read_count"] == 2
    assert empty_document["read_item_counts"] == [0, 0]
    assert empty_document["empty_confirmed"] is True
    assert not tuple(
        (tmp_path / "platform-read-contract-validation").glob("*.json")
    )


def test_two_empty_settlement_reads_can_use_nonempty_daily_shared_transport(
    tmp_path: Path,
) -> None:
    connector = FakeConnector(empty_list_attempts=2)
    daily = FakeDailyValidationSource(
        tmp_path,
        read_attempt_count=2,
    )
    runner = LiveContractValidationRunner(
        connector=connector,
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
        daily_source=daily,
    )

    result = runner.validate(
        authority=_authority(),
        access_window_id="window-composite",
        build_sha256="e" * 64,
        settlement_probe=SettlementListProbe(
            total_count=0,
            list_length=0,
            page_number=1,
            page_size=30,
            response_structure_sha256="f" * 64,
        ),
    )

    document = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    assert document["schema_version"] == 4
    assert (
        document["validation_mode"]
        == "settlement_empty_daily_nonempty"
    )
    assert document["list_item_count"] == 0
    assert document["daily_list_item_count"] == 1
    assert document["operation_counts"]["list_daily_waybills"] == 2
    assert document["daily_contract_selection_sha256"] == "8" * 64
    assert document["settlement_empty_evidence_sha256"]
    assert document["shared_detail_image_validation_sha256"]
    assert len(daily.calls) == 1
    assert "detail:daily-secret-platform-id" in connector.calls
    assert runner.has_successful_validation("e" * 64) is True
    serialized = json.dumps(document, ensure_ascii=False)
    assert "daily-secret-platform-id" not in serialized

    shared_path = (
        tmp_path
        / "platform-read-contract-shared-validation"
        / (
            f"{document['shared_detail_image_validation_sha256']}"
            ".json"
        )
    )
    shared = json.loads(shared_path.read_text(encoding="utf-8"))
    assert shared["daily_list_item_count"] == 1
    assert shared["image_count"] == 2
    assert shared["platform_write_request_count"] == 0
    assert shared["forbidden_request_count"] == 0
    assert shared["redirect_count"] == 0


def test_daily_shared_validation_skips_only_explicitly_unavailable_candidate(
    tmp_path: Path,
) -> None:
    class CandidateConnector(FakeConnector):
        def get_waybill_detail(
            self,
            *,
            authority: BrowserCommandAuthority,
            platform_waybill_id: str,
        ) -> WaybillDetail:
            if platform_waybill_id == "stale-candidate":
                self.calls.append(f"detail:{platform_waybill_id}")
                raise DetailCandidateUnavailableError()
            return super().get_waybill_detail(
                authority=authority,
                platform_waybill_id=platform_waybill_id,
            )

    class CandidateDailySource(FakeDailyValidationSource):
        def prepare_and_list(
            self,
            *,
            authority: BrowserCommandAuthority,
        ) -> DailyContractValidationCandidatePage:
            self.calls.append(authority)
            return DailyContractValidationCandidatePage(
                business_date="2026-07-28",
                query_scope_sha256="7" * 64,
                page_number=1,
                page_size=5,
                total=2,
                platform_waybill_ids=(
                    "stale-candidate",
                    "available-candidate",
                ),
            )

    connector = CandidateConnector(empty_list_attempts=2)
    runner = LiveContractValidationRunner(
        connector=connector,
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
        daily_source=CandidateDailySource(tmp_path),
    )

    result = runner.validate(
        authority=_authority(),
        access_window_id="window-stale-daily-candidate",
        build_sha256="e" * 64,
    )

    assert result.detail_attempt_count == 2
    assert "detail:stale-candidate" in connector.calls
    assert "detail:available-candidate" in connector.calls


def test_composite_gate_replays_both_children_and_daily_selection(
    tmp_path: Path,
) -> None:
    connector = FakeConnector(empty_list_attempts=2)
    runner = LiveContractValidationRunner(
        connector=connector,
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
        daily_source=FakeDailyValidationSource(tmp_path),
    )
    result = runner.validate(
        authority=_authority(),
        access_window_id="window-composite-replay",
        build_sha256="e" * 64,
    )
    document = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    changed_daily_runner = LiveContractValidationRunner(
        connector=FakeConnector(),
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
        daily_source=FakeDailyValidationSource(
            tmp_path,
            selection_sha256="9" * 64,
        ),
    )
    assert changed_daily_runner.has_successful_validation("e" * 64) is False

    empty_path = (
        tmp_path
        / "platform-read-contract-validation-settlement-empty"
        / f"{document['settlement_empty_evidence_sha256']}.json"
    )
    empty_path.unlink()

    with pytest.raises(LiveContractValidationError, match="empty"):
        runner.has_successful_validation("e" * 64)


def test_validation_rejects_tampered_existing_evidence(tmp_path: Path) -> None:
    runner = LiveContractValidationRunner(
        connector=FakeConnector(),
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
    )
    result = runner.validate(
        authority=_authority(),
        access_window_id="window-1",
        build_sha256="e" * 64,
    )
    document = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    document["platform_write_request_count"] = 1
    result.evidence_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(LiveContractValidationError, match="integrity"):
        runner.existing_for_access_window("window-1")


def test_current_gate_rejects_tampered_or_missing_exclusion(
    tmp_path: Path,
) -> None:
    runner = LiveContractValidationRunner(
        connector=FakeConnector(),
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
    )
    result = runner.validate(
        authority=_authority(),
        access_window_id="window-exclusion",
        build_sha256="e" * 64,
    )
    assert result.development_exclusion_sha256 is not None
    exclusion_path = (
        tmp_path
        / "platform-read-contract-validation-exclusions"
        / f"{result.development_exclusion_sha256}.json"
    )
    exclusion_path.unlink()

    with pytest.raises(LiveContractValidationError, match="exclusion"):
        runner.has_successful_validation("e" * 64)


def test_legacy_validation_evidence_is_readable_but_not_a_current_gate(
    tmp_path: Path,
) -> None:
    runner = LiveContractValidationRunner(
        connector=FakeConnector(),
        selected=_selected(tmp_path),
        data_root=tmp_path.resolve(),
        clock=lambda: datetime(2026, 7, 29, 12, tzinfo=UTC),
        identity_salt=IDENTITY_KEY,
        identity_namespace=IDENTITY_NAMESPACE,
    )
    result = runner.validate(
        authority=_authority(),
        access_window_id="legacy-window",
        build_sha256="e" * 64,
    )
    document = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    document["schema_version"] = 1
    document.pop("development_exclusion_sha256")
    document.pop("development_exclusion_inventory_sha256")
    document.pop("identity_context_sha256")
    for field in (
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
    ):
        document.pop(field)
    document["operation_counts"].pop("list_daily_waybills")
    document.pop("canonical_sha256")
    import hashlib

    canonical = hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    document["canonical_sha256"] = canonical
    legacy_path = result.evidence_path.with_name(f"{canonical}.json")
    legacy_path.write_text(
        json.dumps(document, ensure_ascii=False),
        encoding="utf-8",
    )
    result.evidence_path.unlink()

    assert (
        runner.existing_for_access_window("legacy-window")
        is not None
    )
    assert runner.has_successful_validation("e" * 64) is False
