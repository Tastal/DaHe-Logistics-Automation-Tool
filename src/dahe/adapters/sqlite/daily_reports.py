# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from decimal import Decimal
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

from sqlalchemy import select, update

from dahe.adapters.sqlite.daily_items import SqliteDailyItemRepository
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    DAILY_REPORT_IDEMPOTENCY,
    DAILY_REPORT_SETTINGS,
    DAILY_REPORTS,
)
from dahe.application.chengfeng.contract_subject import (
    SHANXI_GUIENBO,
    contract_subject_label,
    require_contract_subject_code,
)
from dahe.application.daily.report_workbook import (
    DailyReportSettings,
    DailyReportWorkbook,
    DailyReportWorkbookError,
    build_daily_report_result,
)
from dahe.ports.jobs import IdempotencyConflictError, RecordVersionConflictError

_DEFAULT_SHIPPING_MINE = "金鸡滩煤矿"
_DEFAULT_COAL_TYPE = "兖矿陕动四号（5600）"
_DEFAULT_UNLOADING_PLACE = "象道货22"
_DEFAULT_QUERY_PLACE_KEYWORD = "榆林"


class DailyReportConflictError(RuntimeError):
    """Raised when report state or a report file changed unexpectedly."""


@dataclass(frozen=True, slots=True)
class DailyReportRecord:
    report_id: str
    contract_subject_code: str
    business_date: date
    status: str
    output_directory: Path
    file_name: str
    file_sha256: str
    data_snapshot_sha256: str
    row_count: int
    loading_net_total: Decimal
    record_version: int
    created_at: str
    confirmed_at: str | None
    stale: bool = False
    candidate_count: int = 0
    window_excluded_count: int = 0
    missing_effective_time_count: int = 0

    @property
    def path(self) -> Path:
        return self.output_directory / self.file_name

    def to_payload(self) -> dict[str, object]:
        return {
            "contract_subject_code": self.contract_subject_code,
            "business_date": self.business_date.isoformat(),
            "confirmed_at": self.confirmed_at,
            "created_at": self.created_at,
            "data_snapshot_sha256": self.data_snapshot_sha256,
            "file_name": self.file_name,
            "file_sha256": self.file_sha256,
            "loading_net_total": format(self.loading_net_total, "f"),
            "output_directory": str(self.output_directory),
            "record_version": self.record_version,
            "report_id": self.report_id,
            "row_count": self.row_count,
            "candidate_count": self.candidate_count,
            "window_excluded_count": self.window_excluded_count,
            "missing_effective_time_count": self.missing_effective_time_count,
            "status": self.status,
            "stale": self.stale,
        }


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _settings_from_row(row: object) -> DailyReportSettings:
    values = row._mapping  # type: ignore[attr-defined]
    return DailyReportSettings(
        shipping_mine=str(values["shipping_mine"]),
        coal_type=str(values["coal_type"]),
        unloading_place=str(values["unloading_place"]),
        query_place_keyword=str(values["query_place_keyword"]),
        output_directory=Path(str(values["output_directory"])).resolve(),
        confirmed=bool(values["confirmed"]),
        record_version=int(values["record_version"]),
        capture_start_time=time.fromisoformat(str(values["capture_start_time"])),
        capture_end_mode=cast(
            Literal["system_current_time", "fixed_time"],
            str(values["capture_end_mode"]),
        ),
        capture_fixed_end_day_offset=int(values["capture_fixed_end_day_offset"]),
        capture_fixed_end_time=time.fromisoformat(
            str(values["capture_fixed_end_time"])
        ),
    )


def _record_from_row(row: object) -> DailyReportRecord:
    values = row._mapping  # type: ignore[attr-defined]
    try:
        data_payload = json.loads(str(values["data_json"]))
    except (TypeError, ValueError):
        data_payload = {}
    if not isinstance(data_payload, dict):
        data_payload = {}
    return DailyReportRecord(
        report_id=str(values["report_id"]),
        contract_subject_code=require_contract_subject_code(
            values["contract_subject_code"]
        ),
        business_date=date.fromisoformat(str(values["business_date"])),
        status=str(values["status"]),
        output_directory=Path(str(values["output_directory"])).resolve(),
        file_name=str(values["file_name"]),
        file_sha256=str(values["file_sha256"]),
        data_snapshot_sha256=str(values["data_snapshot_sha256"]),
        row_count=int(values["row_count"]),
        loading_net_total=Decimal(str(values["loading_net_total"])),
        record_version=int(values["record_version"]),
        created_at=str(values["created_at"]),
        confirmed_at=(
            None if values["confirmed_at"] is None else str(values["confirmed_at"])
        ),
        stale=bool(values["stale"]),
        candidate_count=int(data_payload.get("candidate_count", values["row_count"])),
        window_excluded_count=int(data_payload.get("window_excluded_count", 0)),
        missing_effective_time_count=int(
            data_payload.get("missing_effective_time_count", 0)
        ),
    )


class SqliteDailyReportRepository:
    """Coordinate short SQLite commits with guarded report file writes."""

    def __init__(
        self,
        *,
        runtime: SqliteRuntime,
        daily_store: SqliteDailyStore,
        daily_items: SqliteDailyItemRepository | None = None,
        default_output_directory: Path,
        workbook: DailyReportWorkbook | None = None,
    ) -> None:
        if not default_output_directory.is_absolute():
            raise ValueError("default_output_directory must be absolute")
        self._runtime = runtime
        self._daily_store = daily_store
        self._daily_items = daily_items
        self._default_output_directory = default_output_directory.resolve()
        self._workbook = workbook or DailyReportWorkbook()

    def get_settings(self) -> DailyReportSettings:
        with self._runtime.engine.connect() as connection:
            row = connection.execute(
                select(DAILY_REPORT_SETTINGS).where(
                    DAILY_REPORT_SETTINGS.c.settings_id == "primary"
                )
            ).one_or_none()
        if row is None:
            return DailyReportSettings(
                shipping_mine=_DEFAULT_SHIPPING_MINE,
                coal_type=_DEFAULT_COAL_TYPE,
                unloading_place=_DEFAULT_UNLOADING_PLACE,
                query_place_keyword=_DEFAULT_QUERY_PLACE_KEYWORD,
                output_directory=self._default_output_directory,
                confirmed=True,
                record_version=0,
                capture_start_time=time(14, 0),
                capture_end_mode="system_current_time",
                capture_fixed_end_day_offset=1,
                capture_fixed_end_time=time(14, 30),
            )
        return _settings_from_row(row)

    def save_settings(
        self,
        *,
        shipping_mine: str,
        coal_type: str,
        unloading_place: str,
        query_place_keyword: str,
        output_directory: Path,
        confirmed: bool,
        expected_record_version: int,
        capture_start_time: time = time(14, 0),
        capture_end_mode: str = "system_current_time",
        capture_fixed_end_day_offset: int = 1,
        capture_fixed_end_time: time = time(14, 30),
        idempotency_key: str | None = None,
        request_hash: str | None = None,
    ) -> DailyReportSettings:
        if (idempotency_key is None) != (request_hash is None):
            raise ValueError("settings idempotency requires a key and request hash")
        if idempotency_key is not None and request_hash is not None:
            replay = self._load_replay(
                idempotency_key=idempotency_key,
                operation="save_settings",
                request_hash=request_hash,
            )
            if replay is not None:
                payload = replay.get("settings")
                if not isinstance(payload, dict):
                    raise DailyReportConflictError("settings replay is invalid")
                return DailyReportSettings(
                    shipping_mine=str(payload["shipping_mine"]),
                    coal_type=str(payload["coal_type"]),
                    unloading_place=str(payload["unloading_place"]),
                    query_place_keyword=str(payload["query_place_keyword"]),
                    output_directory=Path(str(payload["output_directory"])).resolve(),
                    confirmed=bool(payload["confirmed"]),
                    record_version=int(payload["record_version"]),
                    capture_start_time=time.fromisoformat(
                        str(payload.get("capture_start_time", "14:00:00"))
                    ),
                    capture_end_mode=cast(
                        Literal["system_current_time", "fixed_time"],
                        str(
                            payload.get(
                                "capture_end_mode", "system_current_time"
                            )
                        ),
                    ),
                    capture_fixed_end_day_offset=int(
                        payload.get("capture_fixed_end_day_offset", 1)
                    ),
                    capture_fixed_end_time=time.fromisoformat(
                        str(payload.get("capture_fixed_end_time", "14:30:00"))
                    ),
                )
        if not output_directory.is_absolute():
            raise ValueError("output_directory must be absolute")
        candidate = DailyReportSettings(
            shipping_mine=shipping_mine,
            coal_type=coal_type,
            unloading_place=unloading_place,
            query_place_keyword=query_place_keyword,
            output_directory=output_directory.resolve(),
            confirmed=confirmed,
            record_version=expected_record_version + 1,
            capture_start_time=capture_start_time,
            capture_end_mode=cast(
                Literal["system_current_time", "fixed_time"],
                capture_end_mode,
            ),
            capture_fixed_end_day_offset=capture_fixed_end_day_offset,
            capture_fixed_end_time=capture_fixed_end_time,
        )
        with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
            existing = connection.execute(
                select(DAILY_REPORT_SETTINGS).where(
                    DAILY_REPORT_SETTINGS.c.settings_id == "primary"
                )
            ).one_or_none()
            actual_version = 0 if existing is None else int(existing.record_version)
            if actual_version != expected_record_version:
                raise RecordVersionConflictError("daily report settings changed")
            values = {
                "shipping_mine": candidate.shipping_mine,
                "coal_type": candidate.coal_type,
                "unloading_place": candidate.unloading_place,
                "query_place_keyword": candidate.query_place_keyword,
                "capture_start_time": candidate.capture_start_time.isoformat(),
                "capture_end_mode": candidate.capture_end_mode,
                "capture_fixed_end_day_offset": (
                    candidate.capture_fixed_end_day_offset
                ),
                "capture_fixed_end_time": (
                    candidate.capture_fixed_end_time.isoformat()
                ),
                "output_directory": str(candidate.output_directory),
                "confirmed": int(candidate.confirmed),
                "record_version": candidate.record_version,
                "updated_at": _now(),
            }
            if existing is None:
                connection.execute(
                    DAILY_REPORT_SETTINGS.insert().values(
                        settings_id="primary",
                        **values,
                    )
                )
            else:
                connection.execute(
                    update(DAILY_REPORT_SETTINGS)
                    .where(DAILY_REPORT_SETTINGS.c.settings_id == "primary")
                    .values(**values)
                )
            if idempotency_key is not None and request_hash is not None:
                self._save_replay(
                    connection,
                    idempotency_key=idempotency_key,
                    operation="save_settings",
                    request_hash=request_hash,
                    result={"settings": self._settings_payload(candidate)},
                )
        return candidate

    def get_report(
        self,
        report_id: str,
        *,
        contract_subject_code: str | None = None,
    ) -> DailyReportRecord:
        query = select(DAILY_REPORTS).where(
            DAILY_REPORTS.c.report_id == report_id
        )
        if contract_subject_code is not None:
            query = query.where(
                DAILY_REPORTS.c.contract_subject_code
                == require_contract_subject_code(contract_subject_code)
            )
        with self._runtime.engine.connect() as connection:
            row = connection.execute(query).one_or_none()
        if row is None:
            raise DailyReportConflictError("daily report does not exist")
        return _record_from_row(row)

    def find_report_for_business_date(
        self,
        business_date: date,
        *,
        contract_subject_code: str = SHANXI_GUIENBO,
    ) -> DailyReportRecord | None:
        subject_code = require_contract_subject_code(contract_subject_code)
        with self._runtime.engine.connect() as connection:
            row = connection.execute(
                select(DAILY_REPORTS)
                .where(
                    DAILY_REPORTS.c.business_date == business_date.isoformat(),
                    DAILY_REPORTS.c.contract_subject_code == subject_code,
                )
                .order_by(
                    DAILY_REPORTS.c.stale.asc(),
                    DAILY_REPORTS.c.created_at.desc(),
                )
                .limit(1)
            ).one_or_none()
        return None if row is None else _record_from_row(row)

    def create_report(
        self,
        *,
        business_date: date,
        expected_settings_version: int,
        idempotency_key: str,
        request_hash: str,
        contract_subject_code: str = SHANXI_GUIENBO,
    ) -> tuple[DailyReportRecord, bool]:
        subject_code = require_contract_subject_code(contract_subject_code)
        replay = self._load_replay(
            idempotency_key=idempotency_key,
            operation="create",
            request_hash=request_hash,
            contract_subject_code=subject_code,
        )
        if replay is not None:
            return self.get_report(
                str(replay["report_id"]),
                contract_subject_code=subject_code,
            ), True
        settings = self.get_settings()
        if settings.record_version != expected_settings_version:
            raise RecordVersionConflictError("daily report settings changed")
        revisions = (
            self._daily_store.list_latest_revisions_for_business_date(
                business_date=business_date,
                receive_place_keyword=settings.query_place_keyword,
                contract_subject_code=subject_code,
            )
            if self._daily_items is None
            else self._daily_items.effective_revisions(
                business_date=business_date,
                receive_place_keyword=settings.query_place_keyword,
                contract_subject_code=subject_code,
            )
        )
        platform_loading_times = self._daily_store.platform_loading_times_for_revisions(
            revisions
        )
        primary_loading_time_ids = (
            frozenset()
            if self._daily_items is None
            else self._daily_items.primary_loading_time_ids(
                revisions,
                contract_subject_code=subject_code,
            )
        )
        built = build_daily_report_result(
            business_date=business_date,
            settings=settings,
            revisions=revisions,
            platform_loading_times=platform_loading_times,
            primary_loading_time_ids=primary_loading_time_ids,
        )
        rows = built.rows
        try:
            generated = self._workbook.write_report(
                business_date=business_date,
                settings=settings,
                rows=rows,
                contract_subject_code=subject_code,
                contract_subject_label=contract_subject_label(subject_code),
            )
        except DailyReportWorkbookError as exc:
            raise DailyReportConflictError(str(exc)) from exc
        existing_report = self.find_report_for_business_date(
            business_date,
            contract_subject_code=subject_code,
        )
        report_id = (
            uuid4().hex
            if existing_report is None
            else existing_report.report_id
        )
        created_at = _now()
        data_json = _json(
            {
                "business_date": business_date.isoformat(),
                "contract_subject_code": subject_code,
                "rows": [row.evidence_payload() for row in rows],
                "candidate_count": built.candidate_count,
                "window_excluded_count": built.window_excluded_count,
                "missing_effective_time_count": built.missing_effective_time_count,
                "schema_version": 2,
            }
        )
        try:
            with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
                report_values = {
                        "report_id": report_id,
                        "contract_subject_code": subject_code,
                        "business_date": business_date.isoformat(),
                        "status": "confirmed",
                        "settings_record_version": settings.record_version,
                        "output_directory": str(settings.output_directory),
                        "file_name": generated.path.name,
                        "file_sha256": generated.file_sha256,
                        "data_snapshot_sha256": generated.data_snapshot_sha256,
                        "data_json": data_json,
                        "row_count": generated.row_count,
                        "loading_net_total": format(generated.loading_net_total, "f"),
                        "record_version": (
                            1
                            if existing_report is None
                            else existing_report.record_version + 1
                        ),
                        "created_at": (
                            created_at
                            if existing_report is None
                            else existing_report.created_at
                        ),
                        "confirmed_at": created_at,
                        "stale": 0,
                }
                if existing_report is None:
                    connection.execute(
                        DAILY_REPORTS.insert().values(**report_values)
                    )
                else:
                    changed = connection.execute(
                        update(DAILY_REPORTS)
                        .where(
                            DAILY_REPORTS.c.report_id == report_id,
                            DAILY_REPORTS.c.record_version
                            == existing_report.record_version,
                        )
                        .values(**report_values)
                    )
                    if changed.rowcount != 1:
                        raise RecordVersionConflictError(
                            "daily report changed"
                        )
                self._save_replay(
                    connection,
                    idempotency_key=idempotency_key,
                    operation="create",
                    request_hash=request_hash,
                    result={"report_id": report_id},
                    contract_subject_code=subject_code,
                )
        except Exception:
            # The file may have atomically replaced an earlier formal report.
            # Never delete that valid business artifact because a later local
            # metadata commit failed; diagnostics can reconcile the orphan.
            raise
        return self.get_report(
            report_id,
            contract_subject_code=subject_code,
        ), False

    def confirm_report(
        self,
        *,
        report_id: str,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
        contract_subject_code: str = SHANXI_GUIENBO,
    ) -> tuple[DailyReportRecord, bool]:
        subject_code = require_contract_subject_code(contract_subject_code)
        replay = self._load_replay(
            idempotency_key=idempotency_key,
            operation="confirm",
            request_hash=request_hash,
            contract_subject_code=subject_code,
        )
        if replay is not None:
            return self.get_report(
                str(replay["report_id"]),
                contract_subject_code=subject_code,
            ), True
        report = self.get_report(
            report_id,
            contract_subject_code=subject_code,
        )
        if report.record_version != expected_record_version:
            raise RecordVersionConflictError("daily report changed")
        if report.status != "pending_confirmation":
            raise DailyReportConflictError("daily report is not pending confirmation")
        self._require_unchanged(report)
        prefix = report.file_name.split("-待确认", 1)[0]
        confirmed_path = report.output_directory / f"{prefix}.xlsx"
        if confirmed_path.exists():
            raise DailyReportConflictError("confirmed report already exists")
        os.replace(report.path, confirmed_path)
        now = _now()
        try:
            with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
                result = connection.execute(
                    update(DAILY_REPORTS)
                    .where(
                        DAILY_REPORTS.c.report_id == report_id,
                        DAILY_REPORTS.c.record_version == expected_record_version,
                    )
                    .values(
                        status="confirmed",
                        file_name=confirmed_path.name,
                        record_version=expected_record_version + 1,
                        confirmed_at=now,
                    )
                )
                if result.rowcount != 1:
                    raise RecordVersionConflictError("daily report changed")
                self._save_replay(
                    connection,
                    idempotency_key=idempotency_key,
                    operation="confirm",
                    request_hash=request_hash,
                    result={"report_id": report_id},
                    contract_subject_code=subject_code,
                )
        except Exception:
            os.replace(confirmed_path, report.path)
            raise
        return self.get_report(
            report_id,
            contract_subject_code=subject_code,
        ), False

    def save_new_copy(
        self,
        *,
        report_id: str,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
        contract_subject_code: str = SHANXI_GUIENBO,
    ) -> tuple[DailyReportRecord, bool]:
        subject_code = require_contract_subject_code(contract_subject_code)
        replay = self._load_replay(
            idempotency_key=idempotency_key,
            operation="save_new_copy",
            request_hash=request_hash,
            contract_subject_code=subject_code,
        )
        if replay is not None:
            return self.get_report(
                str(replay["report_id"]),
                contract_subject_code=subject_code,
            ), True
        report = self.get_report(
            report_id,
            contract_subject_code=subject_code,
        )
        if report.record_version != expected_record_version:
            raise RecordVersionConflictError("daily report changed")
        if report.status != "pending_confirmation" or not report.path.is_file():
            raise DailyReportConflictError("daily report is not available for copying")
        try:
            self._workbook.validate_existing(report.path, row_count=report.row_count)
        except DailyReportWorkbookError as exc:
            raise DailyReportConflictError("externally modified report is invalid") from exc
        prefix = report.file_name.split("-待确认", 1)[0]
        version = 2
        while True:
            destination = report.output_directory / f"{prefix}-待确认-v{version}.xlsx"
            if not destination.exists():
                break
            version += 1
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
        try:
            shutil.copyfile(report.path, temporary)
            with temporary.open("r+b") as handle:
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        new_sha = _sha256_file(destination)
        try:
            with self._runtime.commit_gate.transaction(self._runtime.engine) as connection:
                result = connection.execute(
                    update(DAILY_REPORTS)
                    .where(
                        DAILY_REPORTS.c.report_id == report_id,
                        DAILY_REPORTS.c.record_version == expected_record_version,
                    )
                    .values(
                        file_name=destination.name,
                        file_sha256=new_sha,
                        record_version=expected_record_version + 1,
                    )
                )
                if result.rowcount != 1:
                    raise RecordVersionConflictError("daily report changed")
                self._save_replay(
                    connection,
                    idempotency_key=idempotency_key,
                    operation="save_new_copy",
                    request_hash=request_hash,
                    result={"report_id": report_id},
                    contract_subject_code=subject_code,
                )
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return self.get_report(
            report_id,
            contract_subject_code=subject_code,
        ), False

    def _require_unchanged(self, report: DailyReportRecord) -> None:
        if not report.path.is_file() or _sha256_file(report.path) != report.file_sha256:
            raise DailyReportConflictError("daily report was externally modified")
        try:
            self._workbook.validate_existing(report.path, row_count=report.row_count)
        except DailyReportWorkbookError as exc:
            raise DailyReportConflictError("daily report was externally modified") from exc

    @staticmethod
    def _settings_payload(settings: DailyReportSettings) -> dict[str, object]:
        return {
            "coal_type": settings.coal_type,
            "confirmed": settings.confirmed,
            "output_directory": str(settings.output_directory),
            "query_place_keyword": settings.query_place_keyword,
            "capture_start_time": settings.capture_start_time.isoformat(),
            "capture_end_mode": settings.capture_end_mode,
            "capture_fixed_end_day_offset": settings.capture_fixed_end_day_offset,
            "capture_fixed_end_time": settings.capture_fixed_end_time.isoformat(),
            "record_version": settings.record_version,
            "shipping_mine": settings.shipping_mine,
            "unloading_place": settings.unloading_place,
        }

    def _load_replay(
        self,
        *,
        idempotency_key: str,
        operation: str,
        request_hash: str,
        contract_subject_code: str = SHANXI_GUIENBO,
    ) -> dict[str, object] | None:
        with self._runtime.engine.connect() as connection:
            row = connection.execute(
                select(DAILY_REPORT_IDEMPOTENCY).where(
                    DAILY_REPORT_IDEMPOTENCY.c.idempotency_key == idempotency_key,
                    DAILY_REPORT_IDEMPOTENCY.c.contract_subject_code
                    == contract_subject_code,
                )
            ).one_or_none()
        if row is None:
            return None
        if row.operation != operation or row.request_hash != request_hash:
            raise IdempotencyConflictError("daily report idempotency key was reused")
        parsed = json.loads(str(row.result_json))
        if not isinstance(parsed, dict):
            raise DailyReportConflictError("daily report replay is invalid")
        return parsed

    @staticmethod
    def _save_replay(
        connection: object,
        *,
        idempotency_key: str,
        operation: str,
        request_hash: str,
        result: dict[str, object],
        contract_subject_code: str = SHANXI_GUIENBO,
    ) -> None:
        connection.execute(  # type: ignore[attr-defined]
            DAILY_REPORT_IDEMPOTENCY.insert().values(
                idempotency_key=idempotency_key,
                contract_subject_code=contract_subject_code,
                operation=operation,
                request_hash=request_hash,
                result_json=_json(result),
                created_at=_now(),
            )
        )
