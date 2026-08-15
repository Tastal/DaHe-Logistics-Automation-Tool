from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal
from urllib.parse import urlsplit

PROTOCOL_VERSION = 9
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
_PARAMETER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,99}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_QUERY_ATTEMPT_ID = re.compile(r"^[0-9a-f]{32}$")
_CONTRACT_SUBJECT_CODES = frozenset(
    {"shanxi_guienbo", "shanghai_jinyisheng"}
)
_SETTLEMENT_LIST_PATH = (
    "/api/order-center-server/app/clientOrderItem/"
    "queryWaitSettlementOrderItemListPC"
)
_DISCOVERY_FIELD_PATH = re.compile(
    r"^\$(?:\[\])?(?:\.[A-Za-z][A-Za-z0-9]{0,79}(?:\[\])?)*$"
)
_DAILY_READ_URL = (
    "https://pc.chengfengkuaiyun.com/api/hz/orderItem/"
    "queryOrderItemListPC"
)
_DETAIL_READ_URL = (
    "https://pc.chengfengkuaiyun.com/api/order-center-server/"
    "app/clientOrderItem/getOrderItemDetailsByIdPC"
)
CHENGFENG_IMAGE_HOSTS = frozenset(
    {
        "pc.chengfengkuaiyun.com",
        "cfhy-file-data.obs.cn-north-4.myhuaweicloud.com",
        "cfky.oss-cn-zhangjiakou.aliyuncs.com",
    }
)


class ProtocolError(RuntimeError):
    """Raised when a browser-worker command is not canonical and safe."""


@dataclass(frozen=True, slots=True)
class SmokeCommand:
    request_id: str
    browser: Literal["auto", "chromium", "msedge"]
    browser_store: Path


@dataclass(frozen=True, slots=True)
class InitializeCommand:
    request_id: str
    browser: Literal["auto", "chromium", "msedge"]
    profile_root: Path
    staging_root: Path


@dataclass(frozen=True, slots=True)
class InitializeHeadlessCommand:
    request_id: str
    browser: Literal["auto", "chromium", "msedge"]
    profile_root: Path
    staging_root: Path


@dataclass(frozen=True, slots=True)
class CloseCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class AbortCommand:
    request_id: str
    target_request_id: str


@dataclass(frozen=True, slots=True)
class CaptureStartCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class CaptureStopCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class FreezeHumanSessionCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class ResumeHumanSessionCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class HandoffOperationalSessionCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class ParkOperationalSessionCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class ProbeSettlementViewsCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class StatusCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class PrepareAutomatedCommand:
    request_id: str
    scope: Literal["current", "settled_history"]


@dataclass(frozen=True, slots=True)
class PrepareOperationalCompatCommand:
    request_id: str
    contract_subject_code: str = "shanxi_guienbo"


@dataclass(frozen=True, slots=True)
class PrepareSettlementFilterHandoffCommand:
    request_id: str
    waybill_numbers: tuple[str, ...]
    contract_subject_code: str


@dataclass(frozen=True, slots=True)
class PrepareDailyCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class PrepareDailyFromAutomatedCommand:
    request_id: str


@dataclass(frozen=True, slots=True)
class PrepareOperationalDailyCommand:
    request_id: str
    contract_subject_code: str = "shanxi_guienbo"


@dataclass(frozen=True, slots=True)
class ReadJsonCommand:
    request_id: str
    operation: Literal["list_waybills", "get_waybill_detail"]
    method: Literal["POST"]
    url: str
    parameters: Mapping[str, str | int | tuple[()]]


@dataclass(frozen=True, slots=True)
class ReadDailyJsonCommand:
    request_id: str
    operation: Literal["list_daily_waybills"]
    method: Literal["POST"]
    url: Literal[
        "https://pc.chengfengkuaiyun.com/api/hz/orderItem/queryOrderItemListPC"
    ]
    parameters: Mapping[str, str | int | tuple[()] | None]


@dataclass(frozen=True, slots=True)
class ReadImageCommand:
    request_id: str
    operation: Literal["download_ticket_image"]
    method: Literal["GET"]
    url: str
    parameters: Mapping[str, str | int | tuple[()]]


@dataclass(frozen=True, slots=True)
class OperationalBatchDetailCommand:
    platform_waybill_id: str
    url: Literal[
        "https://pc.chengfengkuaiyun.com/api/order-center-server/"
        "app/clientOrderItem/getOrderItemDetailsByIdPC"
    ]
    parameters: Mapping[str, str | int | tuple[()]]
    reuse: OperationalReuseCandidate | None = None


@dataclass(frozen=True, slots=True)
class OperationalImageReuseCandidate:
    slot: Literal["loading", "unloading"]
    sha256: str
    media_type: str
    validator_sha256: str


@dataclass(frozen=True, slots=True)
class OperationalReuseCandidate:
    source_revision_sha256: str
    images: tuple[OperationalImageReuseCandidate, ...]


@dataclass(frozen=True, slots=True)
class ReadOperationalBatchCommand:
    request_id: str
    details: tuple[OperationalBatchDetailCommand, ...]
    detail_concurrency: int
    image_concurrency: int
    contract_subject_code: str = "shanxi_guienbo"


@dataclass(frozen=True, slots=True)
class CaptureOperationalWholeRunCommand(ReadOperationalBatchCommand):
    """One all-or-nothing online capture after the authoritative list freeze."""


BrowserCommand = (
    SmokeCommand
    | InitializeCommand
    | InitializeHeadlessCommand
    | CloseCommand
    | AbortCommand
    | CaptureStartCommand
    | CaptureStopCommand
    | FreezeHumanSessionCommand
    | ResumeHumanSessionCommand
    | HandoffOperationalSessionCommand
    | ParkOperationalSessionCommand
    | ProbeSettlementViewsCommand
    | StatusCommand
    | PrepareAutomatedCommand
    | PrepareOperationalCompatCommand
    | PrepareSettlementFilterHandoffCommand
    | PrepareDailyCommand
    | PrepareDailyFromAutomatedCommand
    | PrepareOperationalDailyCommand
    | ReadJsonCommand
    | ReadDailyJsonCommand
    | ReadImageCommand
    | ReadOperationalBatchCommand
    | CaptureOperationalWholeRunCommand
)


def parse_command(line: str) -> BrowserCommand:
    try:
        raw = json.loads(line)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ProtocolError("command must be one JSON object") from exc
    if not isinstance(raw, dict):
        raise ProtocolError("command must be one JSON object")
    if raw.get("schema_version") != PROTOCOL_VERSION:
        raise ProtocolError("browser protocol version is invalid")
    command_name = raw.get("command")
    request_id = raw.get("request_id")
    if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
        raise ProtocolError("request identity is invalid")
    if command_name == "abort":
        if set(raw) != {
            "schema_version",
            "command",
            "request_id",
            "target_request_id",
        }:
            raise ProtocolError("abort command fields do not match the protocol")
        target_request_id = raw["target_request_id"]
        if (
            not isinstance(target_request_id, str)
            or _REQUEST_ID.fullmatch(target_request_id) is None
            or target_request_id == request_id
        ):
            raise ProtocolError("abort target identity is invalid")
        return AbortCommand(
            request_id=request_id,
            target_request_id=target_request_id,
        )
    if command_name in {
        "close",
        "capture_start",
        "capture_stop",
        "freeze_human_session",
        "resume_human_session",
        "handoff_operational_session",
        "park_operational_session",
        "probe_settlement_views",
        "prepare_daily",
        "prepare_daily_from_automated",
        "status",
    }:
        if set(raw) != {"schema_version", "command", "request_id"}:
            raise ProtocolError("control command fields do not match the protocol")
        command_types = {
            "close": CloseCommand,
            "capture_start": CaptureStartCommand,
            "capture_stop": CaptureStopCommand,
            "freeze_human_session": FreezeHumanSessionCommand,
            "resume_human_session": ResumeHumanSessionCommand,
            "handoff_operational_session": (
                HandoffOperationalSessionCommand
            ),
            "park_operational_session": ParkOperationalSessionCommand,
            "probe_settlement_views": ProbeSettlementViewsCommand,
            "prepare_daily": PrepareDailyCommand,
            "prepare_daily_from_automated": (
                PrepareDailyFromAutomatedCommand
            ),
            "status": StatusCommand,
        }
        return command_types[command_name](request_id=request_id)
    if command_name in {
        "prepare_operational_compat",
        "prepare_operational_daily",
    }:
        if set(raw) != {
            "schema_version",
            "command",
            "request_id",
            "contract_subject_code",
        }:
            raise ProtocolError(
                "subject preparation fields do not match the protocol"
            )
        contract_subject_code = raw["contract_subject_code"]
        if contract_subject_code not in _CONTRACT_SUBJECT_CODES:
            raise ProtocolError("contract subject is invalid")
        command_type = (
            PrepareOperationalCompatCommand
            if command_name == "prepare_operational_compat"
            else PrepareOperationalDailyCommand
        )
        return command_type(
            request_id=request_id,
            contract_subject_code=contract_subject_code,
        )
    if command_name == "prepare_automated":
        if set(raw) != {
            "schema_version",
            "command",
            "request_id",
            "scope",
        }:
            raise ProtocolError(
                "automated preparation fields do not match the protocol"
            )
        scope = raw["scope"]
        if scope not in {"current", "settled_history"}:
            raise ProtocolError("settlement scope is invalid")
        return PrepareAutomatedCommand(
            request_id=request_id,
            scope=scope,
        )
    if command_name == "prepare_settlement_filter_handoff":
        if set(raw) != {
            "schema_version",
            "command",
            "request_id",
            "waybill_numbers",
            "contract_subject_code",
        }:
            raise ProtocolError(
                "settlement filter handoff fields do not match the protocol"
            )
        values = raw["waybill_numbers"]
        if (
            not isinstance(values, list)
            or not 1 <= len(values) <= 2000
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,40}", value) is None
                for value in values
            )
            or len(set(values)) != len(values)
        ):
            raise ProtocolError("settlement filter waybills are invalid")
        contract_subject_code = raw["contract_subject_code"]
        if contract_subject_code not in _CONTRACT_SUBJECT_CODES:
            raise ProtocolError("contract subject code is invalid")
        return PrepareSettlementFilterHandoffCommand(
            request_id=request_id,
            waybill_numbers=tuple(values),
            contract_subject_code=contract_subject_code,
        )
    if command_name in {"read_operational_batch", "capture_operational_whole_run"}:
        return _parse_operational_batch_command(
            raw,
            request_id=request_id,
            whole_run=command_name == "capture_operational_whole_run",
        )
    if command_name in {"read_json", "read_image", "read_daily_json"}:
        return _parse_read_command(raw, request_id=request_id)
    if command_name not in {"smoke", "initialize", "initialize_headless"}:
        raise ProtocolError("browser command is not allowed")
    path_field = "browser_store" if command_name == "smoke" else "profile_root"
    expected = {"schema_version", "command", "request_id", "browser", path_field}
    if command_name in {"initialize", "initialize_headless"}:
        expected.add("staging_root")
    if set(raw) != expected:
        raise ProtocolError("command fields do not match the protocol")
    browser = raw["browser"]
    path_raw = raw[path_field]
    if browser not in {"auto", "chromium", "msedge"}:
        raise ProtocolError("browser choice is invalid")
    if not isinstance(path_raw, str):
        raise ProtocolError("browser path is invalid")
    path = Path(path_raw)
    if not path.is_absolute() or path.is_symlink():
        raise ProtocolError("browser path must be absolute and non-symlinked")
    if command_name == "smoke":
        return SmokeCommand(
            request_id=request_id,
            browser=browser,
            browser_store=path,
        )
    command_type = (
        InitializeHeadlessCommand
        if command_name == "initialize_headless"
        else InitializeCommand
    )
    return command_type(
        request_id=request_id,
        browser=browser,
        profile_root=path,
        staging_root=_absolute_normal_path(raw["staging_root"]),
    )


def _parse_read_command(
    raw: dict[object, object],
    *,
    request_id: str,
) -> ReadJsonCommand | ReadDailyJsonCommand | ReadImageCommand:
    expected = {
        "schema_version",
        "command",
        "request_id",
        "operation",
        "method",
        "url",
        "parameters",
    }
    if set(raw) != expected:
        raise ProtocolError("read command fields do not match the protocol")
    command_name = raw["command"]
    operation = raw["operation"]
    method = raw["method"]
    if command_name == "read_json":
        if operation not in {"list_waybills", "get_waybill_detail"} or method != "POST":
            raise ProtocolError("JSON read operation is invalid")
    elif command_name == "read_daily_json":
        if (
            operation != "list_daily_waybills"
            or method != "POST"
            or raw["url"] != _DAILY_READ_URL
        ):
            raise ProtocolError("daily JSON read operation is invalid")
    elif (
        command_name != "read_image"
        or operation != "download_ticket_image"
        or method != "GET"
    ):
        raise ProtocolError("image read operation is invalid")
    url = _https_url(raw["url"], allow_query=command_name == "read_image")
    parameters = _parameters(
        raw["parameters"],
        allow_null=command_name == "read_daily_json",
    )
    if command_name == "read_image":
        if parameters:
            raise ProtocolError("image reads cannot contain separate parameters")
        if not is_approved_image_read_url(url):
            raise ProtocolError("image read origin is not allowed")
        return ReadImageCommand(
            request_id=request_id,
            operation="download_ticket_image",
            method="GET",
            url=url,
            parameters=parameters,
        )
    if command_name == "read_daily_json":
        return ReadDailyJsonCommand(
            request_id=request_id,
            operation="list_daily_waybills",
            method="POST",
            url=_DAILY_READ_URL,
            parameters=parameters,
        )
    return ReadJsonCommand(
        request_id=request_id,
        operation=operation,
        method="POST",
        url=url,
        parameters=parameters,
    )


def _parse_operational_batch_command(
    raw: dict[object, object],
    *,
    request_id: str,
    whole_run: bool = False,
) -> ReadOperationalBatchCommand:
    if set(raw) != {
        "schema_version",
        "command",
        "request_id",
        "contract_subject_code",
        "details",
        "detail_concurrency",
        "image_concurrency",
    }:
        raise ProtocolError(
            "operational batch fields do not match the protocol"
        )
    detail_concurrency = raw["detail_concurrency"]
    image_concurrency = raw["image_concurrency"]
    contract_subject_code = raw["contract_subject_code"]
    raw_details = raw["details"]
    if (
        contract_subject_code not in _CONTRACT_SUBJECT_CODES
        or type(detail_concurrency) is not int
        or not 1 <= detail_concurrency <= 4
        or type(image_concurrency) is not int
        or not 1 <= image_concurrency <= 6
        or not isinstance(raw_details, list)
        or not 1 <= len(raw_details) <= (2000 if whole_run else 100)
    ):
        raise ProtocolError("operational batch limits are invalid")
    details: list[OperationalBatchDetailCommand] = []
    identities: set[str] = set()
    for raw_detail in raw_details:
        if not isinstance(raw_detail, dict) or set(raw_detail) != {
            "platform_waybill_id",
            "url",
            "parameters",
            "reuse",
        }:
            raise ProtocolError("operational batch detail is invalid")
        platform_waybill_id = raw_detail["platform_waybill_id"]
        if (
            type(platform_waybill_id) is not str
            or not platform_waybill_id
            or len(platform_waybill_id) > 64
            or not platform_waybill_id.isascii()
            or not platform_waybill_id.isdigit()
            or platform_waybill_id in identities
            or raw_detail["url"] != _DETAIL_READ_URL
        ):
            raise ProtocolError(
                "operational batch detail identity is invalid"
            )
        parameters = _parameters(raw_detail["parameters"])
        if set(parameters) != {"id"} or parameters["id"] != platform_waybill_id:
            raise ProtocolError(
                "operational batch detail parameters are invalid"
            )
        reuse = _parse_operational_reuse(raw_detail["reuse"])
        identities.add(platform_waybill_id)
        details.append(
            OperationalBatchDetailCommand(
                platform_waybill_id=platform_waybill_id,
                url=_DETAIL_READ_URL,
                parameters=parameters,
                reuse=reuse,
            )
        )
    command_type = CaptureOperationalWholeRunCommand if whole_run else ReadOperationalBatchCommand
    return command_type(
        request_id=request_id,
        contract_subject_code=contract_subject_code,
        details=tuple(details),
        detail_concurrency=detail_concurrency,
        image_concurrency=image_concurrency,
    )


def _parse_operational_reuse(
    value: object,
) -> OperationalReuseCandidate | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "source_revision_sha256",
        "images",
    }:
        raise ProtocolError("operational reuse candidate is invalid")
    source_revision_sha256 = value["source_revision_sha256"]
    raw_images = value["images"]
    if (
        not isinstance(source_revision_sha256, str)
        or _SHA256.fullmatch(source_revision_sha256) is None
        or not isinstance(raw_images, list)
        or not 1 <= len(raw_images) <= 2
    ):
        raise ProtocolError("operational reuse candidate is invalid")
    images: list[OperationalImageReuseCandidate] = []
    slots: set[str] = set()
    for raw_image in raw_images:
        if not isinstance(raw_image, dict) or set(raw_image) != {
            "slot",
            "sha256",
            "media_type",
            "validator_sha256",
        }:
            raise ProtocolError("operational reuse image is invalid")
        slot = raw_image["slot"]
        sha256 = raw_image["sha256"]
        media_type = raw_image["media_type"]
        validator_sha256 = raw_image["validator_sha256"]
        if (
            slot not in {"loading", "unloading"}
            or slot in slots
            or not isinstance(sha256, str)
            or _SHA256.fullmatch(sha256) is None
            or media_type not in {
                "image/bmp",
                "image/jpeg",
                "image/png",
                "image/tiff",
                "image/webp",
            }
            or not isinstance(validator_sha256, str)
            or _SHA256.fullmatch(validator_sha256) is None
        ):
            raise ProtocolError("operational reuse image is invalid")
        slots.add(slot)
        images.append(
            OperationalImageReuseCandidate(
                slot=slot,
                sha256=sha256,
                media_type=media_type,
                validator_sha256=validator_sha256,
            )
        )
    return OperationalReuseCandidate(
        source_revision_sha256=source_revision_sha256,
        images=tuple(images),
    )


def _absolute_normal_path(value: object) -> Path:
    if not isinstance(value, str):
        raise ProtocolError("browser path is invalid")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise ProtocolError("browser path must be absolute and non-symlinked")
    return path


def _https_url(value: object, *, allow_query: bool) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ProtocolError("read URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ProtocolError("read URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path.endswith("/")
        or "\\" in value
        or "\x00" in value
        or (parsed.query and not allow_query)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProtocolError("read URL is invalid")
    return value


def is_approved_image_read_url(value: object) -> bool:
    """Accept only the fixed Chengfeng image hosts known to the worker."""

    try:
        url = _https_url(value, allow_query=True)
        parsed = urlsplit(url)
    except ProtocolError:
        return False
    return (
        parsed.hostname in CHENGFENG_IMAGE_HOSTS
        and parsed.netloc == parsed.hostname
    )


def _parameters(
    value: object,
    *,
    allow_null: bool = False,
) -> Mapping[str, str | int | tuple[()] | None]:
    if not isinstance(value, dict) or len(value) > 100:
        raise ProtocolError("read parameters are invalid")
    normalized: dict[str, str | int | tuple[()] | None] = {}
    for key, item in value.items():
        if not isinstance(key, str) or _PARAMETER_NAME.fullmatch(key) is None:
            raise ProtocolError("read parameter name is invalid")
        if type(item) is int or (
            type(item) is str
            and item == item.strip()
            and "://" not in item
            and "?" not in item
            and "#" not in item
        ):
            normalized[key] = item
        elif type(item) is list and not item:
            normalized[key] = ()
        elif allow_null and item is None:
            normalized[key] = None
        else:
            raise ProtocolError("read parameter value is invalid")
    return MappingProxyType(normalized)


def response(
    command: BrowserCommand,
    *,
    ok: bool,
    selected_browser: str | None,
    error_code: str | None = None,
    discovery: list[dict[str, object]] | None = None,
    browser_open: bool | None = None,
    read_result: dict[str, object] | None = None,
    prepare_result: dict[str, object] | None = None,
    batch_result: list[dict[str, object]] | None = None,
) -> str:
    validated_prepare_result = _validated_prepare_result(
        prepare_result,
        command=command,
        ok=ok,
    )
    validated_discovery = _validated_discovery(
        discovery,
        command=command,
        ok=ok,
        error_code=error_code,
    )
    validated_batch_result = _validated_batch_result(
        batch_result,
        command=command,
        ok=ok,
    )
    payload = {
        "schema_version": PROTOCOL_VERSION,
        "request_id": command.request_id,
        "ok": ok,
        "selected_browser": selected_browser,
        "error_code": error_code,
        "discovery": validated_discovery,
        "browser_open": browser_open,
        "read_result": read_result,
        "prepare_result": validated_prepare_result,
        "batch_result": validated_batch_result,
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _validated_batch_result(
    value: object,
    *,
    command: BrowserCommand,
    ok: bool,
) -> list[dict[str, object]] | None:
    if not isinstance(command, ReadOperationalBatchCommand):
        if value is not None:
            raise ProtocolError(
                "batch result is not allowed for this command"
            )
        return None
    if not ok:
        if value is not None:
            raise ProtocolError("failed batch cannot return payloads")
        return None
    if not isinstance(value, list) or len(value) != len(command.details):
        raise ProtocolError("operational batch result count is invalid")
    expected_ids = tuple(
        detail.platform_waybill_id for detail in command.details
    )
    normalized: list[dict[str, object]] = []
    for expected_id, raw_item in zip(expected_ids, value, strict=True):
        if not isinstance(raw_item, Mapping) or set(raw_item) != {
            "platform_waybill_id",
            "source_revision_sha256",
            "detail",
            "images",
        }:
            raise ProtocolError("operational batch result is invalid")
        source_revision_sha256 = raw_item["source_revision_sha256"]
        raw_images = raw_item["images"]
        if (
            raw_item["platform_waybill_id"] != expected_id
            or not isinstance(source_revision_sha256, str)
            or _SHA256.fullmatch(source_revision_sha256) is None
            or not isinstance(raw_images, list)
            or len(raw_images) > 2
        ):
            raise ProtocolError(
                "operational batch result identity is invalid"
            )
        images: list[dict[str, object]] = []
        slots: set[str] = set()
        for raw_image in raw_images:
            if not isinstance(raw_image, Mapping) or set(raw_image) not in (
                {"slot", "payload", "validator_sha256"},
                {"slot", "reused"},
            ):
                raise ProtocolError(
                    "operational batch image result is invalid"
                )
            slot = raw_image["slot"]
            if slot not in {"loading", "unloading"} or slot in slots:
                raise ProtocolError(
                    "operational batch image slot is invalid"
                )
            slots.add(str(slot))
            if "reused" in raw_image:
                reused = _validated_reused_batch_image(
                    raw_image["reused"]
                )
                images.append({"slot": slot, "reused": reused})
                continue
            validator_sha256 = raw_image["validator_sha256"]
            if not (
                validator_sha256 is None
                or (
                    isinstance(validator_sha256, str)
                    and _SHA256.fullmatch(validator_sha256) is not None
                )
            ):
                raise ProtocolError(
                    "operational batch image validator is invalid"
                )
            images.append(
                {
                    "slot": slot,
                    "payload": _validated_batch_payload(
                        raw_image["payload"],
                        expected_media="image",
                    ),
                    "validator_sha256": validator_sha256,
                }
            )
        normalized.append(
            {
                "platform_waybill_id": expected_id,
                "source_revision_sha256": source_revision_sha256,
                "detail": _validated_batch_payload(
                    raw_item["detail"],
                    expected_media="json",
                ),
                "images": images,
            }
        )
    return normalized


def _validated_reused_batch_image(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "sha256",
        "media_type",
        "validator_sha256",
    }:
        raise ProtocolError("operational batch reuse result is invalid")
    digest = value["sha256"]
    media_type = value["media_type"]
    validator_sha256 = value["validator_sha256"]
    if (
        not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or media_type
        not in {
            "image/bmp",
            "image/jpeg",
            "image/png",
            "image/tiff",
            "image/webp",
        }
        or not isinstance(validator_sha256, str)
        or _SHA256.fullmatch(validator_sha256) is None
    ):
        raise ProtocolError("operational batch reuse values are invalid")
    return {
        "sha256": digest,
        "media_type": str(media_type),
        "validator_sha256": validator_sha256,
    }


def _validated_batch_payload(
    value: object,
    *,
    expected_media: Literal["json", "image"],
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {
        "relative_path",
        "sha256",
        "byte_size",
        "media_type",
        "status_code",
    }:
        raise ProtocolError("operational batch payload is invalid")
    relative_path = value["relative_path"]
    digest = value["sha256"]
    byte_size = value["byte_size"]
    media_type = value["media_type"]
    status_code = value["status_code"]
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or "\\" in relative_path
        or ".." in relative_path.split("/")
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or type(byte_size) is not int
        or byte_size <= 0
        or type(status_code) is not int
        or status_code != 200
        or not isinstance(media_type, str)
        or (
            expected_media == "json"
            and media_type != "application/json"
        )
        or (
            expected_media == "image"
            and media_type
            not in {
                "image/bmp",
                "image/jpeg",
                "image/png",
                "image/tiff",
                "image/webp",
            }
        )
    ):
        raise ProtocolError("operational batch payload values are invalid")
    return {
        "relative_path": relative_path,
        "sha256": digest,
        "byte_size": byte_size,
        "media_type": media_type,
        "status_code": 200,
    }


def _validated_operational_query_trace(
    value: object,
    *,
    response_structure_sha256: str,
) -> dict[str, object]:
    expected = {
        "schema_version",
        "query_attempt_id",
        "observed_request_count",
        "approved_request_count",
        "blocked_request_count",
        "query_attempt_count",
        "zero_retry_performed",
        "cache_refresh_count",
        "page_count",
        "request_method",
        "request_path",
        "resource_type",
        "response_status",
        "response_byte_size",
        "response_structure_sha256",
        "duration_ms",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ProtocolError("operational query trace fields are invalid")
    query_attempt_id = value.get("query_attempt_id")
    observed = value.get("observed_request_count")
    approved = value.get("approved_request_count")
    blocked = value.get("blocked_request_count")
    query_attempt_count = value.get("query_attempt_count")
    zero_retry_performed = value.get("zero_retry_performed")
    cache_refresh_count = value.get("cache_refresh_count")
    page_count = value.get("page_count")
    response_byte_size = value.get("response_byte_size")
    duration_ms = value.get("duration_ms")
    trace_digest = value.get("response_structure_sha256")
    invalid_fields = (
        (value.get("schema_version") != 1, "schema_version"),
        (
            not isinstance(query_attempt_id, str)
            or _QUERY_ATTEMPT_ID.fullmatch(query_attempt_id) is None,
            "query_attempt_id",
        ),
        (
            type(observed) is not int or not 1 <= observed <= 10_000,
            "observed_request_count",
        ),
        (type(approved) is not int, "approved_request_count"),
        (
            type(query_attempt_count) is not int
            or query_attempt_count not in {1, 2},
            "query_attempt_count",
        ),
        (approved != query_attempt_count, "approved_request_count"),
        (
            type(blocked) is not int or blocked < 0,
            "blocked_request_count",
        ),
        (
            type(observed) is int
            and type(approved) is int
            and type(blocked) is int
            and observed != approved + blocked,
            "request_reconciliation",
        ),
        (
            type(zero_retry_performed) is not bool
            or zero_retry_performed != (query_attempt_count == 2),
            "zero_retry_performed",
        ),
        (
            type(cache_refresh_count) is not int
            or type(query_attempt_count) is not int
            or not query_attempt_count
            <= cache_refresh_count
            <= query_attempt_count + 1,
            "cache_refresh_count",
        ),
        (
            type(page_count) is not int or page_count != 1,
            "page_count",
        ),
        (value.get("request_method") != "POST", "request_method"),
        (
            value.get("request_path") != _SETTLEMENT_LIST_PATH,
            "request_path",
        ),
        (
            value.get("resource_type") not in {"fetch", "xhr"},
            "resource_type",
        ),
        (value.get("response_status") != 200, "response_status"),
        (
            type(response_byte_size) is not int
            or not 1 <= response_byte_size <= 2 * 1024 * 1024,
            "response_byte_size",
        ),
        (
            trace_digest != response_structure_sha256,
            "response_structure_sha256",
        ),
        (
            type(duration_ms) is not int
            or not 0 <= duration_ms <= 120_000,
            "duration_ms",
        ),
    )
    for invalid, field_name in invalid_fields:
        if invalid:
            raise ProtocolError(
                f"operational query trace {field_name} is invalid"
            )
    return {key: value[key] for key in expected}


def _validated_prepare_result(
    value: object,
    *,
    command: BrowserCommand,
    ok: bool,
) -> dict[str, object] | None:
    is_prepare = isinstance(
        command,
        (
            PrepareAutomatedCommand,
            PrepareOperationalCompatCommand,
            PrepareSettlementFilterHandoffCommand,
            PrepareDailyFromAutomatedCommand,
            PrepareOperationalDailyCommand,
        ),
    )
    if value is None:
        if is_prepare and ok:
            raise ProtocolError("successful preparation requires safe probe metadata")
        return None
    if not is_prepare or not ok or not isinstance(value, Mapping):
        raise ProtocolError("prepare result is not allowed for this response")
    if isinstance(
        command,
        (PrepareDailyFromAutomatedCommand, PrepareOperationalDailyCommand),
    ):
        expected = {
            "schema_version",
            "evidence_kind",
            "cache_disabled_during_reload",
            "ignore_cache_reload",
            "cache_refresh_count",
            "fresh_query_response_observed",
            "page_count",
            "route",
        }
        if isinstance(command, PrepareOperationalDailyCommand):
            expected |= {
                "contract_subject_code",
                "contract_subject_confirmed",
            }
        cache_refresh_count = value.get("cache_refresh_count")
        if (
            set(value) != expected
            or value.get("schema_version") != 1
            or value.get("evidence_kind") != "chengfeng_daily_freshness"
            or value.get("cache_disabled_during_reload") is not True
            or value.get("ignore_cache_reload") is not True
            or type(cache_refresh_count) is not int
            or not 1 <= cache_refresh_count <= 2
            or value.get("fresh_query_response_observed") is not True
            or value.get("page_count") != 1
            or value.get("route") != "/wayBill"
            or (
                isinstance(command, PrepareOperationalDailyCommand)
                and (
                    value.get("contract_subject_code")
                    != command.contract_subject_code
                    or value.get("contract_subject_confirmed") is not True
                )
            )
        ):
            raise ProtocolError("daily freshness evidence is invalid")
        return {key: value[key] for key in expected}
    if isinstance(command, PrepareSettlementFilterHandoffCommand):
        expected = {
            "schema_version",
            "requested_count",
            "matched_count",
            "missing_count",
        }
        if set(value) != expected:
            raise ProtocolError("settlement filter result fields are invalid")
        requested_count = value.get("requested_count")
        matched_count = value.get("matched_count")
        missing_count = value.get("missing_count")
        if (
            value.get("schema_version") != 1
            or type(requested_count) is not int
            or not 1 <= requested_count <= 2000
            or type(matched_count) is not int
            or not 0 <= matched_count <= requested_count
            or type(missing_count) is not int
            or missing_count != requested_count - matched_count
        ):
            raise ProtocolError("settlement filter result values are invalid")
        return {key: value[key] for key in expected}
    required_fields = {
        "schema_version",
        "probe_kind",
        "operation",
        "metrics",
        "response_structure_sha256",
    }
    expected_fields = required_fields | (
        {
            "query_trace",
            "contract_subject_code",
            "contract_subject_confirmed",
        }
        if isinstance(command, PrepareOperationalCompatCommand)
        else set()
    )
    if set(value) != expected_fields:
        raise ProtocolError("prepare result fields are invalid")
    metrics = value.get("metrics")
    if not isinstance(metrics, Mapping) or set(metrics) != {
        "total_count",
        "list_length",
        "page_number",
        "page_size",
    }:
        raise ProtocolError("prepare result metrics are invalid")
    total_count = metrics.get("total_count")
    list_length = metrics.get("list_length")
    page_number = metrics.get("page_number")
    page_size = metrics.get("page_size")
    digest = value.get("response_structure_sha256")
    if (
        value.get("schema_version") != 1
        or value.get("probe_kind") != "chengfeng_settlement_list"
        or value.get("operation") != "list_waybills"
        or type(total_count) is not int
        or not 0 <= total_count <= 10_000_000
        or type(list_length) is not int
        or not 0 <= list_length <= 100
        or type(page_number) is not int
        or not 0 <= page_number <= 10_000
        or type(page_size) is not int
        or not 1 <= page_size <= 100
        or list_length > page_size
        or total_count < list_length
        or (total_count == 0 and list_length != 0)
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or (
            isinstance(command, PrepareOperationalCompatCommand)
            and (
                value.get("contract_subject_code")
                != command.contract_subject_code
                or value.get("contract_subject_confirmed") is not True
            )
        )
    ):
        raise ProtocolError("prepare result values are invalid")
    result = {
        "schema_version": 1,
        "probe_kind": "chengfeng_settlement_list",
        "operation": "list_waybills",
        "metrics": {
            "total_count": total_count,
            "list_length": list_length,
            "page_number": page_number,
            "page_size": page_size,
        },
        "response_structure_sha256": digest,
    }
    if isinstance(command, PrepareOperationalCompatCommand):
        result["query_trace"] = _validated_operational_query_trace(
            value.get("query_trace"),
            response_structure_sha256=digest,
        )
        result["contract_subject_code"] = command.contract_subject_code
        result["contract_subject_confirmed"] = True
    return result


def _validated_discovery(
    value: object,
    *,
    command: BrowserCommand,
    ok: bool,
    error_code: str | None,
) -> list[dict[str, object]] | None:
    if isinstance(command, ProbeSettlementViewsCommand):
        return _validated_settlement_view_probe(
            value,
            ok=ok,
        )
    is_daily_prepare = isinstance(
        command,
        (
            PrepareDailyCommand,
            PrepareDailyFromAutomatedCommand,
            PrepareOperationalDailyCommand,
        ),
    )
    is_daily_read = isinstance(command, ReadDailyJsonCommand)
    if not is_daily_prepare and not is_daily_read:
        return value  # type: ignore[return-value]
    changed_structure = (
        not ok
        and error_code == "browser_daily_response_contract_changed"
    )
    if is_daily_read:
        if value is None:
            return None
        if not changed_structure:
            raise ProtocolError(
                "daily read cannot emit discovery for this result"
            )
    if not ok:
        if value is not None and not changed_structure:
            raise ProtocolError(
                "failed daily command cannot emit discovery"
            )
        if not changed_structure:
            return None
    if not isinstance(value, list) or len(value) != 1:
        raise ProtocolError("daily command requires one observation")
    observation = value[0]
    if not isinstance(observation, Mapping) or set(observation) != {
        "method",
        "origin",
        "path",
        "path_sha256",
        "query_keys",
        "request_fields",
        "resource_kind",
        "response_status",
        "content_kind",
        "response_fields",
    }:
        raise ProtocolError("daily discovery fields are invalid")
    if (
        observation.get("method") != "POST"
        or observation.get("origin") != "https://pc.chengfengkuaiyun.com"
        or observation.get("path")
        != "/api/hz/orderItem/queryOrderItemListPC"
        or observation.get("path_sha256") is not None
        or observation.get("resource_kind") != "json_api"
        or observation.get("response_status") != 200
        or observation.get("content_kind") != "json"
        or observation.get("query_keys") not in ([], ["t"])
    ):
        raise ProtocolError("daily discovery values are invalid")
    request_fields = _validated_discovery_fields(
        observation.get("request_fields"),
        top_level_only=True,
    )
    response_fields = _validated_discovery_fields(
        observation.get("response_fields"),
        top_level_only=False,
    )
    request_paths = {field["path"] for field in request_fields}
    response_paths = {field["path"] for field in response_fields}
    if not {
        "$.loadStartTime",
        "$.loadEndTime",
        "$.receivePlace",
        "$.pageNumber",
        "$.pageSize",
    }.issubset(request_paths):
        raise ProtocolError("daily discovery shape is incomplete")
    if not changed_structure:
        nonempty_shape = {
            "$.data.list[].id",
            "$.data.list[].sn",
            "$.data.list[].carNumber",
            "$.data.list[].loadPunchDate",
            "$.data.total",
        }
        zero_shape = {"$.data.total"}
        if not nonempty_shape.issubset(response_paths) and response_paths != zero_shape:
            raise ProtocolError("daily discovery shape is incomplete")
    if changed_structure and not response_fields:
        raise ProtocolError("changed daily discovery has no response fields")
    return [
        {
            "method": "POST",
            "origin": "https://pc.chengfengkuaiyun.com",
            "path": "/api/hz/orderItem/queryOrderItemListPC",
            "path_sha256": None,
            "query_keys": list(observation["query_keys"]),
            "request_fields": request_fields,
            "resource_kind": "json_api",
            "response_status": 200,
            "content_kind": "json",
            "response_fields": response_fields,
        }
    ]


def _validated_settlement_view_probe(
    value: object,
    *,
    ok: bool,
) -> list[dict[str, object]] | None:
    if value is None:
        if ok:
            raise ProtocolError(
                "successful settlement view probe requires metadata"
            )
        return None
    if not ok or not isinstance(value, list) or len(value) != 1:
        raise ProtocolError("settlement view probe is not allowed")
    probe = value[0]
    if (
        not isinstance(probe, Mapping)
        or set(probe)
        != {
            "schema_version",
            "probe_kind",
            "operation",
            "views",
        }
        or probe.get("schema_version") != 1
        or probe.get("probe_kind") != "chengfeng_settlement_views"
        or probe.get("operation") != "list_waybills"
    ):
        raise ProtocolError("settlement view probe fields are invalid")
    raw_views = probe.get("views")
    if not isinstance(raw_views, list) or len(raw_views) != 2:
        raise ProtocolError("settlement view probe views are invalid")
    validated_views: list[dict[str, object]] = []
    for expected_view, raw_view in zip(
        ("settlement", "credit"),
        raw_views,
        strict=True,
    ):
        if (
            not isinstance(raw_view, Mapping)
            or set(raw_view)
            != {
                "view",
                "metrics",
                "response_structure_sha256",
            }
            or raw_view.get("view") != expected_view
        ):
            raise ProtocolError("settlement view metadata is invalid")
        metrics = raw_view.get("metrics")
        if not isinstance(metrics, Mapping) or set(metrics) != {
            "total_count",
            "list_length",
            "page_number",
            "page_size",
        }:
            raise ProtocolError("settlement view metrics are invalid")
        total_count = metrics.get("total_count")
        list_length = metrics.get("list_length")
        page_number = metrics.get("page_number")
        page_size = metrics.get("page_size")
        digest = raw_view.get("response_structure_sha256")
        if (
            type(total_count) is not int
            or not 0 <= total_count <= 10_000_000
            or type(list_length) is not int
            or not 0 <= list_length <= 100
            or type(page_number) is not int
            or not 0 <= page_number <= 10_000
            or type(page_size) is not int
            or not 1 <= page_size <= 100
            or list_length > page_size
            or total_count < list_length
            or (total_count == 0 and list_length != 0)
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise ProtocolError("settlement view metric values are invalid")
        validated_views.append(
            {
                "view": expected_view,
                "metrics": {
                    "total_count": total_count,
                    "list_length": list_length,
                    "page_number": page_number,
                    "page_size": page_size,
                },
                "response_structure_sha256": digest,
            }
        )
    return [
        {
            "schema_version": 1,
            "probe_kind": "chengfeng_settlement_views",
            "operation": "list_waybills",
            "views": validated_views,
        }
    ]


def _validated_discovery_fields(
    value: object,
    *,
    top_level_only: bool,
) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 500:
        raise ProtocolError("daily discovery field list is invalid")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {"path", "type"}:
            raise ProtocolError("daily discovery field is invalid")
        path = raw.get("path")
        field_type = raw.get("type")
        if (
            not isinstance(path, str)
            or _DISCOVERY_FIELD_PATH.fullmatch(path) is None
            or path in seen
            or (top_level_only and (path.count(".") != 1 or "[]" in path))
            or any(
                marker in path.casefold()
                for marker in (
                    "authorization",
                    "cookie",
                    "password",
                    "secret",
                    "signature",
                    "token",
                )
            )
            or field_type
            not in {
                "null",
                "boolean",
                "integer",
                "number",
                "string",
                "empty_array",
            }
        ):
            raise ProtocolError("daily discovery field value is invalid")
        seen.add(path)
        result.append({"path": path, "type": field_type})
    return result
