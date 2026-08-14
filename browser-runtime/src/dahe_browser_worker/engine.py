from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import suppress
from datetime import datetime, timedelta
from pathlib import Path
from threading import Event, Lock
from time import monotonic
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)
from uuid import uuid4

from dahe_browser_worker.protocol import (
    CHENGFENG_IMAGE_HOSTS,
    CaptureOperationalWholeRunCommand,
    InitializeCommand,
    InitializeHeadlessCommand,
    ReadDailyJsonCommand,
    ReadImageCommand,
    ReadJsonCommand,
    ReadOperationalBatchCommand,
    SmokeCommand,
    is_approved_image_read_url,
)
from dahe_browser_worker.windows_credentials import (
    CredentialUnavailableError,
    read_saved_credential,
)

_SENSITIVE_PATH = re.compile(
    r"(?i)(?:login|logout|auth|token|captcha|password|passwd|sms|verify|verification)"
)
_IMAGE_SUFFIXES = (".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp")
_CAPTURE_RESOURCE_TYPES = {"fetch", "xhr", "image"}
_FIELD_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,120}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,120}$")
_CHENGFENG_ORIGIN = "https://pc.chengfengkuaiyun.com"
CHENGFENG_HUMAN_LOGIN_ENTRY = f"{_CHENGFENG_ORIGIN}/billablewaybill"
CHENGFENG_LIST_PATH = (
    "/api/order-center-server/app/clientOrderItem/queryWaitSettlementOrderItemListPC"
)
CHENGFENG_HISTORICAL_ENTRY = f"{_CHENGFENG_ORIGIN}/rejectedReturnBill"
CHENGFENG_HISTORICAL_LIST_PATH = (
    "/api/order-center-server/app/clientOrderItem/queryClientAllFinishSettlementOrderItemListPC"
)
CHENGFENG_DETAIL_PATH = "/api/order-center-server/app/clientOrderItem/getOrderItemDetailsByIdPC"
CHENGFENG_DAILY_ENTRY = f"{_CHENGFENG_ORIGIN}/wayBill"
CHENGFENG_DAILY_LIST_PATH = "/api/hz/orderItem/queryOrderItemListPC"
CONTRACT_SUBJECT_OPTION_TEXT = {
    "shanxi_guienbo": "山西贵恩博信息科技有限公司",
    "shanghai_jinyisheng": "上海晋亿晟信息科技有限公司",
}
CONTRACT_SUBJECT_OPTION_TIMEOUT_MS = 10_000
CONTRACT_SUBJECT_STABLE_POLL_COUNT = 8
_DAILY_BOOTSTRAP_READ_PATHS = frozenset(
    {
        "/api/hz/evaluate/getEvaluateContent",
        "/api/hz/pc/finance/app/getFinancialAlertsPc",
        "/api/hz/user/auth/getBusinessTaxSource",
        "/api/order-center-server/app/order/getPublicOrderConfig",
        "/api/order-center-server/userlimitconfig/queryUserLimitInfos",
        ("/api/statistics-center-server/order/statistics/businessExportWeightPageButtonValidation"),
        ("/api/statistics-center-server/order/statistics/selectBusinessLoadAdditionalStatusConfig"),
        "/api/user-center-server/business/auth/selectTaxSourceList",
        "/api/user-center-server/business/user/getUserInfoAndFlag",
    }
)
CURRENT_PENDING_SETTLEMENT_SCOPE = "current"
HISTORICAL_SETTLED_SCOPE = "settled_history"
APPROVED_SETTLEMENT_SCOPES = frozenset(
    {
        CURRENT_PENDING_SETTLEMENT_SCOPE,
        HISTORICAL_SETTLED_SCOPE,
    }
)
HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS = 60_000
CHENGFENG_PAGE_HYDRATION_WAIT_MS = 5_000
CHENGFENG_PAGE_HYDRATION_POLL_MS = 250
SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS = 60_000
OPERATIONAL_UI_IDLE_TIMEOUT_MS = 15_000
SESSION_HEADER_CAPTURE_WAIT_STEPS = 50
SESSION_HEADER_CAPTURE_POLL_MS = 100
JSON_READ_TIMEOUT_MS = 30_000
IMAGE_READ_TIMEOUT_MS = 60_000
MAX_JSON_READ_BYTES = 2 * 1024 * 1024
MAX_IMAGE_READ_BYTES = 25 * 1024 * 1024
MAX_OPERATIONAL_BATCH_BYTES = 2 * 1024 * 1024 * 1024
MAX_SESSION_HEADER_COUNT = 64
MAX_SESSION_HEADER_VALUE_LENGTH = 8 * 1024
MAX_SESSION_HEADER_TOTAL_LENGTH = 32 * 1024
MAX_PRIVATE_DAILY_BODY_BYTES = 64 * 1024
MAX_PRIVATE_DAILY_VALUE_DEPTH = 6
MAX_NATIVE_LIST_TOTAL_COUNT = 10_000_000
MAX_NATIVE_LIST_LENGTH = 100
MAX_NATIVE_LIST_PAGE_NUMBER = 10_000
NATIVE_LIST_PROBE_SCHEMA_VERSION = 1
DETAIL_IMAGE_GRANT_TTL_SECONDS = 5 * 60
DAILY_NATIVE_CAPTURE_WAIT_STEPS = 50
DAILY_NATIVE_CAPTURE_POLL_MS = 100
_DAILY_CONTROLLED_FIELDS = {
    "loadStartTime",
    "loadEndTime",
    "receivePlace",
    "pageNumber",
    "pageSize",
}
_DAILY_SCOPE_FIELDS = {
    "loadStartTime",
    "loadEndTime",
    "receivePlace",
}
_DYNAMIC_DAILY_BASELINE_FIELDS = {
    "deptCode",
    "order",
    "pageNumber",
    "pageSize",
    "sortParams",
}
_PRIVATE_DAILY_SENSITIVE_MARKERS = (
    "authorization",
    "cookie",
    "password",
    "secret",
    "signature",
    "token",
)
_OWNED_READ_RESULT_DIRECTORY = re.compile(r"^(?:daily|read)-[0-9a-f]{32}$")
_OWNED_READ_RESULT_FILES = frozenset(
    {
        ".payload.part",
        "payload.bmp",
        "payload.jpg",
        "payload.json",
        "payload.png",
        "payload.tiff",
        "payload.webp",
    }
)
_REPARSE_POINT_ATTRIBUTE = getattr(
    stat,
    "FILE_ATTRIBUTE_REPARSE_POINT",
    0x400,
)
_SESSION_HEADER_BLOCKLIST = {
    "accept-encoding",
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "set-cookie",
}
_IMAGE_MEDIA_TYPES = {
    "image/bmp": ".bmp",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/tiff": ".tiff",
    "image/webp": ".webp",
}
_IMAGE_MEDIA_TYPE_ALIASES = {
    # Huawei OBS can serve a valid JPEG with this widely used nonstandard
    # alias. Normalize it only after the file signature is verified.
    "image/jpg": "image/jpeg",
}

_OPERATIONAL_BATCH_FETCH_SCRIPT = """
async ({requests, headers, concurrency, timeoutMs}) => {
  const results = new Array(requests.length);
  let nextIndex = 0;
  const worker = async () => {
    while (true) {
      const index = nextIndex++;
      if (index >= requests.length) return;
      const request = requests[index];
      const body = new URLSearchParams({id: request.platformWaybillId});
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
      let response;
      try {
        response = await fetch(request.url, {
          method: "POST",
          headers: {
            ...headers,
            "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
          },
          body,
          credentials: "include",
          redirect: "manual",
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }
      results[index] = {
        index,
        status: response.status,
        redirected: response.redirected,
        contentType: response.headers.get("content-type") || "",
        body: await response.text(),
      };
    }
  };
  await Promise.all(
    Array.from(
      {length: Math.min(concurrency, requests.length)},
      () => worker(),
    ),
  );
  return results;
}
"""

_OPERATIONAL_LIST_FETCH_SCRIPT = """
async ({url, headers, body}) => {
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    credentials: "include",
    redirect: "manual",
  });
  return {
    status: response.status,
    redirected: response.redirected,
    contentType: response.headers.get("content-type") || "",
    body: await response.text(),
  };
}
"""


class LoginEntryError(RuntimeError):
    """Raised when the fixed human-login entry cannot be shown safely."""


class BrowserReadError(RuntimeError):
    """A bounded read failure that never carries platform values."""

    def __init__(
        self,
        code: str,
        *,
        safe_discovery: list[dict[str, object]] | None = None,
    ) -> None:
        super().__init__("controlled read failed")
        self.code = code
        self.safe_discovery = safe_discovery


def _validated_image_media_type(declared: str, content: bytes) -> str:
    """Normalize one approved image media type after checking its signature."""

    media_type = _IMAGE_MEDIA_TYPE_ALIASES.get(declared, declared)
    signature_matches = {
        "image/bmp": content.startswith(b"BM"),
        "image/jpeg": content.startswith(b"\xff\xd8\xff"),
        "image/png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/tiff": content.startswith((b"II*\x00", b"MM\x00*")),
        "image/webp": (len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP"),
    }
    if media_type not in _IMAGE_MEDIA_TYPES or not signature_matches.get(
        media_type,
        False,
    ):
        raise BrowserReadError("browser_image_contract_changed")
    return media_type


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _bounded_http_fetch(
    *,
    url: str,
    method: str,
    headers: Mapping[str, str],
    body: bytes | None,
    maximum_bytes: int,
    expected_image: bool,
    timeout_seconds: float,
) -> tuple[bytes, str, str | None]:
    request = Request(
        url,
        data=body,
        headers=dict(headers),
        method=method,
    )
    try:
        response = build_opener(_RejectRedirects()).open(
            request,
            timeout=timeout_seconds,
        )
    except HTTPError as exc:
        status = int(exc.code)
        with suppress(Exception):
            exc.close()
        if status in {401, 403}:
            raise BrowserReadError("browser_read_login_required") from exc
        if status == 429:
            raise BrowserReadError("browser_read_rate_limited") from exc
        if 500 <= status < 600:
            raise BrowserReadError("browser_read_server_transient") from exc
        if 300 <= status < 400:
            raise BrowserReadError("browser_read_redirect_rejected") from exc
        raise BrowserReadError("browser_read_http_failed") from exc
    except (OSError, TimeoutError, URLError) as exc:
        raise BrowserReadError("browser_read_network_failed") from exc
    try:
        status = int(response.status)
        media_type = (
            str(response.headers.get("content-type", "")).split(";", 1)[0].strip().casefold()
        )
        validator_sha256 = _image_validator_sha256(
            response.headers,
            media_type=media_type,
        )
        if status != 200:
            raise BrowserReadError("browser_read_http_failed")
        if (
            not expected_image
            and media_type != "application/json"
            and not media_type.endswith("+json")
        ):
            raise BrowserReadError("browser_read_contract_changed")
        content = response.read(maximum_bytes + 1)
    except BrowserReadError:
        raise
    except Exception as exc:
        raise BrowserReadError("browser_read_network_failed") from exc
    finally:
        with suppress(Exception):
            response.close()
    if not content or len(content) > maximum_bytes:
        raise BrowserReadError("browser_read_size_invalid")
    if expected_image:
        media_type = _validated_image_media_type(media_type, content)
    return (
        content,
        (media_type if expected_image else "application/json"),
        validator_sha256 if expected_image else None,
    )


def _image_validator_sha256(
    headers: Mapping[str, object],
    *,
    media_type: str,
) -> str | None:
    """Hash only stable, non-sensitive HTTP validators."""

    etag = str(headers.get("etag", "")).strip()
    last_modified = str(headers.get("last-modified", "")).strip()
    if not etag and not last_modified:
        return None
    canonical = json.dumps(
        {
            "etag": etag,
            "last_modified": last_modified,
            "media_type": media_type,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _bounded_http_image_probe(
    *,
    url: str,
    headers: Mapping[str, str],
    timeout_seconds: float,
    unsupported_hosts: set[str] | None = None,
) -> tuple[str, str] | None:
    """Return a trusted validator without downloading the image body."""

    hostname = (urlsplit(url).hostname or "").casefold()
    fully_unsupported_key = f"!{hostname}"
    if unsupported_hosts is not None and fully_unsupported_key in unsupported_hosts:
        return None
    skip_head = unsupported_hosts is not None and hostname in unsupported_hosts
    request_headers = dict(headers)
    request = Request(
        url,
        headers=request_headers,
        method=("GET" if skip_head else "HEAD"),
    )
    if skip_head:
        request.add_header("Range", "bytes=0-0")
    try:
        response = build_opener(_RejectRedirects()).open(
            request,
            timeout=timeout_seconds,
        )
    except HTTPError as exc:
        status = int(exc.code)
        with suppress(Exception):
            exc.close()
        if not skip_head and status in {401, 403, 405, 501}:
            # A signed evidence host may permit GET while denying optional
            # HEAD probes. Retry once with a one-byte Range GET so a stable
            # validator can still prove the cached body current without
            # transferring or staging the complete image.
            if unsupported_hosts is not None and hostname:
                unsupported_hosts.add(hostname)
            return _bounded_http_image_probe(
                url=url,
                headers=headers,
                timeout_seconds=timeout_seconds,
                unsupported_hosts=unsupported_hosts,
            )
        if status == 429:
            raise BrowserReadError("browser_read_rate_limited") from exc
        if 500 <= status < 600:
            raise BrowserReadError("browser_read_server_transient") from exc
        if 300 <= status < 400:
            raise BrowserReadError("browser_read_redirect_rejected") from exc
        return None
    except (OSError, TimeoutError, URLError):
        if unsupported_hosts is not None and hostname:
            unsupported_hosts.add(hostname)
        return None
    try:
        if int(response.status) not in {200, 206}:
            return None
        media_type = (
            str(response.headers.get("content-type", "")).split(";", 1)[0].strip().casefold()
        )
        if media_type not in _IMAGE_MEDIA_TYPES:
            return None
        validator_sha256 = _image_validator_sha256(
            response.headers,
            media_type=media_type,
        )
        if validator_sha256 is None:
            # A successful HEAD without ETag or Last-Modified cannot prove
            # that cached evidence is current. Remember the host for this
            # worker session so later images go straight to the authoritative
            # bounded GET instead of paying for another useless probe.
            if unsupported_hosts is not None and hostname:
                if skip_head:
                    unsupported_hosts.add(fully_unsupported_key)
                    return None
                unsupported_hosts.add(hostname)
                return _bounded_http_image_probe(
                    url=url,
                    headers=headers,
                    timeout_seconds=timeout_seconds,
                    unsupported_hosts=unsupported_hosts,
                )
            return None
        if skip_head and int(response.status) == 206:
            content_range = str(response.headers.get("content-range", "")).strip()
            if not content_range.startswith("bytes 0-0/"):
                return None
        return media_type, validator_sha256
    except Exception:
        return None
    finally:
        with suppress(Exception):
            response.close()


def _assert_business_landing(
    url: str,
    *,
    response_status: int,
    expected_path: str,
) -> None:
    """Accept only the fixed business entry or its same-origin login redirect."""

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise LoginEntryError("login landing URL is invalid") from exc
    exact_origin = (
        parsed.scheme == "https"
        and parsed.hostname == "pc.chengfengkuaiyun.com"
        and port is None
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    )
    approved_path = (parsed.path == expected_path and not parsed.query) or (
        parsed.path == "/login" or parsed.path.startswith("/login/")
    )
    if not exact_origin or not approved_path or response_status < 200 or response_status >= 400:
        raise LoginEntryError("browser did not reach the approved login entry")


def assert_login_landing(url: str, *, response_status: int) -> None:
    _assert_business_landing(
        url,
        response_status=response_status,
        expected_path="/billablewaybill",
    )


def _open_human_login_entry(page: Any) -> None:
    try:
        response = page.goto(
            CHENGFENG_HUMAN_LOGIN_ENTRY,
            wait_until="commit",
            timeout=HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS,
        )
        if response is None:
            raise LoginEntryError("login navigation returned no response")
        assert_login_landing(
            str(getattr(page, "url", "")),
            response_status=int(getattr(response, "status", 0)),
        )
        page.bring_to_front()
    except LoginEntryError:
        raise
    except Exception as exc:
        raise LoginEntryError("approved login entry could not be opened") from exc


def _trusted_edge_executable(
    environment: Mapping[str, str] | None = None,
) -> Path | None:
    values = {
        key.upper(): value
        for key, value in (os.environ if environment is None else environment).items()
        if value
    }
    for key in ("PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432"):
        raw_root = values.get(key)
        if raw_root is None:
            continue
        root = Path(raw_root)
        if not root.is_absolute() or root.is_symlink():
            continue
        candidate = root / "Microsoft" / "Edge" / "Application" / "msedge.exe"
        try:
            resolved_root = root.resolve(strict=True)
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(resolved_root)
        except (OSError, ValueError):
            continue
        if candidate.is_symlink() or not resolved.is_file():
            continue
        return resolved
    return None


def _browser_candidates() -> tuple[tuple[str, Path | None], ...]:
    candidates: list[tuple[str, Path | None]] = [("chromium", None)]
    edge = _trusted_edge_executable()
    if edge is not None:
        candidates.append(("msedge", edge))
    return tuple(candidates)


def _json_fields(value: object, *, prefix: str = "$", limit: int = 500) -> list[dict[str, str]]:
    fields: list[dict[str, str]] = []

    def visit(current: object, path: str) -> None:
        if len(fields) >= limit:
            return
        if isinstance(current, dict):
            for raw_key in sorted(current, key=str):
                if not isinstance(raw_key, str) or not _FIELD_NAME.fullmatch(raw_key):
                    continue
                lowered = raw_key.casefold()
                if any(
                    marker in lowered
                    for marker in (
                        "password",
                        "passwd",
                        "cookie",
                        "authorization",
                        "token",
                        "secret",
                        "signature",
                        "accesskey",
                    )
                ):
                    continue
                visit(current[raw_key], f"{path}.{raw_key}")
            return
        if isinstance(current, list):
            if current:
                visit(current[0], f"{path}[]")
            else:
                fields.append({"path": f"{path}[]", "type": "empty_array"})
            return
        value_type = (
            "null"
            if current is None
            else "boolean"
            if type(current) is bool
            else "integer"
            if type(current) is int
            else "number"
            if type(current) is float
            else "string"
            if type(current) is str
            else "unknown"
        )
        fields.append({"path": path, "type": value_type})

    visit(value, prefix)
    return fields


def _request_observation(request: Any) -> dict[str, object] | None:
    method = str(getattr(request, "method", "")).upper()
    url = str(getattr(request, "url", ""))
    resource_type = str(getattr(request, "resource_type", "")).casefold()
    if method not in {"GET", "POST"} or resource_type not in _CAPTURE_RESOURCE_TYPES:
        return None
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or not parsed.path.startswith("/")
        or _SENSITIVE_PATH.search(parsed.path)
    ):
        return None
    origin = f"https://{hostname.casefold()}"
    query_keys = sorted(
        {
            key
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
            if _FIELD_NAME.fullmatch(key)
        }
    )
    is_image = resource_type == "image" or parsed.path.casefold().endswith(_IMAGE_SUFFIXES)
    request_fields: list[dict[str, str]] = []
    if method == "POST":
        try:
            post_data = request.post_data_json
        except Exception:
            post_data = None
        if post_data is not None:
            request_fields = _json_fields(post_data)
    return {
        "method": method,
        "origin": origin,
        "path": None if is_image else parsed.path,
        "path_sha256": (
            hashlib.sha256(parsed.path.encode("utf-8")).hexdigest() if is_image else None
        ),
        "query_keys": query_keys,
        "request_fields": request_fields,
        "resource_kind": "image" if is_image else "json_api",
        "response_status": None,
        "content_kind": None,
        "response_fields": [],
    }


def _session_request_shape(
    request: Any,
    *,
    expected_path: str = CHENGFENG_LIST_PATH,
) -> str:
    method = str(getattr(request, "method", "")).upper()
    resource_type = str(getattr(request, "resource_type", "")).casefold()
    if method != "POST":
        return "method_mismatch"
    if resource_type not in {"fetch", "xhr"}:
        return "resource_mismatch"
    try:
        parsed = urlsplit(str(getattr(request, "url", "")))
        port = parsed.port
    except ValueError:
        return "url_invalid"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "pc.chengfengkuaiyun.com"
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
    ):
        return "origin_mismatch"
    if parsed.fragment:
        return "url_invalid"
    if parsed.path == expected_path:
        return "query_present" if parsed.query else "approved"
    if parsed.path.casefold().endswith(f"/{expected_path.rsplit('/', 1)[-1].casefold()}"):
        return "list_path_variant"
    if parsed.path.startswith("/api/"):
        return "same_origin_other_api"
    return "same_origin_non_api"


def _is_session_header_request(
    request: Any,
    *,
    expected_path: str = CHENGFENG_LIST_PATH,
) -> bool:
    return _session_request_shape(
        request,
        expected_path=expected_path,
    ) in {"approved", "query_present"}


def _session_headers_from_request(
    request: Any,
    *,
    expected_path: str = CHENGFENG_LIST_PATH,
) -> dict[str, str] | None:
    """Copy only a bounded approved list request's headers into worker memory."""

    if not _is_session_header_request(
        request,
        expected_path=expected_path,
    ):
        return None
    try:
        raw_headers = request.all_headers()
    except Exception:
        return None
    if not isinstance(raw_headers, Mapping):
        return None
    headers: dict[str, str] = {}
    total_length = 0
    for raw_name, raw_value in raw_headers.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            continue
        name = raw_name.casefold()
        if (
            name in _SESSION_HEADER_BLOCKLIST
            or not _HEADER_NAME.fullmatch(name)
            or not raw_value
            or len(raw_value) > MAX_SESSION_HEADER_VALUE_LENGTH
            or "\r" in raw_value
            or "\n" in raw_value
            or "\x00" in raw_value
        ):
            continue
        next_total = total_length + len(name) + len(raw_value)
        if len(headers) >= MAX_SESSION_HEADER_COUNT or next_total > MAX_SESSION_HEADER_TOTAL_LENGTH:
            return None
        headers[name] = raw_value
        total_length = next_total
    return headers or None


def _private_list_fixed_values_from_request(
    request: Any,
) -> dict[str, str | int] | None:
    """Keep only the two bounded UI-owned list values in worker memory."""

    if not _is_session_header_request(request):
        return None
    try:
        post_data = request.post_data_json
    except Exception:
        return None
    if not isinstance(post_data, Mapping):
        return None
    order = post_data.get("order")
    query_type = post_data.get("queryType")
    settle_query_type = post_data.get("settleQueryType")
    if order not in {"asc", "desc"}:
        return None
    if not isinstance(query_type, str) or (
        query_type != ""
        and (len(query_type) != 1 or not query_type.isascii() or not query_type.isdigit())
    ):
        return None
    if type(settle_query_type) is not int or not 1 <= settle_query_type <= 9:
        return None
    return {
        "order": order,
        "queryType": query_type,
        "settleQueryType": settle_query_type,
    }


def _historical_list_fixed_values_from_request(
    request: Any,
) -> dict[str, str] | None:
    """Keep only the bounded historical department identity in worker memory."""

    if not _is_session_header_request(
        request,
        expected_path=CHENGFENG_HISTORICAL_LIST_PATH,
    ):
        return None
    try:
        post_data = request.post_data_json
    except Exception:
        return None
    if not isinstance(post_data, Mapping) or set(post_data) != {
        "deptCode",
        "pageNumber",
        "pageSize",
        "sortParams",
    }:
        return None
    if (
        _normalized_private_list_body_sha256(
            post_data,
            scope=HISTORICAL_SETTLED_SCOPE,
        )
        is None
    ):
        return None
    dept_code = post_data.get("deptCode")
    if (
        not isinstance(dept_code, str)
        or dept_code != dept_code.strip()
        or len(dept_code) > 64
        or not dept_code.isascii()
        or (dept_code != "" and not dept_code.isalnum())
    ):
        return None
    return {"deptCode": dept_code}


def _private_list_cache_query_from_request(
    request: Any,
    *,
    expected_path: str = CHENGFENG_LIST_PATH,
) -> str | None:
    """Keep only the bounded official list cache key in worker memory."""

    if not _is_session_header_request(
        request,
        expected_path=expected_path,
    ):
        return None
    try:
        parsed = urlsplit(str(getattr(request, "url", "")))
    except ValueError:
        return None
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if len(pairs) != 1 or pairs[0][0] != "t":
        return None
    value = pairs[0][1]
    if not value.isascii() or not value.isdigit() or not 10 <= len(value) <= 20:
        return None
    return f"t={value}"


def _normalized_private_list_body_sha256(
    body: Mapping[str, object],
    *,
    scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
) -> str | None:
    """Hash a bounded flat list body after normalizing only paging."""

    if scope == HISTORICAL_SETTLED_SCOPE:
        if set(body) != {
            "deptCode",
            "pageNumber",
            "pageSize",
            "sortParams",
        }:
            return None
        dept_code = body.get("deptCode")
        page_number = body.get("pageNumber")
        page_size = body.get("pageSize")
        sort_params = body.get("sortParams")
        if (
            not isinstance(dept_code, str)
            or dept_code != dept_code.strip()
            or len(dept_code) > 64
            or not dept_code.isascii()
            or (dept_code != "" and not dept_code.isalnum())
            or type(page_number) is not int
            or not 1 <= page_number <= MAX_NATIVE_LIST_PAGE_NUMBER
            or type(page_size) is not int
            or not 1 <= page_size <= MAX_NATIVE_LIST_LENGTH
            or type(sort_params) is not list
            or sort_params
        ):
            return None
        historical_normalized = {
            "deptCode": dept_code,
            "pageNumber": 0,
            "pageSize": 0,
            "sortParams": [],
        }
        canonical = json.dumps(
            historical_normalized,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()
    if scope != CURRENT_PENDING_SETTLEMENT_SCOPE:
        return None
    if not 1 <= len(body) <= 128:
        return None
    normalized: dict[str, object] = {}
    for key, value in body.items():
        folded_key = key.casefold() if isinstance(key, str) else ""
        if (
            not isinstance(key, str)
            or not _FIELD_NAME.fullmatch(key)
            or any(
                marker in folded_key
                for marker in (
                    "authorization",
                    "cookie",
                    "credential",
                    "password",
                    "secret",
                    "signature",
                    "token",
                )
            )
        ):
            return None
        if key in {"pageNumber", "pageSize"}:
            if type(value) is not int or value <= 0:
                return None
            normalized[key] = 0
            continue
        if isinstance(value, str):
            if len(value) > 512 or any(
                ord(character) < 32 and character not in "\t" for character in value
            ):
                return None
            normalized[key] = value
            continue
        if isinstance(value, list):
            if value:
                return None
            normalized[key] = []
            continue
        if isinstance(value, Mapping):
            if value:
                return None
            normalized[key] = {}
            continue
        if value is None or type(value) is bool:
            normalized[key] = value
            continue
        if type(value) is int and -1_000_000_000 <= value <= 1_000_000_000:
            normalized[key] = value
            continue
        return None
    if (
        len(
            json.dumps(
                normalized,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        > 65_536
    ):
        return None
    canonical = json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _private_list_body_from_request(
    request: Any,
    *,
    scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
) -> dict[str, object] | None:
    expected_path = (
        CHENGFENG_HISTORICAL_LIST_PATH if scope == HISTORICAL_SETTLED_SCOPE else CHENGFENG_LIST_PATH
    )
    if not _is_session_header_request(request, expected_path=expected_path):
        return None
    try:
        post_data = request.post_data_json
    except Exception:
        return None
    if not isinstance(post_data, Mapping):
        return None
    if _normalized_private_list_body_sha256(post_data, scope=scope) is None:
        return None
    return {
        str(key): list(value) if isinstance(value, list) else value
        for key, value in post_data.items()
    }


def _private_list_body_sha256_from_request(
    request: Any,
    *,
    scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
) -> str | None:
    body = _private_list_body_from_request(request, scope=scope)
    if body is None:
        return None
    return _normalized_private_list_body_sha256(body, scope=scope)


def _private_list_structure_observation(
    body: Mapping[str, object],
    *,
    scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
) -> dict[str, object]:
    request_fields: list[dict[str, str]] = []
    for name in sorted(body):
        value = body[name]
        if isinstance(value, list):
            path = f"$.{name}[]"
            value_type = "empty_array"
        elif type(value) is int:
            path = f"$.{name}"
            value_type = "integer"
        else:
            path = f"$.{name}"
            value_type = "string"
        request_fields.append({"path": path, "type": value_type})
    return {
        "method": "POST",
        "origin": _CHENGFENG_ORIGIN,
        "path": (
            CHENGFENG_HISTORICAL_LIST_PATH
            if scope == HISTORICAL_SETTLED_SCOPE
            else CHENGFENG_LIST_PATH
        ),
        "path_sha256": None,
        "query_keys": ["t"],
        "request_fields": request_fields,
        "resource_kind": "json_api",
        "response_status": None,
        "content_kind": None,
        "response_fields": [],
    }


def _response_structure_sha256(payload: object) -> str:
    """Hash response field names and types without retaining response values."""

    fields = _json_fields(payload)
    canonical = json.dumps(
        fields,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _safe_native_list_probe(
    payload: object,
    *,
    scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
    requested_page_number: int = 1,
    requested_page_size: int = 30,
) -> dict[str, object]:
    """Derive the only value-free metadata allowed from a native list response."""

    if (
        not isinstance(payload, Mapping)
        or type(requested_page_number) is not int
        or not 1 <= requested_page_number <= MAX_NATIVE_LIST_PAGE_NUMBER
        or type(requested_page_size) is not int
        or not 1 <= requested_page_size <= MAX_NATIVE_LIST_LENGTH
    ):
        raise BrowserReadError("browser_session_native_probe_contract_changed")
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise BrowserReadError("browser_session_native_probe_contract_changed")
    items = data.get("list")
    if scope == HISTORICAL_SETTLED_SCOPE:
        raw_total_count = data.get("total")
        if (
            not isinstance(items, list)
            or any(
                not isinstance(item, Mapping)
                or type(item.get("orderItemId")) is not str
                or not item.get("orderItemId")
                or type(item.get("orderItemSn")) is not str
                or not item.get("orderItemSn")
                or type(item.get("carNumber")) is not str
                for item in items
            )
            or type(raw_total_count) is not str
            or not raw_total_count
            or not raw_total_count.isascii()
            or not raw_total_count.isdigit()
            or (len(raw_total_count) > 1 and raw_total_count.startswith("0"))
        ):
            raise BrowserReadError("browser_session_native_probe_contract_changed")
        historical_total_count = int(raw_total_count)
        list_length = len(items)
        if (
            historical_total_count > MAX_NATIVE_LIST_TOTAL_COUNT
            or list_length > requested_page_size
            or list_length > MAX_NATIVE_LIST_LENGTH
            or historical_total_count < list_length
            or (historical_total_count == 0 and list_length != 0)
        ):
            raise BrowserReadError("browser_session_native_probe_contract_changed")
        return {
            "schema_version": NATIVE_LIST_PROBE_SCHEMA_VERSION,
            "probe_kind": "chengfeng_settlement_list",
            "operation": "list_waybills",
            "metrics": {
                "total_count": historical_total_count,
                "list_length": list_length,
                "page_number": requested_page_number,
                "page_size": requested_page_size,
            },
            "response_structure_sha256": _response_structure_sha256(payload),
        }
    if scope != CURRENT_PENDING_SETTLEMENT_SCOPE:
        raise BrowserReadError("browser_session_native_probe_contract_changed")
    raw_page_number = data.get("pageNo")
    raw_page_size = data.get("pageSize")
    total_count = data.get("total")
    if (
        not isinstance(items, list)
        or any(not isinstance(item, Mapping) for item in items)
        or type(raw_page_number) is not int
        or type(raw_page_size) is not int
        or not 0 <= raw_page_size <= MAX_NATIVE_LIST_LENGTH
        or type(total_count) is not int
        or not 0 <= total_count <= MAX_NATIVE_LIST_TOTAL_COUNT
    ):
        raise BrowserReadError("browser_session_native_probe_contract_changed")
    list_length = len(items)
    reversed_request_pagination = (
        list_length > 0
        and raw_page_number == requested_page_size
        and raw_page_size == requested_page_number
    )
    accepted_page_numbers = {
        requested_page_number,
        requested_page_number - 1,
    }
    if reversed_request_pagination:
        # Chengfeng's current pending-settlement response has also been
        # observed to reverse the two request pagination values: the requested
        # page size appears in pageNo and the requested page number appears in
        # pageSize. Only that exact paired representation is accepted. The
        # request remains authoritative and cross-page identity and total
        # reconciliation still reject stale or repeated pages.
        accepted_page_numbers.add(requested_page_size)
    if raw_page_number not in accepted_page_numbers:
        total_pages = data.get("totalPage")
        if raw_page_number == requested_page_number + 1:
            page_mismatch_code = "browser_session_native_probe_page_number_ahead_one"
        elif type(total_pages) is int and raw_page_number == total_pages:
            page_mismatch_code = "browser_session_native_probe_page_number_is_total_pages"
        elif raw_page_number == total_count:
            page_mismatch_code = "browser_session_native_probe_page_number_is_total_count"
        elif raw_page_number == raw_page_size:
            page_mismatch_code = "browser_session_native_probe_page_number_is_page_size"
        elif raw_page_number > requested_page_number:
            page_mismatch_code = "browser_session_native_probe_page_number_ahead_many"
        elif raw_page_number < requested_page_number - 1:
            page_mismatch_code = "browser_session_native_probe_page_number_behind_many"
        else:
            page_mismatch_code = "browser_session_native_probe_page_number_mismatch"
        raise BrowserReadError(page_mismatch_code)
    if list_length > requested_page_size:
        raise BrowserReadError("browser_session_native_probe_list_exceeds_requested_page_size")
    if list_length > MAX_NATIVE_LIST_LENGTH:
        raise BrowserReadError("browser_session_native_probe_contract_changed")
    if not reversed_request_pagination and raw_page_size != 0 and list_length > raw_page_size:
        raise BrowserReadError("browser_session_native_probe_list_exceeds_response_page_size")
    if total_count < list_length:
        raise BrowserReadError("browser_session_native_probe_total_below_list_length")
    if not reversed_request_pagination and raw_page_size not in {0, requested_page_size}:
        raise BrowserReadError("browser_session_native_probe_page_size_mismatch")
    return {
        "schema_version": NATIVE_LIST_PROBE_SCHEMA_VERSION,
        "probe_kind": "chengfeng_settlement_list",
        "operation": "list_waybills",
        "metrics": {
            "total_count": total_count,
            "list_length": list_length,
            "page_number": requested_page_number,
            "page_size": (
                requested_page_size
                if raw_page_size == 0 or reversed_request_pagination
                else raw_page_size
            ),
        },
        "response_structure_sha256": _response_structure_sha256(payload),
    }


def _safe_settlement_filter_result(
    payload: object,
    *,
    request_body: Mapping[str, object],
    requested_waybills: tuple[str, ...],
) -> dict[str, object]:
    """Validate a batch-filter result without returning platform payload data."""

    page_number = request_body.get("pageNumber")
    page_size = request_body.get("pageSize")
    if type(page_number) is not int or type(page_size) is not int:
        raise BrowserReadError("browser_settlement_filter_result_changed")
    probe = _safe_native_list_probe(
        payload,
        requested_page_number=page_number,
        requested_page_size=page_size,
    )
    if not isinstance(payload, Mapping):
        raise BrowserReadError("browser_settlement_filter_result_changed")
    data = payload.get("data")
    items = data.get("list") if isinstance(data, Mapping) else None
    if not isinstance(items, list):
        raise BrowserReadError("browser_settlement_filter_result_changed")
    requested = frozenset(requested_waybills)
    visible: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            raise BrowserReadError("browser_settlement_filter_result_changed")
        value = item.get("sn")
        if type(value) is not str or value not in requested or value in visible:
            raise BrowserReadError("browser_settlement_filter_result_changed")
        visible.add(value)
    metrics = probe["metrics"]
    assert isinstance(metrics, Mapping)
    matched_count = metrics["total_count"]
    if type(matched_count) is not int or matched_count > len(requested_waybills):
        raise BrowserReadError("browser_settlement_filter_result_changed")
    if matched_count < len(visible):
        raise BrowserReadError("browser_settlement_filter_result_changed")
    return {
        "schema_version": 1,
        "requested_count": len(requested_waybills),
        "matched_count": matched_count,
        "missing_count": len(requested_waybills) - matched_count,
    }


def _fetch_native_list_probe(
    route: Any,
    *,
    request_body: Mapping[str, object],
    scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
) -> dict[str, object]:
    """Execute one exact routed list request and immediately discard its body."""

    requested_page_number = request_body.get("pageNumber")
    requested_page_size = request_body.get("pageSize")
    if (
        type(requested_page_number) is not int
        or not 1 <= requested_page_number <= MAX_NATIVE_LIST_PAGE_NUMBER
        or type(requested_page_size) is not int
        or not 1 <= requested_page_size <= MAX_NATIVE_LIST_LENGTH
    ):
        raise BrowserReadError("browser_session_native_probe_contract_changed")
    response = None
    raw_body: bytes | None = None
    parsed: object = None
    try:
        try:
            response = route.fetch(
                max_redirects=0,
                timeout=JSON_READ_TIMEOUT_MS,
            )
        except Exception as exc:
            raise BrowserReadError("browser_session_native_probe_network_failed") from exc
        try:
            status = int(response.status)
        except (AttributeError, TypeError, ValueError) as exc:
            raise BrowserReadError("browser_session_native_probe_contract_changed") from exc
        if status in {401, 403}:
            raise BrowserReadError("browser_read_login_required")
        if status != 200:
            raise BrowserReadError("browser_session_native_probe_http_failed")
        try:
            raw_body = response.body()
        except Exception as exc:
            raise BrowserReadError("browser_session_native_probe_network_failed") from exc
        if not isinstance(raw_body, bytes) or not raw_body or len(raw_body) > MAX_JSON_READ_BYTES:
            raise BrowserReadError("browser_session_native_probe_contract_changed")
        try:
            parsed = json.loads(raw_body.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrowserReadError("browser_session_native_probe_contract_changed") from exc
        return _safe_native_list_probe(
            parsed,
            scope=scope,
            requested_page_number=requested_page_number,
            requested_page_size=requested_page_size,
        )
    finally:
        parsed = None
        raw_body = None
        if response is not None:
            with suppress(Exception):
                response.dispose()


def _native_list_response(
    response: Any,
    *,
    request_body: Mapping[str, object],
) -> tuple[dict[str, object], bytes]:
    """Validate one page-completed list response and retain it only in memory."""

    requested_page_number = request_body.get("pageNumber")
    requested_page_size = request_body.get("pageSize")
    if (
        type(requested_page_number) is not int
        or not 1 <= requested_page_number <= MAX_NATIVE_LIST_PAGE_NUMBER
        or type(requested_page_size) is not int
        or not 1 <= requested_page_size <= MAX_NATIVE_LIST_LENGTH
    ):
        raise BrowserReadError("browser_operational_query_contract_changed")
    try:
        status = int(response.status)
    except (AttributeError, TypeError, ValueError) as exc:
        raise BrowserReadError("browser_operational_query_contract_changed") from exc
    if status in {401, 403}:
        raise BrowserReadError("browser_read_login_required")
    if status != 200:
        raise BrowserReadError("browser_operational_query_http_failed")
    try:
        content = response.body()
    except Exception as exc:
        raise BrowserReadError("browser_operational_query_network_failed") from exc
    if not isinstance(content, bytes) or not content or len(content) > MAX_JSON_READ_BYTES:
        raise BrowserReadError("browser_operational_query_contract_changed")
    try:
        payload = json.loads(content.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrowserReadError("browser_operational_query_contract_changed") from exc
    try:
        probe = _safe_native_list_probe(
            payload,
            scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
            requested_page_number=requested_page_number,
            requested_page_size=requested_page_size,
        )
    except BrowserReadError as exc:
        if exc.code not in {
            "browser_session_native_probe_contract_changed",
            "browser_session_native_probe_page_number_mismatch",
            "browser_session_native_probe_page_number_ahead_one",
            "browser_session_native_probe_page_number_is_total_pages",
            "browser_session_native_probe_page_number_is_total_count",
            "browser_session_native_probe_page_number_is_page_size",
            "browser_session_native_probe_page_number_ahead_many",
            "browser_session_native_probe_page_number_behind_many",
            "browser_session_native_probe_list_exceeds_requested_page_size",
            "browser_session_native_probe_list_exceeds_response_page_size",
            "browser_session_native_probe_total_below_list_length",
            "browser_session_native_probe_page_size_mismatch",
        }:
            raise
        observation = _private_list_structure_observation(request_body)
        observation["response_status"] = 200
        observation["content_kind"] = "json"
        observation["response_fields"] = _json_fields(payload)
        raise BrowserReadError(
            exc.code,
            safe_discovery=[observation],
        ) from exc
    return probe, content


def _approved_json_read_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == "pc.chengfengkuaiyun.com"
        and port is None
        and parsed.username is None
        and parsed.password is None
        and parsed.path
        in {
            CHENGFENG_LIST_PATH,
            CHENGFENG_HISTORICAL_LIST_PATH,
            CHENGFENG_DETAIL_PATH,
        }
        and not parsed.query
        and not parsed.fragment
    )


def _approved_daily_json_read_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == "pc.chengfengkuaiyun.com"
        and port is None
        and parsed.username is None
        and parsed.password is None
        and parsed.path == CHENGFENG_DAILY_LIST_PATH
        and not parsed.query
        and not parsed.fragment
    )


def _operational_batch_detail_identity(
    request: Any,
    *,
    allowed_identities: set[str],
) -> str | None:
    """Allow one exact page-owned detail read from the frozen batch."""

    if str(getattr(request, "method", "")).upper() != "POST" or str(
        getattr(request, "resource_type", "")
    ).casefold() not in {"fetch", "xhr"}:
        return None
    try:
        parsed = urlsplit(str(getattr(request, "url", "")))
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or parsed.hostname != "pc.chengfengkuaiyun.com"
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != CHENGFENG_DETAIL_PATH
        or parsed.query
        or parsed.fragment
    ):
        return None
    post_data = getattr(request, "post_data", None)
    if not isinstance(post_data, str) or not post_data:
        return None
    try:
        fields = parse_qsl(
            post_data,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=2,
        )
    except ValueError:
        return None
    if len(fields) != 1 or fields[0][0] != "id":
        return None
    identity = fields[0][1]
    if identity not in allowed_identities:
        return None
    return identity


def _operational_list_request_matches(
    request: Any,
    *,
    expected_body: Mapping[str, object],
    expected_cache_query: str,
) -> bool:
    """Allow one exact page-owned continuation of the captured list read."""

    if not _is_session_header_request(
        request,
        expected_path=CHENGFENG_LIST_PATH,
    ):
        return False
    if (
        _private_list_cache_query_from_request(
            request,
            expected_path=CHENGFENG_LIST_PATH,
        )
        != expected_cache_query
    ):
        return False
    try:
        actual_body = request.post_data_json
    except Exception:
        return False
    return isinstance(actual_body, Mapping) and dict(actual_body) == dict(expected_body)


def _approved_discovery_request(request: Any) -> bool:
    """Allow only known read-shaped traffic while discovery is active."""

    method = str(getattr(request, "method", "")).upper()
    resource_type = str(getattr(request, "resource_type", "")).casefold()
    try:
        parsed = urlsplit(str(getattr(request, "url", "")))
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        return False
    if method == "GET":
        return bool(
            parsed.hostname.casefold() in CHENGFENG_IMAGE_HOSTS
            and (resource_type == "image" or parsed.path.casefold().endswith(_IMAGE_SUFFIXES))
        )
    if (
        method != "POST"
        or resource_type not in {"fetch", "xhr"}
        or parsed.hostname != "pc.chengfengkuaiyun.com"
        or parsed.path
        not in {
            CHENGFENG_LIST_PATH,
            CHENGFENG_HISTORICAL_LIST_PATH,
            CHENGFENG_DETAIL_PATH,
            CHENGFENG_DAILY_LIST_PATH,
        }
    ):
        return False
    return not parsed.query or _daily_query_keys(parsed.query) == ["t"]


def _approved_daily_bootstrap_request(request: Any) -> bool:
    """Allow only fixed same-origin reads needed to construct the daily page."""

    method = str(getattr(request, "method", "")).upper()
    resource_type = str(getattr(request, "resource_type", "")).casefold()
    if method != "POST" or resource_type not in {"fetch", "xhr"}:
        return False
    try:
        parsed = urlsplit(str(getattr(request, "url", "")))
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == "pc.chengfengkuaiyun.com"
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and parsed.path in _DAILY_BOOTSTRAP_READ_PATHS
        and (not parsed.query or _daily_query_keys(parsed.query) == ["t"])
        and not parsed.fragment
    )


def _is_daily_native_request(request: Any) -> bool:
    method = str(getattr(request, "method", "")).upper()
    resource_type = str(getattr(request, "resource_type", "")).casefold()
    if method != "POST" or resource_type not in {"fetch", "xhr"}:
        return False
    try:
        parsed = urlsplit(str(getattr(request, "url", "")))
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == "pc.chengfengkuaiyun.com"
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and parsed.path == CHENGFENG_DAILY_LIST_PATH
        and not parsed.fragment
        and _daily_query_keys(parsed.query) is not None
    )


def _daily_query_keys(query: str) -> list[str] | None:
    if not query:
        return []
    pairs = parse_qsl(query, keep_blank_values=True)
    if (
        len(pairs) != 1
        or pairs[0][0] != "t"
        or not pairs[0][1].isascii()
        or not pairs[0][1].isdigit()
        or not 10 <= len(pairs[0][1]) <= 20
    ):
        return None
    return ["t"]


def _daily_session_headers_from_request(request: Any) -> dict[str, str] | None:
    if not _is_daily_native_request(request):
        return None
    try:
        raw_headers = request.all_headers()
    except Exception:
        return None
    if not isinstance(raw_headers, Mapping):
        return None
    headers: dict[str, str] = {}
    total_length = 0
    for raw_name, raw_value in raw_headers.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            continue
        name = raw_name.casefold()
        if (
            name in _SESSION_HEADER_BLOCKLIST
            or not _HEADER_NAME.fullmatch(name)
            or not raw_value
            or len(raw_value) > MAX_SESSION_HEADER_VALUE_LENGTH
            or "\r" in raw_value
            or "\n" in raw_value
            or "\x00" in raw_value
        ):
            continue
        next_total = total_length + len(name) + len(raw_value)
        if len(headers) >= MAX_SESSION_HEADER_COUNT or next_total > MAX_SESSION_HEADER_TOTAL_LENGTH:
            return None
        headers[name] = raw_value
        total_length = next_total
    return headers or None


def _private_daily_name_is_safe(name: object) -> bool:
    return (
        isinstance(name, str)
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,79}", name) is not None
        and not any(marker in name.casefold() for marker in _PRIVATE_DAILY_SENSITIVE_MARKERS)
    )


def _private_daily_value_is_safe(value: object, *, depth: int = 0) -> bool:
    """Validate a page-owned query value without exposing or interpreting it."""

    if depth > MAX_PRIVATE_DAILY_VALUE_DEPTH:
        return False
    if value is None or type(value) in {bool, int, float}:
        return True
    if type(value) is str:
        return len(value) <= 8 * 1024 and "\x00" not in value
    if type(value) is list:
        return len(value) <= 256 and all(
            _private_daily_value_is_safe(item, depth=depth + 1) for item in value
        )
    if type(value) is dict:
        return len(value) <= 128 and all(
            _private_daily_name_is_safe(name)
            and _private_daily_value_is_safe(item, depth=depth + 1)
            for name, item in value.items()
        )
    return False


def _private_daily_body_from_request(request: Any) -> dict[str, object] | None:
    if not _is_daily_native_request(request):
        return None
    try:
        body = request.post_data_json
    except Exception:
        return None
    if not isinstance(body, Mapping) or not 5 <= len(body) <= 128:
        return None
    if set(body) == _DYNAMIC_DAILY_BASELINE_FIELDS:
        dept_code = body.get("deptCode")
        order = body.get("order")
        page_number = body.get("pageNumber")
        page_size = body.get("pageSize")
        sort_params = body.get("sortParams")
        if (
            dept_code != ""
            or order not in {"", "asc", "desc"}
            or type(page_number) is not int
            or not 1 <= page_number <= 10_000
            or type(page_size) is not int
            or not 1 <= page_size <= 100
            or type(sort_params) is not list
            or sort_params
        ):
            return None
        return {
            "deptCode": "",
            "order": order,
            "pageNumber": 1,
            "pageSize": 1,
            "sortParams": [],
        }
    try:
        encoded_body = json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        return None
    if len(encoded_body) > MAX_PRIVATE_DAILY_BODY_BYTES:
        return None
    normalized: dict[str, object] = {}
    for raw_name, value in body.items():
        if not _private_daily_name_is_safe(raw_name):
            return None
        if raw_name in {"loadStartTime", "loadEndTime", "receivePlace"}:
            if type(value) is not str or len(value) > 100:
                return None
            normalized[raw_name] = ""
        elif raw_name == "pageNumber":
            if type(value) is not int or not 1 <= value <= 10_000:
                return None
            normalized[raw_name] = 1
        elif raw_name == "pageSize":
            if type(value) is not int or not 1 <= value <= 100:
                return None
            normalized[raw_name] = 1
        elif not _private_daily_value_is_safe(value):
            return None
        else:
            # The value remains inside the browser worker.  It is copied rather
            # than interpreted so the page's successful read scope remains the
            # authority while controlled business fields are substituted later.
            normalized[raw_name] = json.loads(
                json.dumps(value, ensure_ascii=False, allow_nan=False)
            )
    if not _DAILY_CONTROLLED_FIELDS.issubset(normalized):
        return None
    return normalized


def _daily_page_request_matches(
    request: Any,
    *,
    expected_body: Mapping[str, object],
) -> bool:
    """Allow one exact page-owned daily list request."""

    if not _is_daily_native_request(request):
        return False
    try:
        actual_body = request.post_data_json
    except Exception:
        return False
    return isinstance(actual_body, Mapping) and dict(actual_body) == dict(expected_body)


def _daily_page_request_can_be_scoped(
    request: Any,
    *,
    private_baseline: Mapping[str, object],
) -> bool:
    """Allow the official page query while preserving its private filter baseline."""

    if not _is_daily_native_request(request):
        return False
    try:
        actual_body = request.post_data_json
    except Exception:
        return False
    if not isinstance(actual_body, Mapping) or set(actual_body) != set(private_baseline):
        return False
    return all(
        name in _DAILY_CONTROLLED_FIELDS or actual_body.get(name) == baseline_value
        for name, baseline_value in private_baseline.items()
    )


def _validate_daily_read_parameters(
    parameters: Mapping[str, object],
    *,
    baseline: Mapping[str, object],
) -> dict[str, object]:
    data = {
        key: list(value) if isinstance(value, tuple) else value for key, value in parameters.items()
    }
    if set(data) != set(baseline):
        raise BrowserReadError("browser_daily_request_fields_changed")
    for name, baseline_value in baseline.items():
        if name not in _DAILY_CONTROLLED_FIELDS and data[name] != baseline_value:
            raise BrowserReadError("browser_daily_filter_contract_changed")
    start_raw = data.get("loadStartTime")
    end_raw = data.get("loadEndTime")
    receive_place = data.get("receivePlace")
    page_number = data.get("pageNumber")
    page_size = data.get("pageSize")
    if (
        type(start_raw) is not str
        or type(end_raw) is not str
        or type(receive_place) is not str
        or not receive_place
        or receive_place != receive_place.strip()
        or len(receive_place) > 100
        or "://" in receive_place
        or "?" in receive_place
        or "#" in receive_place
        or any(ord(character) < 32 or ord(character) == 127 for character in receive_place)
        or type(page_number) is not int
        or not 1 <= page_number <= 10_000
        or type(page_size) is not int
        or not 1 <= page_size <= 100
    ):
        raise BrowserReadError("browser_daily_business_parameters_invalid")
    try:
        start = datetime.strptime(start_raw, "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(end_raw, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise BrowserReadError("browser_daily_business_parameters_invalid") from exc
    if (
        (start.hour, start.minute, start.second) != (14, 0, 0)
        or end < start
        or end > start + timedelta(days=1, minutes=30)
    ):
        raise BrowserReadError("browser_daily_business_parameters_invalid")
    return data


def _daily_probe_request_mismatch(
    *,
    probe_body: Mapping[str, object],
    requested_body: Mapping[str, object],
) -> str | None:
    """Classify a probe reuse mismatch without exposing request values."""

    if set(probe_body) != set(requested_body):
        return "fields"
    if probe_body.get("receivePlace") != "榆林":
        return "source_place"
    if requested_body.get("receivePlace") != "榆林":
        return "requested_place"
    categories = (
        ("start", ("loadStartTime",)),
        ("end", ("loadEndTime",)),
        ("pagination", ("pageNumber", "pageSize")),
    )
    for category, fields in categories:
        if any(probe_body.get(field) != requested_body.get(field) for field in fields):
            return category
    if dict(probe_body) != dict(requested_body):
        return "baseline"
    return None


def _daily_response_fields(
    payload: object,
    *,
    require_nonempty: bool,
) -> list[dict[str, str]]:
    if not isinstance(payload, Mapping):
        raise BrowserReadError("browser_daily_response_contract_changed")
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise BrowserReadError("browser_daily_response_contract_changed")
    items = data.get("list")
    total = data.get("total")
    code = payload.get("code")
    success = payload.get("success")
    if (code is not None and code not in {200, "200"}) or (
        success is not None and success is not True
    ):
        raise BrowserReadError("browser_daily_response_contract_changed")
    if items is None and total == 0:
        items = []
    if (
        not isinstance(items, list)
        or type(total) is not int
        or not 0 <= total <= MAX_NATIVE_LIST_TOTAL_COUNT
        or len(items) > MAX_NATIVE_LIST_LENGTH
        or total < len(items)
        or (total == 0 and items)
        or (total > 0 and not items)
    ):
        raise BrowserReadError("browser_daily_response_contract_changed")
    if require_nonempty and not items:
        raise BrowserReadError("browser_daily_list_empty")
    for item in items:
        if not isinstance(item, Mapping):
            raise BrowserReadError("browser_daily_response_contract_changed")
        platform_id = item.get("id")
        waybill_number = item.get("sn")
        car_number = item.get("carNumber")
        original_date = item.get("loadPunchDate")
        if (
            not (
                (type(platform_id) is int and platform_id > 0)
                or (
                    type(platform_id) is str
                    and platform_id.isascii()
                    and platform_id.isdigit()
                    and 1 <= len(platform_id) <= 64
                )
            )
            or type(waybill_number) is not str
            or not waybill_number
            or len(waybill_number) > 100
            or (car_number is not None and (type(car_number) is not str or len(car_number) > 100))
            or (
                original_date is not None
                and (type(original_date) is not str or len(original_date) > 100)
            )
        ):
            raise BrowserReadError("browser_daily_response_contract_changed")
    if not items:
        return [{"path": "$.data.total", "type": "integer"}]
    first = items[0]
    return [
        {
            "path": "$.data.list[].carNumber",
            "type": _json_scalar_type(first.get("carNumber")),
        },
        {
            "path": "$.data.list[].id",
            "type": _json_scalar_type(first.get("id")),
        },
        {
            "path": "$.data.list[].loadPunchDate",
            "type": _json_scalar_type(first.get("loadPunchDate")),
        },
        {
            "path": "$.data.list[].sn",
            "type": _json_scalar_type(first.get("sn")),
        },
        {"path": "$.data.total", "type": "integer"},
    ]


def _validate_page_owned_daily_scope(
    payload: Mapping[str, object],
    *,
    request_body: Mapping[str, object],
) -> None:
    """Prove that a page-owned response applied the requested business scope."""

    data = payload.get("data")
    items = data.get("list") if isinstance(data, Mapping) else None
    if isinstance(data, Mapping) and items is None and data.get("total") == 0:
        items = []
    start_raw = request_body.get("loadStartTime")
    end_raw = request_body.get("loadEndTime")
    receive_place = request_body.get("receivePlace")
    if not isinstance(items, list):
        raise BrowserReadError("browser_daily_scope_items_invalid")
    if (
        type(start_raw) is not str
        or type(end_raw) is not str
        or type(receive_place) is not str
        or not receive_place
    ):
        raise BrowserReadError("browser_daily_scope_request_invalid")
    try:
        start = datetime.strptime(start_raw, "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(end_raw, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise BrowserReadError("browser_daily_scope_request_time_invalid") from exc
    if end < start:
        raise BrowserReadError("browser_daily_scope_range_invalid")
    for item in items:
        if not isinstance(item, Mapping):
            raise BrowserReadError("browser_daily_scope_item_invalid")
        loaded_at_raw = item.get("loadPunchDate")
        # The exact page-owned request body is the location-scope authority.
        # Chengfeng does not consistently echo the location label on every
        # returned row, so an optional display field cannot be a safety gate.
        if loaded_at_raw is None or loaded_at_raw == "":
            continue
        if type(loaded_at_raw) is not str:
            raise BrowserReadError("browser_daily_scope_loading_time_type_invalid")
        try:
            datetime.strptime(
                loaded_at_raw,
                "%Y-%m-%d %H:%M:%S",
            )
        except ValueError as exc:
            raise BrowserReadError("browser_daily_scope_loading_time_format_changed") from exc
        # Chengfeng may return a broader candidate page even when the exact
        # page-owned request contains the requested dates. The application
        # performs the authoritative 14:00-to-14:00 filter before details or
        # reports are materialized, so the Worker only requires a parseable
        # loading timestamp here.


def _json_scalar_type(value: object) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if type(value) is str:
        return "string"
    return "unknown"


def _daily_scope_sha256(body: Mapping[str, object]) -> str:
    """Hash the business scope, excluding pagination transport controls."""

    controlled = {name: body.get(name) for name in sorted(_DAILY_SCOPE_FIELDS)}
    return hashlib.sha256(
        json.dumps(
            controlled,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _daily_platform_display_total(page: Any) -> int | None:
    """Read the page's visible pagination total without persisting page text."""

    selectors = (
        ".el-pagination__total",
        ".ant-pagination-total-text",
        "[class*='pagination'] [class*='total']",
    )
    for selector in selectors:
        try:
            locator = page.locator(selector)
            count = min(locator.count(), 8)
            for index in range(count):
                text = locator.nth(index).inner_text(timeout=1_000)
                match = re.search(r"(?:共|总计)\s*([0-9,]+)\s*(?:条|项)?", text)
                if match is not None:
                    return int(match.group(1).replace(",", ""))
        except Exception:
            continue
    return None


def _normalized_daily_read_bytes(
    payload: Mapping[str, object],
    *,
    scope_metadata: Mapping[str, object] | None = None,
) -> bytes:
    """Project a validated raw response to the only approved persisted fields."""

    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise BrowserReadError("browser_daily_response_contract_changed")
    raw_items = data.get("list")
    total = data.get("total")
    if raw_items is None and total == 0:
        raw_items = []
    if not isinstance(raw_items, list) or type(total) is not int:
        raise BrowserReadError("browser_daily_response_contract_changed")
    normalized_items = [
        {
            "carNumber": item.get("carNumber"),
            "id": item.get("id"),
            "orderItemSn": item.get("sn"),
            "originalDate": item.get("loadPunchDate"),
        }
        for item in raw_items
        if isinstance(item, Mapping)
    ]
    if len(normalized_items) != len(raw_items):
        raise BrowserReadError("browser_daily_response_contract_changed")
    normalized: dict[str, object] = {
        "data": {
            "list": normalized_items,
            "total": total,
        }
    }
    if scope_metadata is not None:
        normalized["_dahe_scope"] = dict(scope_metadata)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _daily_read_structure_observation(
    *,
    body: Mapping[str, object],
    response_fields: list[dict[str, str]],
) -> dict[str, object]:
    """Return field shapes only for a failed controlled daily read."""

    request_fields = _json_fields(body)
    for field in request_fields:
        if field["type"] == "empty_array" and field["path"].endswith("[]"):
            field["path"] = field["path"][:-2]
    return {
        "method": "POST",
        "origin": _CHENGFENG_ORIGIN,
        "path": CHENGFENG_DAILY_LIST_PATH,
        "path_sha256": None,
        "query_keys": [],
        "request_fields": request_fields,
        "resource_kind": "json_api",
        "response_status": 200,
        "content_kind": "json",
        "response_fields": [dict(field) for field in response_fields],
    }


def _fetch_daily_native_observation(
    route: Any,
    *,
    request: Any,
    body: Mapping[str, object],
) -> dict[str, object]:
    response = None
    raw_body: bytes | None = None
    parsed: object = None
    try:
        try:
            response = route.fetch(
                max_redirects=0,
                timeout=JSON_READ_TIMEOUT_MS,
            )
        except Exception as exc:
            raise BrowserReadError("browser_daily_native_probe_network_failed") from exc
        try:
            status = int(response.status)
            headers = {str(key).casefold(): str(value) for key, value in response.headers.items()}
        except (AttributeError, TypeError, ValueError) as exc:
            raise BrowserReadError("browser_daily_response_contract_changed") from exc
        if status in {401, 403}:
            raise BrowserReadError("browser_read_login_required")
        if 300 <= status < 400:
            raise BrowserReadError("browser_daily_redirect_rejected")
        if status != 200:
            raise BrowserReadError("browser_daily_native_probe_http_failed")
        media_type = headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        if media_type != "application/json" and not media_type.endswith("+json"):
            raise BrowserReadError("browser_daily_response_contract_changed")
        try:
            raw_body = response.body()
        except Exception as exc:
            raise BrowserReadError("browser_daily_native_probe_network_failed") from exc
        if not isinstance(raw_body, bytes) or not raw_body or len(raw_body) > MAX_JSON_READ_BYTES:
            raise BrowserReadError("browser_daily_response_contract_changed")
        try:
            parsed = json.loads(raw_body.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrowserReadError("browser_daily_response_contract_changed") from exc
        response_fields = _daily_response_fields(parsed, require_nonempty=True)
        parsed_url = urlsplit(str(getattr(request, "url", "")))
        query_keys = _daily_query_keys(parsed_url.query)
        if query_keys is None:
            raise BrowserReadError("browser_daily_request_contract_changed")
        return {
            "method": "POST",
            "origin": _CHENGFENG_ORIGIN,
            "path": CHENGFENG_DAILY_LIST_PATH,
            "path_sha256": None,
            "query_keys": query_keys,
            "request_fields": _json_fields(body),
            "resource_kind": "json_api",
            "response_status": 200,
            "content_kind": "json",
            "response_fields": response_fields,
        }
    finally:
        parsed = None
        raw_body = None
        if response is not None:
            with suppress(Exception):
                response.dispose()


def _daily_discovery_body(now: datetime) -> dict[str, object]:
    """Build one bounded completed-business-day discovery query."""

    candidate = now.date() - timedelta(days=1)
    safety_end = datetime.combine(
        candidate + timedelta(days=1),
        datetime.min.time(),
    ).replace(hour=14, minute=30)
    if now < safety_end:
        candidate -= timedelta(days=1)
    start = datetime.combine(candidate, datetime.min.time()).replace(
        hour=14,
        minute=0,
    )
    return {
        "loadEndTime": (start + timedelta(days=1, minutes=30)).strftime("%Y-%m-%d %H:%M:%S"),
        "loadStartTime": start.strftime("%Y-%m-%d %H:%M:%S"),
        "pageNumber": 1,
        "pageSize": 5,
        "receivePlace": "榆林",
    }


def _frozen_daily_private_body() -> dict[str, object]:
    """Return the selected read contract when an authenticated page stays idle."""

    return {
        "loadEndTime": "",
        "loadStartTime": "",
        "pageNumber": 1,
        "pageSize": 1,
        "receivePlace": "",
    }


def _fetch_daily_discovery_observation(
    request_context: Any,
    *,
    headers: Mapping[str, str],
    body: Mapping[str, object],
) -> tuple[dict[str, object], bytes]:
    """Execute one exact daily read and release all raw response values."""

    response = None
    raw_body: bytes | None = None
    parsed: object = None
    try:
        try:
            response = request_context.fetch(
                f"{_CHENGFENG_ORIGIN}{CHENGFENG_DAILY_LIST_PATH}",
                method="POST",
                data=dict(body),
                headers=dict(headers),
                fail_on_status_code=False,
                max_redirects=0,
                timeout=JSON_READ_TIMEOUT_MS,
            )
        except Exception as exc:
            raise BrowserReadError("browser_daily_native_probe_network_failed") from exc
        try:
            status = int(response.status)
            response_headers = {
                str(key).casefold(): str(value) for key, value in response.headers.items()
            }
        except (AttributeError, TypeError, ValueError) as exc:
            raise BrowserReadError("browser_daily_response_contract_changed") from exc
        if status in {401, 403}:
            raise BrowserReadError("browser_read_login_required")
        if 300 <= status < 400:
            raise BrowserReadError("browser_daily_redirect_rejected")
        if status != 200:
            raise BrowserReadError("browser_daily_native_probe_http_failed")
        media_type = response_headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        if media_type != "application/json" and not media_type.endswith("+json"):
            raise BrowserReadError("browser_daily_response_contract_changed")
        try:
            raw_body = response.body()
        except Exception as exc:
            raise BrowserReadError("browser_daily_native_probe_network_failed") from exc
        if not isinstance(raw_body, bytes) or not raw_body or len(raw_body) > MAX_JSON_READ_BYTES:
            raise BrowserReadError("browser_daily_response_contract_changed")
        try:
            parsed = json.loads(raw_body.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrowserReadError("browser_daily_response_contract_changed") from exc
        observation = {
            "method": "POST",
            "origin": _CHENGFENG_ORIGIN,
            "path": CHENGFENG_DAILY_LIST_PATH,
            "path_sha256": None,
            "query_keys": [],
            "request_fields": _json_fields(body),
            "resource_kind": "json_api",
            "response_status": 200,
            "content_kind": "json",
            "response_fields": [],
        }
        try:
            observation["response_fields"] = _daily_response_fields(
                parsed,
                require_nonempty=True,
            )
        except BrowserReadError as exc:
            if exc.code != "browser_daily_response_contract_changed":
                raise
            observation["response_fields"] = _json_fields(parsed)
            raise BrowserReadError(
                exc.code,
                safe_discovery=[observation],
            ) from exc
        return observation, _normalized_daily_read_bytes(parsed)
    finally:
        parsed = None
        raw_body = None
        if response is not None:
            with suppress(Exception):
                response.dispose()


def _approved_daily_page_get(request: Any) -> bool:
    if str(getattr(request, "method", "")).upper() != "GET" or str(
        getattr(request, "resource_type", "")
    ).casefold() not in {"document", "script", "stylesheet", "font"}:
        return False
    try:
        parsed = urlsplit(str(getattr(request, "url", "")))
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == "pc.chengfengkuaiyun.com"
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and not _SENSITIVE_PATH.search(parsed.path)
        and (
            (
                str(getattr(request, "resource_type", "")).casefold() == "document"
                and parsed.path == "/wayBill"
                and not parsed.query
            )
            or (
                str(getattr(request, "resource_type", "")).casefold() != "document"
                and parsed.path.startswith("/")
            )
        )
    )


def _page_requires_login(page: Any) -> bool:
    """Detect login controls without reading or returning their values."""

    try:
        password = page.locator("input[type='password']").first
        if password.is_visible():
            return True
    except Exception:
        pass
    try:
        login_button = page.get_by_role(
            "button",
            name="登录",
            exact=True,
        ).first
        return bool(login_button.is_visible())
    except Exception:
        return False


def _entry_business_controls_visible(page: Any) -> bool:
    """Detect a hydrated settlement page without reading business values."""

    try:
        control = page.get_by_text("按运单显示", exact=True).filter(visible=True).first
        return bool(control.is_visible())
    except Exception:
        return False


def _daily_business_controls_visible(page: Any) -> bool:
    """Detect a hydrated daily page without reading business values."""

    try:
        control = page.get_by_text("运单管理", exact=True).filter(visible=True).first
        return bool(control.is_visible())
    except Exception:
        return False


def _page_hydration_score(page: Any) -> int:
    """Rank safe same-origin pages without reading credentials or business data."""

    if (
        _page_requires_login(page)
        or _entry_business_controls_visible(page)
        or _daily_business_controls_visible(page)
    ):
        return 2
    try:
        observation = page.evaluate(
            """() => ({
                ready_state: document.readyState,
                body_element_count: document.body
                    ? document.body.querySelectorAll("*").length
                    : 0,
            })"""
        )
    except Exception:
        return 0
    if not isinstance(observation, Mapping) or set(observation) != {
        "ready_state",
        "body_element_count",
    }:
        return 0
    ready_state = observation.get("ready_state")
    body_element_count = observation.get("body_element_count")
    if (
        ready_state in {"interactive", "complete"}
        and type(body_element_count) is int
        and 0 < body_element_count <= 100_000
    ):
        return 1
    return 0


def _wait_for_entry_login_state(page: Any, *, daily: bool = False) -> bool:
    """Wait for the SPA to reveal either login or authenticated controls."""

    for _ in range(HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS // 500):
        if _page_requires_login(page):
            return True
        if (
            _daily_business_controls_visible(page)
            if daily
            else _entry_business_controls_visible(page)
        ):
            return False
        page.wait_for_timeout(500)
    return _page_requires_login(page)


def _visible_captcha(page: Any) -> bool:
    selectors = (
        "input[placeholder*='验证码']",
        "input[name*='captcha' i]",
        "iframe[src*='captcha' i]",
        "[class*='captcha' i]",
        "[class*='verify' i]",
    )
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.is_visible():
                return True
        except Exception:
            continue
    return False


def _contract_subject_control(page: Any, *, login_page: bool) -> Any:
    if login_page:
        candidates = page.locator(".el-form-item")
        matching = []
        for index in range(candidates.count()):
            candidate = candidates.nth(index)
            label = candidate.locator(".el-form-item__label").first
            if label.count() == 1 and str(label.inner_text()).strip() == "签约主体":
                matching.append(candidate.locator(".el-select").first)
        if len(matching) != 1 or matching[0].count() != 1:
            raise BrowserReadError("browser_contract_subject_control_unavailable")
        return matching[0]
    control = page.locator(".l-content .el-select")
    if control.count() != 1:
        raise BrowserReadError("browser_contract_subject_control_unavailable")
    return control.first


def _selected_contract_subject_code(page: Any, *, login_page: bool) -> str:
    control = _contract_subject_control(page, login_page=login_page)
    selected_text = ""
    inputs = control.locator("input")
    if inputs.count() == 1:
        selected_text = str(inputs.first.input_value()).strip()
    if not selected_text:
        selected = page.locator(".el-select-dropdown:visible .el-select-dropdown__item.selected")
        if selected.count() == 1:
            selected_text = str(selected.first.inner_text()).strip()
    for code, option_text in CONTRACT_SUBJECT_OPTION_TEXT.items():
        if selected_text == option_text:
            return code
    raise BrowserReadError("browser_contract_subject_unknown")


def _ensure_contract_subject(
    page: Any,
    *,
    contract_subject_code: str,
    login_page: bool,
) -> dict[str, object]:
    option_text = CONTRACT_SUBJECT_OPTION_TEXT.get(contract_subject_code)
    if option_text is None:
        raise BrowserReadError("browser_contract_subject_unknown")
    if _selected_contract_subject_code(page, login_page=login_page) == contract_subject_code:
        return {
            "contract_subject_code": contract_subject_code,
            "contract_subject_switch_performed": False,
        }
    control = _contract_subject_control(page, login_page=login_page)
    switch_response_revision = 0
    switch_document_response_observed = False

    def observe_switch_response(response: Any) -> None:
        nonlocal switch_response_revision
        nonlocal switch_document_response_observed
        try:
            parsed = urlsplit(str(getattr(response, "url", "")))
            request = getattr(response, "request", None)
            resource_type = str(
                getattr(request, "resource_type", "")
            ).casefold()
            status = int(getattr(response, "status", 0))
        except (TypeError, ValueError):
            return
        if (
            parsed.scheme == "https"
            and parsed.hostname == "pc.chengfengkuaiyun.com"
            and parsed.port in {None, 443}
            and parsed.username is None
            and parsed.password is None
            and resource_type in {"document", "fetch", "xhr"}
            and 200 <= status < 400
        ):
            switch_response_revision += 1
            if resource_type == "document":
                switch_document_response_observed = True

    response_listener_installed = False
    try:
        control.locator("input").first.click(timeout=10_000)
        exact_match = None
        for _ in range(CONTRACT_SUBJECT_OPTION_TIMEOUT_MS // 250):
            options = page.locator(
                ".el-select-dropdown:visible .el-select-dropdown__item"
            )
            exact_matches = []
            for index in range(options.count()):
                candidate = options.nth(index)
                if str(candidate.inner_text()).strip() == option_text:
                    exact_matches.append(candidate)
            if len(exact_matches) > 1:
                raise BrowserReadError("browser_contract_subject_option_unavailable")
            if exact_matches:
                exact_match = exact_matches[0]
                break
            page.wait_for_timeout(250)
        if exact_match is None:
            raise BrowserReadError("browser_contract_subject_option_unavailable")
        page.on("response", observe_switch_response)
        response_listener_installed = True
        exact_match.click(timeout=10_000)
        stable_confirmation_count = 0
        target_selection_observed = False
        for _ in range(CONTRACT_SUBJECT_OPTION_TIMEOUT_MS // 250):
            page.wait_for_timeout(250)
            try:
                if (
                    _selected_contract_subject_code(
                        page,
                        login_page=login_page,
                    )
                    == contract_subject_code
                ):
                    target_selection_observed = True
                    # The Chengfeng shell continues polling notification and
                    # account endpoints after a subject switch. Those later
                    # successful reads prove the page is alive; they must not
                    # reset an already stable subject selection.
                    stable_confirmation_count += 1
                    if (
                        stable_confirmation_count
                        >= CONTRACT_SUBJECT_STABLE_POLL_COUNT
                    ):
                        return {
                            "contract_subject_code": contract_subject_code,
                            "contract_subject_switch_performed": True,
                            "contract_subject_switch_response_observed": (
                                switch_response_revision > 0
                            ),
                        }
                else:
                    stable_confirmation_count = 0
            except BrowserReadError:
                stable_confirmation_count = 0
                continue
        if target_selection_observed and switch_document_response_observed:
            # Switching back to Chengfeng's primary subject performs a full
            # same-origin document reload. The selected input can disappear
            # before the normal stable-poll window completes. Hand this
            # explicitly observed transition to the caller's hydration and
            # final-subject gates instead of treating the empty shell as a
            # failed click.
            return {
                "contract_subject_code": contract_subject_code,
                "contract_subject_switch_performed": True,
                "contract_subject_switch_response_observed": True,
            }
    except BrowserReadError:
        raise
    except Exception as exc:
        raise BrowserReadError("browser_contract_subject_switch_failed") from exc
    finally:
        if response_listener_installed:
            with suppress(Exception):
                page.remove_listener("response", observe_switch_response)
    raise BrowserReadError("browser_contract_subject_confirmation_failed")


def _stabilize_contract_subject_business_page(
    page: Any,
    *,
    contract_subject_code: str,
    entry: str,
    daily: bool,
) -> None:
    """Recover one blank SPA shell after an accepted subject switch."""

    controls_visible = (
        _daily_business_controls_visible if daily else _entry_business_controls_visible
    )
    def wait_for_stable_controls(poll_count: int) -> bool:
        stable_count = 0
        for _ in range(poll_count):
            page.wait_for_timeout(250)
            try:
                ready = (
                    controls_visible(page)
                    and _selected_contract_subject_code(
                        page,
                        login_page=False,
                    )
                    == contract_subject_code
                )
            except BrowserReadError:
                ready = False
            if ready:
                stable_count += 1
                if stable_count >= CONTRACT_SUBJECT_STABLE_POLL_COUNT:
                    return True
            else:
                stable_count = 0
        return False

    if not wait_for_stable_controls(
        CONTRACT_SUBJECT_OPTION_TIMEOUT_MS // 250
    ):
        error_code = (
            "browser_daily_query_control_unavailable"
            if daily
            else "browser_session_waybill_control_unavailable"
        )
        try:
            response = page.goto(
                entry,
                wait_until="domcontentloaded",
                timeout=HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS,
            )
            if response is None:
                raise BrowserReadError(error_code)
            _assert_business_landing(
                str(getattr(page, "url", "")),
                response_status=int(getattr(response, "status", 0)),
                expected_path="/wayBill" if daily else "/billablewaybill",
            )
        except BrowserReadError:
            raise
        except Exception as exc:
            raise BrowserReadError(error_code) from exc
        if _page_requires_login(page):
            raise BrowserReadError("browser_read_login_required")
        if not wait_for_stable_controls(
            HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS // 250
        ):
            raise BrowserReadError(error_code)


def _login_with_saved_credential(
    page: Any,
    *,
    contract_subject_code: str = "shanxi_guienbo",
) -> None:
    if _visible_captcha(page):
        raise BrowserReadError("browser_saved_login_captcha_required")
    try:
        credential = read_saved_credential()
    except CredentialUnavailableError as exc:
        raise BrowserReadError("browser_saved_credential_missing") from exc
    try:
        username = page.locator(
            "input[type='text'], input[type='tel'], input[name*='user' i], input[name*='account' i]"
        ).first
        password = page.locator("input[type='password']").first
        submit = page.get_by_role("button", name="登录", exact=True).first
        if not (username.is_visible() and password.is_visible() and submit.is_visible()):
            raise BrowserReadError("browser_saved_login_structure_changed")
        username.fill(credential.username)
        password.fill(credential.password)
        with suppress(AttributeError, TypeError):
            _ensure_contract_subject(
                page,
                contract_subject_code=contract_subject_code,
                login_page=True,
            )
        submit.click(timeout=10_000)
        for _ in range(HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS // 500):
            page.wait_for_timeout(500)
            if _visible_captcha(page):
                raise BrowserReadError("browser_saved_login_captcha_required")
            if not _page_requires_login(page):
                parsed = urlsplit(str(getattr(page, "url", "")))
                if (
                    parsed.scheme == "https"
                    and parsed.hostname == "pc.chengfengkuaiyun.com"
                    and parsed.path == "/billablewaybill"
                ):
                    return
        raise BrowserReadError("browser_saved_login_failed")
    finally:
        credential = None


def run_smoke(command: SmokeCommand) -> str:
    """Launch only a blank page; this command has no network navigation surface."""

    os.environ.setdefault(
        "PLAYWRIGHT_BROWSERS_PATH",
        str(Path(sys.prefix).resolve().parent / "browsers"),
    )
    from playwright.sync_api import Error, sync_playwright

    command.browser_store.mkdir(parents=True, exist_ok=True)
    candidates = _browser_candidates()
    if command.browser != "auto":
        candidates = tuple(candidate for candidate in candidates if candidate[0] == command.browser)
    failures: list[str] = []
    with sync_playwright() as playwright:
        for browser_name, executable in candidates:
            profile = command.browser_store / f"smoke-{browser_name}"
            try:
                launch_options = (
                    {} if executable is None else {"executable_path": os.fspath(executable)}
                )
                context = playwright.chromium.launch_persistent_context(
                    user_data_dir=profile,
                    headless=True,
                    offline=True,
                    chromium_sandbox=True,
                    **launch_options,
                )
                try:
                    page = context.pages[0] if context.pages else context.new_page()
                    page.goto("about:blank")
                    if page.url != "about:blank":
                        raise RuntimeError("blank-page smoke navigated unexpectedly")
                finally:
                    context.close()
                return browser_name
            except (Error, OSError, RuntimeError) as exc:
                failures.append(type(exc).__name__)
    raise RuntimeError("no verified browser passed smoke: " + ",".join(failures))


def assert_managed_store(path: Path, *, allowed_root: Path) -> Path:
    resolved_root = allowed_root.resolve()
    resolved = path.resolve()
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise RuntimeError("browser store is outside the managed data root")
    return resolved


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT_ATTRIBUTE)


def _path_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _normal_path_metadata(path: Path, *, directory: bool) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeError("browser read staging path is unavailable") from exc
    if _is_link_or_reparse(metadata):
        raise RuntimeError("browser read staging contains a symbolic link or reparse point")
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected:
        raise RuntimeError("browser read staging contains an unsafe entry")
    return metadata


def recover_read_result_staging(staging_root: Path) -> int:
    """Remove only known orphan payloads created by this browser runtime."""

    root = staging_root.absolute()
    root_metadata = _normal_path_metadata(root, directory=True)
    root_identity = _path_identity(root_metadata)
    removed = 0
    for candidate in tuple(root.iterdir()):
        if _OWNED_READ_RESULT_DIRECTORY.fullmatch(candidate.name) is None:
            continue
        if _path_identity(_normal_path_metadata(root, directory=True)) != root_identity:
            raise RuntimeError("browser read staging changed during recovery")
        directory_metadata = _normal_path_metadata(candidate, directory=True)
        directory_identity = _path_identity(directory_metadata)
        children = tuple(candidate.iterdir())
        child_identities: dict[Path, tuple[int, int, int, int]] = {}
        for child in children:
            if child.name not in _OWNED_READ_RESULT_FILES:
                raise RuntimeError("owned browser read staging contains an unknown entry")
            child_identities[child] = _path_identity(_normal_path_metadata(child, directory=False))
        for child in children:
            if (
                _path_identity(_normal_path_metadata(root, directory=True)) != root_identity
                or _path_identity(_normal_path_metadata(candidate, directory=True))
                != directory_identity
                or _path_identity(_normal_path_metadata(child, directory=False))
                != child_identities[child]
            ):
                raise RuntimeError("browser read staging changed during recovery")
            child.unlink()
        if (
            _path_identity(_normal_path_metadata(root, directory=True)) != root_identity
            or _path_identity(_normal_path_metadata(candidate, directory=True))
            != directory_identity
        ):
            raise RuntimeError("browser read staging changed during recovery")
        try:
            candidate.rmdir()
        except OSError as exc:
            raise RuntimeError("browser read staging changed during recovery") from exc
        removed += 1
    return removed


def _validated_detail_image_urls(
    payload: Mapping[str, object],
    *,
    expected_platform_waybill_id: object,
) -> tuple[str, ...]:
    """Extract exact image URLs only from one minimally valid detail response."""

    return tuple(
        url
        for _slot, url in _validated_detail_images(
            payload,
            expected_platform_waybill_id=expected_platform_waybill_id,
        )
    )


def _validated_detail_images(
    payload: Mapping[str, object],
    *,
    expected_platform_waybill_id: object,
) -> tuple[tuple[str, str], ...]:
    """Keep the business slot while validating response-derived image URLs."""

    if type(expected_platform_waybill_id) is not str or not expected_platform_waybill_id:
        raise BrowserReadError("browser_read_contract_changed")
    data = payload.get("data")
    if not isinstance(data, list):
        if data is None:
            code = f"browser_detail_data_null_{_detail_wrapper_status_category(payload)}"
        elif isinstance(data, dict):
            code = "browser_detail_data_object"
        elif isinstance(data, str):
            code = "browser_detail_data_string"
        elif type(data) is int:
            code = "browser_detail_data_integer"
        else:
            code = "browser_detail_data_unsupported"
        raise BrowserReadError(code)
    if len(data) != 1:
        raise BrowserReadError("browser_detail_cardinality_changed")
    detail = data[0]
    if not isinstance(detail, dict):
        raise BrowserReadError("browser_detail_item_contract_changed")
    if detail.get("id") != expected_platform_waybill_id:
        raise BrowserReadError("browser_detail_identity_mismatch")
    images: list[tuple[str, str]] = []
    for slot, field_name in (
        ("loading", "originalTonImageUrl"),
        ("unloading", "image"),
    ):
        value = detail.get(field_name)
        if value is None or value == "":
            continue
        if type(value) is not str or not is_approved_image_read_url(value):
            raise BrowserReadError("browser_image_contract_changed")
        images.append((slot, value))
    return tuple(images)


def _detail_wrapper_status_category(
    payload: Mapping[str, object],
) -> str:
    success = payload.get("success")
    code = payload.get("code")
    if success is False:
        return "failure"
    if code in {0, 200, "0", "200", "00000"}:
        return "success"
    if code in {401, 403, "401", "403"}:
        return "auth"
    if code is None and success is True:
        return "success"
    if code is None and success is None:
        return "missing"
    return "failure"


class BrowserEngine:
    def __init__(self) -> None:
        self._playwright = None
        self._context = None
        self.selected_browser: str | None = None
        self._capturing = False
        self._observations: list[dict[str, object]] = []
        self._request_indexes: dict[int, int] = {}
        self._page_handlers: dict[int, tuple[object, object, object, object]] = {}
        self._context_page_handler = None
        self._discovery_blocked_method_counts: dict[str, int] = {}
        self._human_freeze_handlers: dict[int, tuple[object, object]] = {}
        self._human_freeze_context_page_handler = None
        self._single_chengfeng_page_handler = None
        self._session_request_handler = None
        self._session_headers: dict[str, str] | None = None
        self._private_batch_cookie_header: str | None = None
        self._private_batch_session_frozen = False
        self._prefer_private_http_batch_reads = False
        self._image_head_probe_unsupported_hosts: set[str] = set()
        self._session_list_fixed_values: dict[str, str | int] | None = None
        self._session_list_cache_query: str | None = None
        self._session_list_body: dict[str, object] | None = None
        self._session_list_body_sha256: str | None = None
        self._session_native_probe: dict[str, object] | None = None
        self._session_request_seen = False
        self._session_headers_rejected = False
        self._session_fixed_values_rejected = False
        self._session_cache_query_rejected = False
        self._session_list_body_rejected = False
        self._session_trigger_shapes: set[str] = set()
        self._daily_session_headers: dict[str, str] | None = None
        self._daily_body: dict[str, object] | None = None
        self._daily_private_body: dict[str, object] | None = None
        self._daily_response_fields: list[dict[str, str]] | None = None
        self._daily_probe_body: dict[str, object] | None = None
        self._daily_probe_content: bytes | None = None
        self._daily_probe_read_pending = False
        self._daily_authority_scope_sha256: str | None = None
        self._daily_platform_display_total: int | None = None
        self._daily_cache_refresh_count = 0
        self._automated_prepared = False
        self._automated_scope: str | None = None
        self._operational_compat_prepared = False
        self._operational_first_list_content: bytes | None = None
        self._operational_first_page_number: int | None = None
        self._operational_first_page_size: int | None = None
        self._operational_query_trace: dict[str, object] | None = None
        self._active_contract_subject_code: str | None = None
        self._human_page: Any | None = None
        self._operational_batch_page: Any | None = None
        self._operational_batch_route_handler: Any | None = None
        self._operational_batch_allowed_ids: set[str] = set()
        self._operational_batch_seen_ids: set[str] = set()
        self._operational_batch_list_body: dict[str, object] | None = None
        self._operational_batch_list_cache_query: str | None = None
        self._operational_batch_list_seen = False
        self._operational_daily_list_body: dict[str, object] | None = None
        self._operational_daily_list_seen = False
        self._operational_daily_authority_body: dict[str, object] | None = None
        self._operational_daily_authority_seen = False
        self._staging_root: Path | None = None
        self._detail_image_grants: dict[str, float] = {}
        self._monotonic = monotonic

    def is_open(self) -> bool:
        if self._context is None:
            return False
        try:
            return any(not bool(page.is_closed()) for page in tuple(self._context.pages))
        except Exception:
            return False

    def initialize(
        self,
        command: InitializeCommand | InitializeHeadlessCommand,
    ) -> str:
        if self._context is not None:
            raise RuntimeError("browser context is already initialized")
        os.environ.setdefault(
            "PLAYWRIGHT_BROWSERS_PATH",
            str(Path(sys.prefix).resolve().parent / "browsers"),
        )
        from playwright.sync_api import Error, sync_playwright

        candidates = _browser_candidates()
        if command.browser != "auto":
            candidates = tuple(item for item in candidates if item[0] == command.browser)
        self._playwright = sync_playwright().start()
        profile_root = command.profile_root.resolve()
        if profile_root.name != "chengfeng-shadow" or profile_root.parent.name != "browser-profile":
            self.close()
            raise RuntimeError("browser profile is not in the managed layout")
        data_root = profile_root.parent.parent
        expected_staging = data_root / "runtime" / "browser-worker" / "read-results"
        staging_root = assert_managed_store(
            command.staging_root,
            allowed_root=data_root,
        )
        if staging_root != expected_staging.resolve():
            self.close()
            raise RuntimeError("browser read staging is not in the managed layout")
        staging_root.mkdir(parents=True, exist_ok=True)
        if staging_root.is_symlink():
            self.close()
            raise RuntimeError("browser read staging cannot be a symbolic link")
        try:
            recover_read_result_staging(staging_root)
        except RuntimeError:
            self.close()
            raise
        self._staging_root = staging_root
        failures: list[str] = []
        for browser_name, executable in candidates:
            profile = command.profile_root / browser_name
            profile.mkdir(parents=True, exist_ok=True)
            try:
                launch_options = (
                    {} if executable is None else {"executable_path": os.fspath(executable)}
                )
                headless = isinstance(command, InitializeHeadlessCommand)
                self._context = self._playwright.chromium.launch_persistent_context(
                    user_data_dir=profile,
                    headless=headless,
                    chromium_sandbox=True,
                    no_viewport=True,
                    service_workers="block",
                    **launch_options,
                )
                self._install_session_request_handler()
                page = self._context.pages[0] if self._context.pages else self._context.new_page()
                self._human_page = page
                try:
                    _open_human_login_entry(page)
                    page = self._human_page_or_create(wait_for_hydrated=True)
                    self._install_single_chengfeng_page_guard()
                    if headless and _wait_for_entry_login_state(page):
                        _login_with_saved_credential(
                            page,
                            contract_subject_code="shanxi_guienbo",
                        )
                except LoginEntryError:
                    self._context.close()
                    self._context = None
                    self.close()
                    raise
                except BrowserReadError:
                    self._context.close()
                    self._context = None
                    self.close()
                    raise
                self.selected_browser = browser_name
                return browser_name
            except LoginEntryError:
                raise
            except BrowserReadError:
                raise
            except (Error, OSError, RuntimeError) as exc:
                failures.append(type(exc).__name__)
        self.close()
        raise RuntimeError("no browser could be initialized: " + ",".join(failures))

    def read(
        self,
        command: ReadJsonCommand | ReadDailyJsonCommand | ReadImageCommand,
    ) -> dict[str, object]:
        if self._context is None or self._staging_root is None:
            raise BrowserReadError("browser_context_closed")
        is_daily = isinstance(command, ReadDailyJsonCommand)
        is_json = isinstance(command, (ReadJsonCommand, ReadDailyJsonCommand))
        if isinstance(command, ReadImageCommand) and not is_approved_image_read_url(command.url):
            raise BrowserReadError("browser_image_origin_denied")
        if isinstance(command, ReadImageCommand):
            self._prune_detail_image_grants()
            if command.url not in self._detail_image_grants:
                raise BrowserReadError("browser_image_not_registered")
        options: dict[str, object] = {
            "method": command.method,
            "fail_on_status_code": False,
            "max_redirects": 0,
            "timeout": JSON_READ_TIMEOUT_MS if is_json else IMAGE_READ_TIMEOUT_MS,
        }
        if is_json:
            if is_daily:
                if not _approved_daily_json_read_url(command.url):
                    raise BrowserReadError("browser_read_contract_changed")
                if self._daily_session_headers is None:
                    raise BrowserReadError("browser_read_login_required")
                if self._daily_body is None or self._daily_response_fields is None:
                    raise BrowserReadError("browser_daily_prepare_required")
                data = _validate_daily_read_parameters(
                    command.parameters,
                    baseline=self._daily_body,
                )
                request_url = command.url
                options["headers"] = dict(self._daily_session_headers)
            else:
                if not _approved_json_read_url(command.url):
                    raise BrowserReadError("browser_read_contract_changed")
                data = {
                    key: list(value) if isinstance(value, tuple) else value
                    for key, value in command.parameters.items()
                }
                request_url = command.url
                if command.operation == "list_waybills":
                    request_headers = self._session_headers
                else:
                    request_headers = self._session_headers or self._daily_session_headers
                if request_headers is None:
                    raise BrowserReadError("browser_read_login_required")
            if not is_daily and command.operation == "list_waybills":
                settlement_scope = self._automated_scope or CURRENT_PENDING_SETTLEMENT_SCOPE
                expected_list_path = (
                    CHENGFENG_HISTORICAL_LIST_PATH
                    if settlement_scope == HISTORICAL_SETTLED_SCOPE
                    else CHENGFENG_LIST_PATH
                )
                if (
                    settlement_scope not in APPROVED_SETTLEMENT_SCOPES
                    or command.url != f"{_CHENGFENG_ORIGIN}{expected_list_path}"
                ):
                    raise BrowserReadError("browser_read_contract_changed")
                if (
                    not self._operational_compat_prepared
                    and self._session_list_fixed_values is None
                ):
                    raise BrowserReadError("browser_session_fixed_values_unavailable")
                if self._session_list_cache_query is None:
                    raise BrowserReadError("browser_session_cache_query_unavailable")
                if self._session_list_body_sha256 is None:
                    raise BrowserReadError("browser_session_list_body_unavailable")
                if self._session_list_body is None:
                    raise BrowserReadError("browser_session_list_body_unavailable")
                if self._operational_compat_prepared:
                    if settlement_scope != CURRENT_PENDING_SETTLEMENT_SCOPE:
                        raise BrowserReadError("browser_read_contract_changed")
                    requested_page = data.get("pageNumber")
                    requested_size = data.get("pageSize")
                    if (
                        type(requested_page) is not int
                        or not 1 <= requested_page <= MAX_NATIVE_LIST_PAGE_NUMBER
                        or type(requested_size) is not int
                        or not 1 <= requested_size <= MAX_NATIVE_LIST_LENGTH
                    ):
                        raise BrowserReadError("browser_read_contract_changed")
                    final_data = dict(self._session_list_body)
                    final_data["pageNumber"] = requested_page
                    final_data["pageSize"] = requested_size
                    if (
                        _normalized_private_list_body_sha256(
                            final_data,
                            scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                        )
                        != self._session_list_body_sha256
                    ):
                        raise BrowserReadError("browser_operational_query_body_changed")
                    data = final_data
                    request_url = f"{command.url}?{self._session_list_cache_query}"
                elif settlement_scope == HISTORICAL_SETTLED_SCOPE:
                    if set(data) != {
                        "deptCode",
                        "pageNumber",
                        "pageSize",
                        "sortParams",
                    }:
                        raise BrowserReadError("browser_read_contract_changed")
                    if data.get("deptCode") != "" or data.get("sortParams") != []:
                        raise BrowserReadError("browser_read_contract_changed")
                elif not {
                    "order",
                    "queryType",
                    "settleQueryType",
                }.issubset(data):
                    raise BrowserReadError("browser_read_contract_changed")
                requested_fields = set(data)
                baseline_fields = set(self._session_list_body)
                if not self._operational_compat_prepared and requested_fields != baseline_fields:
                    if requested_fields < baseline_fields:
                        mismatch_code = "browser_session_list_body_fields_added"
                    elif baseline_fields < requested_fields:
                        mismatch_code = "browser_session_list_body_fields_removed"
                    else:
                        mismatch_code = "browser_session_list_body_fields_changed"
                    raise BrowserReadError(
                        mismatch_code,
                        safe_discovery=[
                            _private_list_structure_observation(
                                self._session_list_body,
                                scope=settlement_scope,
                            )
                        ],
                    )
                if (
                    not self._operational_compat_prepared
                    and settlement_scope == CURRENT_PENDING_SETTLEMENT_SCOPE
                ):
                    for key, value in data.items():
                        if key in {
                            "order",
                            "pageNumber",
                            "pageSize",
                            "queryType",
                            "settleQueryType",
                        }:
                            continue
                        if value != "" and value != []:
                            raise BrowserReadError("browser_session_list_body_filter_mismatch")
                if not self._operational_compat_prepared:
                    final_data = dict(self._session_list_body)
                    for key in ("pageNumber", "pageSize"):
                        requested = data.get(key)
                        if type(requested) is not int or requested <= 0:
                            raise BrowserReadError("browser_read_contract_changed")
                        final_data[key] = requested
                    if (
                        _normalized_private_list_body_sha256(
                            final_data,
                            scope=settlement_scope,
                        )
                        != self._session_list_body_sha256
                    ):
                        raise BrowserReadError("browser_session_list_body_hash_mismatch")
                    data = final_data
                    request_url = f"{command.url}?{self._session_list_cache_query}"
            if (
                not is_daily
                and isinstance(command, ReadJsonCommand)
                and command.operation == "get_waybill_detail"
            ):
                options["form"] = data
            else:
                options["data"] = data
            if not is_daily:
                options["headers"] = {
                    name: value
                    for name, value in request_headers.items()
                    if (
                        command.operation != "get_waybill_detail"
                        or name.casefold() != "content-type"
                    )
                }
        else:
            request_url = command.url
        if is_daily and self._daily_probe_read_pending:
            probe_body = self._daily_probe_body
            probe_content = self._daily_probe_content
            self._daily_probe_read_pending = False
            self._daily_probe_body = None
            self._daily_probe_content = None
            if probe_body is None or probe_content is None:
                raise BrowserReadError("browser_daily_probe_cache_unavailable")
            mismatch = _daily_probe_request_mismatch(
                probe_body=probe_body,
                requested_body=data,
            )
            if mismatch is None:
                content = probe_content
                digest = hashlib.sha256(content).hexdigest()
                relative_path = self._stage_read_payload(
                    request_id=command.request_id,
                    suffix=".json",
                    content=content,
                )
                return {
                    "relative_path": relative_path,
                    "sha256": digest,
                    "byte_size": len(content),
                    "media_type": "application/json",
                    "status_code": 200,
                }
            # The discovery response proves only the request/response shape.
            # A different validated business day or page must use a fresh
            # read instead of being rejected as if the probe were the target.
        if is_daily and self._daily_private_body is not None:
            content, _response_fields = self._read_daily_list_in_page(
                body=data,
                require_nonempty=False,
            )
            digest = hashlib.sha256(content).hexdigest()
            relative_path = self._stage_read_payload(
                request_id=command.request_id,
                suffix=".json",
                content=content,
            )
            return {
                "relative_path": relative_path,
                "sha256": digest,
                "byte_size": len(content),
                "media_type": "application/json",
                "status_code": 200,
            }
        if (
            not is_daily
            and isinstance(command, ReadJsonCommand)
            and command.operation == "list_waybills"
            and self._operational_compat_prepared
            and self._operational_first_list_content is not None
            and data.get("pageNumber") == self._operational_first_page_number
            and data.get("pageSize") == self._operational_first_page_size
        ):
            content = self._operational_first_list_content
            digest = hashlib.sha256(content).hexdigest()
            relative_path = self._stage_read_payload(
                request_id=command.request_id,
                suffix=".json",
                content=content,
            )
            return {
                "relative_path": relative_path,
                "sha256": digest,
                "byte_size": len(content),
                "media_type": "application/json",
                "status_code": 200,
            }
        if (
            not is_daily
            and isinstance(command, ReadJsonCommand)
            and command.operation == "list_waybills"
            and self._operational_compat_prepared
        ):
            content = self._read_operational_list_in_page(
                url=request_url,
                body=data,
            )
            digest = hashlib.sha256(content).hexdigest()
            relative_path = self._stage_read_payload(
                request_id=command.request_id,
                suffix=".json",
                content=content,
            )
            return {
                "relative_path": relative_path,
                "sha256": digest,
                "byte_size": len(content),
                "media_type": "application/json",
                "status_code": 200,
            }
        try:
            response = self._context.request.fetch(request_url, **options)
        except Exception as exc:
            raise BrowserReadError("browser_read_network_failed") from exc
        try:
            status = int(response.status)
            headers = {str(key).casefold(): str(value) for key, value in response.headers.items()}
        except (AttributeError, TypeError, ValueError) as exc:
            raise BrowserReadError("browser_read_contract_changed") from exc
        if status in {401, 403}:
            raise BrowserReadError("browser_read_login_required")
        if 300 <= status < 400:
            raise BrowserReadError("browser_read_redirect_rejected")
        if status != 200:
            raise BrowserReadError("browser_read_http_failed")
        media_type = headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        if is_json:
            if media_type != "application/json" and not media_type.endswith("+json"):
                raise BrowserReadError("browser_read_contract_changed")
            media_type = "application/json"
            suffix = ".json"
            maximum = MAX_JSON_READ_BYTES
        else:
            suffix = _IMAGE_MEDIA_TYPES.get(media_type, "")
            if not suffix:
                raise BrowserReadError("browser_image_contract_changed")
            maximum = MAX_IMAGE_READ_BYTES
        try:
            content = response.body()
        except Exception as exc:
            raise BrowserReadError("browser_read_network_failed") from exc
        finally:
            dispose = getattr(response, "dispose", None)
            if callable(dispose):
                with suppress(Exception):
                    dispose()
        del response
        if not isinstance(content, bytes) or not content or len(content) > maximum:
            raise BrowserReadError("browser_read_size_invalid")
        detail_image_urls: tuple[str, ...] = ()
        if is_json:
            try:
                parsed = json.loads(content.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BrowserReadError("browser_read_contract_changed") from exc
            if not isinstance(parsed, dict):
                raise BrowserReadError("browser_read_contract_changed")
            if isinstance(command, ReadJsonCommand) and command.operation == "get_waybill_detail":
                detail_image_urls = _validated_detail_image_urls(
                    parsed,
                    expected_platform_waybill_id=command.parameters.get("id"),
                )
            if is_daily:
                try:
                    _daily_response_fields(
                        parsed,
                        require_nonempty=False,
                    )
                except BrowserReadError as exc:
                    if exc.code != "browser_daily_response_contract_changed":
                        raise
                    raise BrowserReadError(
                        exc.code,
                        safe_discovery=[
                            _daily_read_structure_observation(
                                body=data,
                                response_fields=_json_fields(parsed),
                            )
                        ],
                    ) from exc
                normalized_content = _normalized_daily_read_bytes(parsed)
                del parsed
                content = normalized_content
                del normalized_content
        digest = hashlib.sha256(content).hexdigest()
        byte_size = len(content)
        relative_path = self._stage_read_payload(
            request_id=command.request_id,
            suffix=suffix,
            content=content,
        )
        if detail_image_urls:
            expiry = self._monotonic() + DETAIL_IMAGE_GRANT_TTL_SECONDS
            self._prune_detail_image_grants()
            for image_url in detail_image_urls:
                self._detail_image_grants[image_url] = expiry
        del content
        return {
            "relative_path": relative_path,
            "sha256": digest,
            "byte_size": byte_size,
            "media_type": media_type,
            "status_code": status,
        }

    def _read_operational_list_in_page(
        self,
        *,
        url: str,
        body: Mapping[str, object],
    ) -> bytes:
        """Continue list pagination through the authenticated page network."""

        page = self._operational_batch_page
        if (
            page is None
            or bool(page.is_closed())
            or self._operational_batch_route_handler is None
            or self._session_headers is None
            or self._session_list_cache_query is None
        ):
            raise BrowserReadError("browser_operational_batch_prepare_required")
        page_headers = {
            name: value
            for name, value in self._session_headers.items()
            if name.casefold() not in _SESSION_HEADER_BLOCKLIST
            and name.casefold() not in {"origin", "referer", "user-agent"}
            and not name.casefold().startswith("sec-")
        }
        page_headers["content-type"] = "application/json;charset=UTF-8"
        self._operational_batch_list_body = dict(body)
        self._operational_batch_list_cache_query = self._session_list_cache_query
        self._operational_batch_list_seen = False
        try:
            raw_result = page.evaluate(
                _OPERATIONAL_LIST_FETCH_SCRIPT,
                {
                    "url": url,
                    "headers": page_headers,
                    "body": dict(body),
                },
            )
        except Exception as exc:
            raise BrowserReadError("browser_read_network_failed") from exc
        finally:
            self._operational_batch_list_body = None
            self._operational_batch_list_cache_query = None
        if not self._operational_batch_list_seen:
            self._operational_batch_list_seen = False
            raise BrowserReadError("browser_read_contract_changed")
        self._operational_batch_list_seen = False
        if not isinstance(raw_result, Mapping):
            raise BrowserReadError("browser_read_contract_changed")
        status = raw_result.get("status")
        if status in {401, 403}:
            raise BrowserReadError("browser_read_login_required")
        if status == 429:
            raise BrowserReadError("browser_read_rate_limited")
        if type(status) is int and 500 <= status < 600:
            raise BrowserReadError("browser_read_server_transient")
        if raw_result.get("redirected") is not False:
            raise BrowserReadError("browser_read_redirect_rejected")
        if type(status) is not int or status != 200:
            raise BrowserReadError("browser_read_http_failed")
        content_type = raw_result.get("contentType")
        if not isinstance(content_type, str):
            raise BrowserReadError("browser_read_contract_changed")
        media_type = content_type.split(";", 1)[0].strip().casefold()
        if media_type != "application/json" and not media_type.endswith("+json"):
            raise BrowserReadError("browser_read_contract_changed")
        raw_body = raw_result.get("body")
        if not isinstance(raw_body, str):
            raise BrowserReadError("browser_read_contract_changed")
        content = raw_body.encode("utf-8", errors="strict")
        if not content or len(content) > MAX_JSON_READ_BYTES:
            raise BrowserReadError("browser_read_size_invalid")
        try:
            parsed = json.loads(content.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrowserReadError("browser_read_contract_changed") from exc
        if not isinstance(parsed, dict):
            raise BrowserReadError("browser_read_contract_changed")
        return content

    def _read_daily_list_in_page(
        self,
        *,
        body: Mapping[str, object],
        require_nonempty: bool,
    ) -> tuple[bytes, list[dict[str, str]]]:
        """Run one fixed daily query inside the authenticated Chengfeng page."""

        page = self._operational_batch_page
        private_baseline = self._daily_private_body
        if (
            page is None
            or bool(page.is_closed())
            or self._operational_batch_route_handler is None
            or self._daily_session_headers is None
            or private_baseline is None
        ):
            raise BrowserReadError("browser_daily_prepare_required")
        private_body = dict(private_baseline)
        for name in _DAILY_CONTROLLED_FIELDS:
            if name not in body:
                raise BrowserReadError("browser_daily_request_fields_changed")
            private_body[name] = body[name]
        scope_sha256 = _daily_scope_sha256(private_body)
        if body.get("pageNumber") == 1 and (
            scope_sha256 != self._daily_authority_scope_sha256
            or self._daily_platform_display_total is None
        ):
            return self._read_page_authoritative_daily_list(
                body=body,
                private_body=private_body,
                require_nonempty=require_nonempty,
            )
        page_headers = {
            name: value
            for name, value in self._daily_session_headers.items()
            if name.casefold() not in _SESSION_HEADER_BLOCKLIST
            and name.casefold() not in {"origin", "referer", "user-agent"}
            and not name.casefold().startswith("sec-")
        }
        page_headers["content-type"] = "application/json;charset=UTF-8"
        request_url = (
            f"{_CHENGFENG_ORIGIN}{CHENGFENG_DAILY_LIST_PATH}"
            f"?t={int(datetime.now().timestamp() * 1000)}"
        )
        self._operational_daily_list_body = dict(private_body)
        self._operational_daily_list_seen = False
        try:
            raw_result = page.evaluate(
                _OPERATIONAL_LIST_FETCH_SCRIPT,
                {
                    "url": request_url,
                    "headers": page_headers,
                    "body": private_body,
                },
            )
        except Exception as exc:
            raise BrowserReadError("browser_read_network_failed") from exc
        finally:
            self._operational_daily_list_body = None
        if not self._operational_daily_list_seen:
            self._operational_daily_list_seen = False
            raise BrowserReadError("browser_read_contract_changed")
        self._operational_daily_list_seen = False
        if not isinstance(raw_result, Mapping):
            raise BrowserReadError("browser_read_contract_changed")
        status = raw_result.get("status")
        if status in {401, 403}:
            raise BrowserReadError("browser_read_login_required")
        if status == 429:
            raise BrowserReadError("browser_read_rate_limited")
        if type(status) is int and 500 <= status < 600:
            raise BrowserReadError("browser_read_server_transient")
        if raw_result.get("redirected") is not False:
            raise BrowserReadError("browser_read_redirect_rejected")
        if type(status) is not int or status != 200:
            raise BrowserReadError("browser_read_http_failed")
        content_type = raw_result.get("contentType")
        if not isinstance(content_type, str):
            raise BrowserReadError("browser_read_contract_changed")
        media_type = content_type.split(";", 1)[0].strip().casefold()
        if media_type != "application/json" and not media_type.endswith("+json"):
            raise BrowserReadError("browser_read_contract_changed")
        raw_body = raw_result.get("body")
        if not isinstance(raw_body, str):
            raise BrowserReadError("browser_read_contract_changed")
        content = raw_body.encode("utf-8", errors="strict")
        if not content or len(content) > MAX_JSON_READ_BYTES:
            raise BrowserReadError("browser_read_size_invalid")
        try:
            parsed = json.loads(content.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrowserReadError("browser_read_contract_changed") from exc
        response_fields = _daily_response_fields(
            parsed,
            require_nonempty=require_nonempty,
        )
        _validate_page_owned_daily_scope(
            parsed,
            request_body=body,
        )
        response_total = parsed.get("data", {}).get("total")
        if type(response_total) is not int or response_total < 0:
            raise BrowserReadError("browser_daily_response_contract_changed")
        page_display_total = (
            self._daily_platform_display_total
            if scope_sha256 == self._daily_authority_scope_sha256
            else None
        )
        display_total = page_display_total if page_display_total == response_total else None
        page_size = int(body["pageSize"])
        response_page_count = max(
            1,
            (response_total + page_size - 1) // page_size,
        )
        normalized = _normalized_daily_read_bytes(
            parsed,
            scope_metadata={
                "platform_display_total": display_total,
                "response_total": response_total,
                "response_page_count": response_page_count,
                "query_scope_sha256": scope_sha256,
                "scope_complete": True,
                "scope_diagnostic_code": None,
            },
        )
        return normalized, response_fields

    def _read_page_authoritative_daily_list(
        self,
        *,
        body: Mapping[str, object],
        private_body: Mapping[str, object],
        require_nonempty: bool,
        retry_after_refresh: bool = False,
    ) -> tuple[bytes, list[dict[str, str]]]:
        """Run the target first page through Chengfeng's own query button."""

        page = self._operational_batch_page
        if page is None or bool(page.is_closed()):
            raise BrowserReadError("browser_daily_prepare_required")
        self._operational_daily_authority_body = dict(private_body)
        self._operational_daily_authority_seen = False
        native_response = None
        try:
            _, _, query_button = self._wait_for_daily_controls(page)
            with page.expect_response(
                lambda candidate: _is_daily_native_request(getattr(candidate, "request", None)),
                timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
            ) as response_info:
                query_button.click(timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS)
            native_response = response_info.value
            self._wait_for_operational_ui_idle(page)
            if not self._operational_daily_authority_seen:
                raise BrowserReadError("browser_daily_page_request_not_constructed")
            status = int(getattr(native_response, "status", 0))
            if status in {401, 403}:
                raise BrowserReadError("browser_read_login_required")
            if status == 429:
                raise BrowserReadError("browser_read_rate_limited")
            if 500 <= status < 600:
                raise BrowserReadError("browser_read_server_transient")
            if status != 200:
                raise BrowserReadError("browser_read_http_failed")
            content = native_response.body()
            if not isinstance(content, bytes) or not content or len(content) > MAX_JSON_READ_BYTES:
                raise BrowserReadError("browser_read_size_invalid")
            try:
                parsed = json.loads(content.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BrowserReadError("browser_read_contract_changed") from exc
            response_fields = _daily_response_fields(
                parsed,
                require_nonempty=require_nonempty,
            )
            _validate_page_owned_daily_scope(parsed, request_body=body)
            response_total = parsed.get("data", {}).get("total")
            if type(response_total) is not int or response_total < 0:
                raise BrowserReadError("browser_daily_response_contract_changed")
            if response_total == 0 and not retry_after_refresh:
                self._refresh_daily_page_authority_after_zero(page)
                refreshed_private_body = self._daily_private_body
                if refreshed_private_body is None:
                    raise BrowserReadError("browser_daily_prepare_required")
                retry_private_body = dict(refreshed_private_body)
                for name in _DAILY_CONTROLLED_FIELDS:
                    retry_private_body[name] = body[name]
                return self._read_page_authoritative_daily_list(
                    body=body,
                    private_body=retry_private_body,
                    require_nonempty=require_nonempty,
                    retry_after_refresh=True,
                )
            page_display_total = _daily_platform_display_total(page)
            display_total = page_display_total if page_display_total == response_total else None
            scope_sha256 = _daily_scope_sha256(private_body)
            page_size = int(body["pageSize"])
            response_page_count = max(
                1,
                (response_total + page_size - 1) // page_size,
            )
            self._daily_authority_scope_sha256 = scope_sha256
            self._daily_platform_display_total = display_total
            normalized = _normalized_daily_read_bytes(
                parsed,
                scope_metadata={
                    "platform_display_total": display_total,
                    "response_total": response_total,
                    "response_page_count": response_page_count,
                    "query_scope_sha256": scope_sha256,
                    "scope_complete": True,
                    "scope_diagnostic_code": None,
                },
            )
            return normalized, response_fields
        except BrowserReadError:
            raise
        except Exception as exc:
            if _page_requires_login(page):
                raise BrowserReadError("browser_read_login_required") from exc
            raise BrowserReadError("browser_daily_page_query_failed") from exc
        finally:
            self._operational_daily_authority_body = None
            self._operational_daily_authority_seen = False

    def _refresh_daily_page_authority_after_zero(self, page: Any) -> None:
        """Rebuild the private daily baseline after one authoritative zero."""

        if self._context is None:
            raise BrowserReadError("browser_context_closed")
        captured_headers: dict[str, str] | None = None
        captured_private_body: dict[str, object] | None = None

        def navigation_route(route: Any) -> None:
            nonlocal captured_headers, captured_private_body
            request = getattr(route, "request", None)
            method = str(getattr(request, "method", "")).upper()
            if method in {"GET", "HEAD"}:
                route.continue_()
                return
            if _is_daily_native_request(request):
                headers = _daily_session_headers_from_request(request)
                private = _private_daily_body_from_request(request)
                if headers is not None and private is not None:
                    captured_headers = dict(headers)
                    captured_private_body = dict(private)
                    route.continue_()
                    return
            if _approved_discovery_request(request) or _approved_daily_bootstrap_request(request):
                route.continue_()
                return
            route.abort()

        self._remove_operational_batch_page()
        route_installed = False
        try:
            page.route("**/*", navigation_route)
            route_installed = True
            self._refresh_page_without_cache(
                page,
                error_code="browser_daily_cache_refresh_failed",
            )
            self._wait_for_daily_controls(page)
            if captured_headers is None or captured_private_body is None:
                _, _, query_button = self._wait_for_daily_controls(page)
                with page.expect_response(
                    lambda candidate: _is_daily_native_request(getattr(candidate, "request", None)),
                    timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                ):
                    query_button.click(timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS)
                self._wait_for_operational_ui_idle(page)
            if captured_headers is None or captured_private_body is None:
                if _page_requires_login(page):
                    raise BrowserReadError("browser_read_login_required")
                raise BrowserReadError("browser_daily_page_request_not_constructed")
        except BrowserReadError:
            with suppress(Exception):
                page.close()
            raise
        except Exception as exc:
            with suppress(Exception):
                page.close()
            raise BrowserReadError("browser_daily_cache_refresh_failed") from exc
        finally:
            if route_installed:
                with suppress(Exception):
                    page.unroute("**/*", navigation_route)
        self._daily_session_headers = captured_headers
        self._daily_private_body = captured_private_body
        self._daily_authority_scope_sha256 = None
        self._daily_platform_display_total = None
        self._install_operational_batch_page(page)
        self._daily_cache_refresh_count += 1

    def read_operational_batch(
        self,
        command: ReadOperationalBatchCommand | CaptureOperationalWholeRunCommand,
        *,
        abort_event: Event | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> list[dict[str, object]]:
        """Read one validated capture unit without exposing session or signed URLs."""

        def abort_requested() -> bool:
            return abort_event is not None and abort_event.is_set()

        def ensure_not_aborted() -> None:
            if abort_requested():
                raise BrowserReadError("browser_read_cancelled")

        def emit_progress(phase: str, completed: int, total: int) -> None:
            if progress_callback is not None:
                progress_callback(phase, completed, total)

        def run_bounded_tasks(
            *,
            tasks: list[object],
            worker: Callable[[object], object],
            maximum_workers: int,
            thread_name_prefix: str,
            phase: str,
        ) -> list[object]:
            """Run only one bounded concurrency window and remain abortable."""

            if not tasks:
                return []
            executor = ThreadPoolExecutor(
                max_workers=maximum_workers,
                thread_name_prefix=thread_name_prefix,
            )
            pending: dict[Future[object], int] = {}
            results: list[object | None] = [None] * len(tasks)
            next_index = 0
            completed = 0

            def submit_available() -> None:
                nonlocal next_index
                while (
                    next_index < len(tasks)
                    and len(pending) < maximum_workers
                    and not abort_requested()
                ):
                    index = next_index
                    next_index += 1
                    pending[executor.submit(worker, tasks[index])] = index

            try:
                ensure_not_aborted()
                submit_available()
                while pending:
                    ensure_not_aborted()
                    done, _not_done = wait(
                        tuple(pending),
                        timeout=0.1,
                        return_when=FIRST_COMPLETED,
                    )
                    if not done:
                        continue
                    for future in done:
                        index = pending.pop(future)
                        results[index] = future.result()
                        completed += 1
                        emit_progress(phase, completed, len(tasks))
                    submit_available()
                ensure_not_aborted()
                if next_index != len(tasks) or any(result is None for result in results):
                    raise BrowserReadError("browser_read_cancelled")
                return [result for result in results if result is not None]
            except BaseException:
                for future in pending:
                    future.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
                raise
            finally:
                if not pending:
                    executor.shutdown(wait=True)

        if (
            not self._private_batch_session_frozen
            and self._context is not None
            and (self._session_headers is not None or self._daily_session_headers is not None)
        ):
            self._freeze_private_batch_session()
        page = self._operational_batch_page
        if isinstance(command, CaptureOperationalWholeRunCommand) and (
            self._active_contract_subject_code != command.contract_subject_code
            or page is None
            or bool(page.is_closed())
            or _selected_contract_subject_code(page, login_page=False)
            != command.contract_subject_code
        ):
            raise BrowserReadError("browser_contract_subject_confirmation_failed")
        if (
            self._staging_root is None
            or not (self._operational_compat_prepared or self._daily_session_headers is not None)
            or (self._session_headers is None and self._daily_session_headers is None)
            or not self._private_batch_session_frozen
        ):
            raise BrowserReadError("browser_operational_batch_prepare_required")
        session_headers = self._session_headers or self._daily_session_headers
        assert session_headers is not None
        page_headers = {
            name: value
            for name, value in session_headers.items()
            if name.casefold() not in _SESSION_HEADER_BLOCKLIST
            and name.casefold()
            not in {
                "content-type",
                "origin",
                "referer",
                "user-agent",
            }
            and not name.casefold().startswith("sec-")
        }
        detail_requests = [
            {
                "platformWaybillId": detail.platform_waybill_id,
                "url": detail.url,
            }
            for detail in command.details
        ]
        allowed_ids = {detail.platform_waybill_id for detail in command.details}
        if len(allowed_ids) != len(command.details):
            raise BrowserReadError("browser_read_contract_changed")

        def read_details_in_page() -> list[object]:
            if (
                page is None
                or bool(page.is_closed())
                or self._operational_batch_route_handler is None
            ):
                raise BrowserReadError("browser_read_login_required")
            self._operational_batch_allowed_ids = set(allowed_ids)
            self._operational_batch_seen_ids = set()
            try:
                page_results = page.evaluate(
                    _OPERATIONAL_BATCH_FETCH_SCRIPT,
                    {
                        "requests": detail_requests,
                        "headers": page_headers,
                        "concurrency": command.detail_concurrency,
                        "timeoutMs": JSON_READ_TIMEOUT_MS,
                    },
                )
            except Exception as exc:
                raise BrowserReadError("browser_read_network_failed") from exc
            finally:
                self._operational_batch_allowed_ids = set()
            if self._operational_batch_seen_ids != allowed_ids:
                self._operational_batch_seen_ids = set()
                raise BrowserReadError("browser_read_contract_changed")
            self._operational_batch_seen_ids = set()
            if not isinstance(page_results, list):
                raise BrowserReadError("browser_read_contract_changed")
            return page_results

        # The authoritative list query has already frozen the identities. Read
        # only the fixed, protocol-validated detail endpoint from worker-private
        # memory so each request can complete independently and report progress.
        detail_headers_by_url = {
            str(detail.url): self._private_batch_headers(
                url=str(detail.url),
                image=False,
            )
            for detail in command.details
        }

        def read_detail_direct(detail_value: object) -> dict[str, object]:
            detail = detail_value
            platform_waybill_id = str(detail.platform_waybill_id)
            url = str(detail.url)
            content, _media_type, _validator = _bounded_http_fetch(
                url=url,
                method="POST",
                headers=detail_headers_by_url[url],
                body=urlencode({"id": platform_waybill_id}).encode("ascii"),
                maximum_bytes=MAX_JSON_READ_BYTES,
                expected_image=False,
                timeout_seconds=JSON_READ_TIMEOUT_MS / 1000,
            )
            return {
                "status": 200,
                "redirected": False,
                "contentType": "application/json",
                "body": content.decode("utf-8", errors="strict"),
            }

        def read_all_details_direct() -> list[object]:
            return run_bounded_tasks(
                tasks=list(command.details),
                worker=read_detail_direct,
                maximum_workers=command.detail_concurrency,
                thread_name_prefix="chengfeng-detail",
                phase="detail",
            )

        page_read_available = (
            not self._prefer_private_http_batch_reads
            and page is not None
            and not bool(page.is_closed())
            and self._operational_batch_route_handler is not None
        )
        if page_read_available:
            try:
                raw_results = read_details_in_page()
            except BrowserReadError as exc:
                if exc.code not in {
                    "browser_read_login_required",
                    "browser_read_network_failed",
                }:
                    raise
                self._operational_batch_seen_ids = set()
                raw_results = read_all_details_direct()
        else:
            detail_results = read_all_details_direct()
            raw_results = [result for result in detail_results if isinstance(result, dict)]
        if not isinstance(raw_results, list) or len(raw_results) != len(command.details):
            raise BrowserReadError("browser_read_contract_changed")

        parsed_detail_results: list[
            tuple[
                int,
                str,
                bytes,
                str,
                tuple[tuple[str, str], ...],
            ]
        ] = []
        for detail_index, (detail, raw_result) in enumerate(
            zip(command.details, raw_results, strict=True)
        ):
            ensure_not_aborted()
            if not isinstance(raw_result, Mapping):
                raise BrowserReadError("browser_read_contract_changed")
            status = raw_result.get("status")
            if status in {401, 403}:
                raise BrowserReadError("browser_read_login_required")
            if raw_result.get("redirected") is not False or (
                type(status) is not int or status != 200
            ):
                raise BrowserReadError("browser_read_http_failed")
            content_type = raw_result.get("contentType")
            if (
                not isinstance(content_type, str)
                or content_type.split(";", 1)[0].strip().casefold() != "application/json"
            ):
                raise BrowserReadError("browser_read_contract_changed")
            raw_body = raw_result.get("body")
            if not isinstance(raw_body, str):
                raise BrowserReadError("browser_read_contract_changed")
            content = raw_body.encode("utf-8", errors="strict")
            if not content or len(content) > MAX_JSON_READ_BYTES:
                raise BrowserReadError("browser_read_size_invalid")
            try:
                parsed = json.loads(content.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BrowserReadError("browser_read_contract_changed") from exc
            if not isinstance(parsed, dict):
                raise BrowserReadError("browser_read_contract_changed")
            images = _validated_detail_images(
                parsed,
                expected_platform_waybill_id=detail.platform_waybill_id,
            )
            detail_payload = parsed["data"][0]
            assert isinstance(detail_payload, dict)
            sanitized_content = json.dumps(
                {
                    "data": [
                        {
                            "carNumber": detail_payload.get("carNumber"),
                            "currentTon": detail_payload.get("currentTon"),
                            "id": detail_payload.get("id"),
                            "image": (
                                "worker-image:unloading"
                                if any(slot == "unloading" for slot, _url in images)
                                else None
                            ),
                            "originalTon": detail_payload.get("originalTon"),
                            "originalTonImageUrl": (
                                "worker-image:loading"
                                if any(slot == "loading" for slot, _url in images)
                                else None
                            ),
                            "sn": detail_payload.get("sn"),
                        }
                    ]
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            source_revision_sha256 = hashlib.sha256(sanitized_content).hexdigest()
            parsed_detail_results.append(
                (
                    detail_index,
                    detail.platform_waybill_id,
                    sanitized_content,
                    source_revision_sha256,
                    images,
                )
            )
            if page_read_available:
                emit_progress(
                    "detail",
                    detail_index + 1,
                    len(command.details),
                )

        batch_key = hashlib.sha256(command.request_id.encode("ascii")).hexdigest()[:20]
        staged_paths: list[str] = []
        staged_paths_lock = Lock()

        def read_image(
            task: tuple[
                int,
                str,
                str,
                Mapping[str, str],
                object,
            ],
        ) -> tuple[
            int,
            str,
            dict[str, object] | None,
            str,
            str | None,
            str | None,
        ]:
            detail_index, slot, url, headers, reuse_image = task
            if reuse_image is not None:
                probe = _bounded_http_image_probe(
                    url=url,
                    headers=headers,
                    timeout_seconds=IMAGE_READ_TIMEOUT_MS / 1000,
                    unsupported_hosts=(self._image_head_probe_unsupported_hosts),
                )
                if (
                    probe is not None
                    and probe[0] == reuse_image.media_type
                    and probe[1] == reuse_image.validator_sha256
                ):
                    return (
                        detail_index,
                        slot,
                        None,
                        reuse_image.media_type,
                        reuse_image.validator_sha256,
                        reuse_image.sha256,
                    )
            fetched = _bounded_http_fetch(
                url=url,
                method="GET",
                headers=headers,
                body=None,
                maximum_bytes=MAX_IMAGE_READ_BYTES,
                expected_image=True,
                timeout_seconds=IMAGE_READ_TIMEOUT_MS / 1000,
            )
            if len(fetched) == 2:
                content, media_type = fetched
                validator_sha256 = None
            else:
                content, media_type, validator_sha256 = fetched
            image_payload = self._stage_batch_payload(
                request_id=f"whole-{batch_key}-d{detail_index:04d}-{slot}",
                content=content,
                media_type=media_type,
            )
            with staged_paths_lock:
                staged_paths.append(str(image_payload["relative_path"]))
            return (
                detail_index,
                slot,
                image_payload,
                media_type,
                validator_sha256,
                None,
            )

        image_tasks: list[object] = []
        for (
            detail_index,
            _platform_waybill_id,
            _content,
            source_revision_sha256,
            images,
        ) in parsed_detail_results:
            for slot, image_url in images:
                image_tasks.append(
                    (
                        detail_index,
                        slot,
                        image_url,
                        self._private_batch_headers(
                            url=image_url,
                            image=True,
                        ),
                        next(
                            (
                                candidate
                                for candidate in (
                                    command.details[detail_index].reuse.images
                                    if command.details[detail_index].reuse is not None
                                    and command.details[detail_index].reuse.source_revision_sha256
                                    == source_revision_sha256
                                    else ()
                                )
                                if candidate.slot == slot
                            ),
                            None,
                        ),
                    )
                )
        try:
            image_task_results = run_bounded_tasks(
                tasks=image_tasks,
                worker=read_image,
                maximum_workers=command.image_concurrency,
                thread_name_prefix="chengfeng-image",
                phase="image",
            )
        except Exception:
            self._cleanup_batch_paths(staged_paths)
            raise
        parsed_details = tuple(
            (platform_waybill_id, content, source_revision_sha256, images)
            for (
                _detail_index,
                platform_waybill_id,
                content,
                source_revision_sha256,
                images,
            ) in parsed_detail_results
        )
        image_results = tuple(result for result in image_task_results if isinstance(result, tuple))
        total_bytes = sum(
            len(content) for _identity, content, _source_revision, _images in parsed_details
        )
        total_bytes += sum(
            int(payload["byte_size"])
            for (
                _detail_index,
                _slot,
                payload,
                _media_type,
                _validator,
                _reused_sha,
            ) in image_results
            if payload is not None
        )
        if total_bytes > MAX_OPERATIONAL_BATCH_BYTES:
            self._cleanup_batch_paths(staged_paths)
            raise BrowserReadError("browser_read_size_invalid")

        try:
            ensure_not_aborted()
            result_by_detail: list[dict[str, object]] = []
            for detail_index, (
                platform_waybill_id,
                detail_content,
                source_revision_sha256,
                _images,
            ) in enumerate(parsed_details):
                detail_request_id = f"batch-{batch_key}-d{detail_index:02d}"
                detail_payload = self._stage_batch_payload(
                    request_id=detail_request_id,
                    content=detail_content,
                    media_type="application/json",
                )
                staged_paths.append(str(detail_payload["relative_path"]))
                result_by_detail.append(
                    {
                        "platform_waybill_id": platform_waybill_id,
                        "source_revision_sha256": source_revision_sha256,
                        "detail": detail_payload,
                        "images": [],
                    }
                )
            for _image_index, (
                detail_index,
                slot,
                image_payload,
                media_type,
                validator_sha256,
                reused_sha256,
            ) in enumerate(image_results):
                images = result_by_detail[detail_index]["images"]
                assert isinstance(images, list)
                if reused_sha256 is not None:
                    images.append(
                        {
                            "slot": slot,
                            "reused": {
                                "sha256": reused_sha256,
                                "media_type": media_type,
                                "validator_sha256": validator_sha256,
                            },
                        }
                    )
                    continue
                assert image_payload is not None
                images.append(
                    {
                        "slot": slot,
                        "payload": image_payload,
                        "validator_sha256": validator_sha256,
                    }
                )
            return result_by_detail
        except Exception:
            self._cleanup_batch_paths(staged_paths)
            raise

    def _private_batch_headers(
        self,
        *,
        url: str,
        image: bool,
    ) -> dict[str, str]:
        session_headers = self._session_headers or self._daily_session_headers
        if session_headers is None or not self._private_batch_session_frozen:
            raise BrowserReadError("browser_read_login_required")
        parsed = urlsplit(url)
        if image:
            allowed_names = {
                "accept",
                "accept-language",
                "referer",
                "user-agent",
            }
            if parsed.hostname == "pc.chengfengkuaiyun.com":
                allowed_names.add("authorization")
            headers = {
                name: value
                for name, value in session_headers.items()
                if name.casefold() in allowed_names
            }
        else:
            headers = {
                name: value
                for name, value in session_headers.items()
                if name.casefold() != "content-type"
            }
            headers["content-type"] = "application/x-www-form-urlencoded;charset=UTF-8"
        cookie_header = None
        if parsed.hostname == "pc.chengfengkuaiyun.com":
            cookie_header = self._private_batch_cookie_header
        if cookie_header:
            headers["cookie"] = cookie_header
        return headers

    def _freeze_private_batch_session(self) -> None:
        """Freeze bounded same-origin cookies for page-independent batch reads."""

        if self._context is None:
            raise BrowserReadError("browser_context_closed")
        cookie_reader = getattr(self._context, "cookies", None)
        if not callable(cookie_reader):
            self._private_batch_cookie_header = None
            self._private_batch_session_frozen = True
            return
        try:
            cookies = cookie_reader([f"{_CHENGFENG_ORIGIN}{CHENGFENG_DETAIL_PATH}"])
        except Exception as exc:
            raise BrowserReadError("browser_read_login_required") from exc
        cookie_parts: list[str] = []
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(value, str)
                or any(marker in name for marker in (";", "\r", "\n", "\x00"))
                or any(marker in value for marker in (";", "\r", "\n", "\x00"))
            ):
                raise BrowserReadError("browser_read_contract_changed")
            cookie_parts.append(f"{name}={value}")
        self._private_batch_cookie_header = "; ".join(cookie_parts) if cookie_parts else None
        self._private_batch_session_frozen = True

    def _install_operational_batch_page(self, page: Any) -> None:
        """Freeze one authenticated page and allow only armed detail reads."""

        self._remove_operational_batch_page()
        self._freeze_private_batch_session()

        def route_handler(route: Any) -> None:
            request = getattr(route, "request", None)
            list_body = self._operational_batch_list_body
            list_cache_query = self._operational_batch_list_cache_query
            daily_body = self._operational_daily_list_body
            daily_authority_body = self._operational_daily_authority_body
            if (
                daily_authority_body is not None
                and not self._operational_daily_authority_seen
                and self._daily_private_body is not None
                and _daily_page_request_can_be_scoped(
                    request,
                    private_baseline=self._daily_private_body,
                )
            ):
                self._operational_daily_authority_seen = True
                route.continue_(
                    post_data=json.dumps(
                        daily_authority_body,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                )
                return
            if (
                daily_body is not None
                and not self._operational_daily_list_seen
                and _daily_page_request_matches(
                    request,
                    expected_body=daily_body,
                )
            ):
                self._operational_daily_list_seen = True
                route.continue_()
                return
            if (
                list_body is not None
                and list_cache_query is not None
                and not self._operational_batch_list_seen
                and _operational_list_request_matches(
                    request,
                    expected_body=list_body,
                    expected_cache_query=list_cache_query,
                )
            ):
                self._operational_batch_list_seen = True
                route.continue_()
                return
            identity = _operational_batch_detail_identity(
                request,
                allowed_identities=self._operational_batch_allowed_ids,
            )
            if identity is not None and identity not in self._operational_batch_seen_ids:
                self._operational_batch_seen_ids.add(identity)
                route.continue_()
                return
            route.abort()

        try:
            page.route("**/*", route_handler)
        except Exception as exc:
            raise BrowserReadError("browser_operational_batch_prepare_required") from exc
        self._operational_batch_page = page
        self._operational_batch_route_handler = route_handler
        self._operational_batch_allowed_ids = set()
        self._operational_batch_seen_ids = set()
        self._operational_batch_list_body = None
        self._operational_batch_list_cache_query = None
        self._operational_batch_list_seen = False
        self._operational_daily_list_body = None
        self._operational_daily_list_seen = False
        self._operational_daily_authority_body = None
        self._operational_daily_authority_seen = False

    def _human_page_or_create(self, *, wait_for_hydrated: bool = False) -> Any:
        """Return the one Chengfeng page without touching unrelated tabs."""

        if self._context is None:
            raise BrowserReadError("browser_context_closed")
        context = self._context

        def is_open(candidate: Any) -> bool:
            try:
                is_closed = getattr(candidate, "is_closed", None)
                return not bool(is_closed()) if callable(is_closed) else True
            except Exception:
                return False

        def is_chengfeng(candidate: Any) -> bool:
            try:
                parsed = urlsplit(str(getattr(candidate, "url", "")))
            except ValueError:
                return False
            return (
                parsed.scheme == "https"
                and parsed.hostname == "pc.chengfengkuaiyun.com"
                and parsed.port in {None, 443}
                and parsed.username is None
                and parsed.password is None
            )

        def page_snapshot() -> tuple[list[Any], list[Any], Any | None]:
            open_pages = [candidate for candidate in tuple(context.pages) if is_open(candidate)]
            chengfeng_pages = [candidate for candidate in open_pages if is_chengfeng(candidate)]
            preferred = self._human_page
            if preferred not in open_pages or (
                preferred not in chengfeng_pages
                and str(getattr(preferred, "url", "")) not in {"", "about:blank"}
            ):
                preferred = None
            return open_pages, chengfeng_pages, preferred

        open_pages, chengfeng_pages, preferred = page_snapshot()
        if wait_for_hydrated and open_pages:
            wait_page = preferred or (chengfeng_pages[0] if chengfeng_pages else open_pages[0])
            for _ in range(CHENGFENG_PAGE_HYDRATION_WAIT_MS // CHENGFENG_PAGE_HYDRATION_POLL_MS):
                pending_blank = any(
                    str(getattr(candidate, "url", "")) in {"", "about:blank"}
                    for candidate in open_pages
                )
                if not pending_blank and any(
                    _page_hydration_score(candidate) > 0 for candidate in chengfeng_pages
                ):
                    break
                with suppress(Exception):
                    wait_page.wait_for_timeout(CHENGFENG_PAGE_HYDRATION_POLL_MS)
                open_pages, chengfeng_pages, preferred = page_snapshot()

        page = None
        highest_score = 0
        for candidate in chengfeng_pages:
            score = _page_hydration_score(candidate)
            if score > highest_score or (score == highest_score and candidate is preferred):
                page = candidate
                highest_score = score
        if page is None:
            page = preferred or (chengfeng_pages[0] if chengfeng_pages else None)
        if page is None:
            page = context.new_page()
        if highest_score > 0 or len(chengfeng_pages) <= 1:
            for candidate in chengfeng_pages:
                if candidate is page:
                    continue
                with suppress(Exception):
                    candidate.close()
        if wait_for_hydrated and highest_score > 0:
            for candidate in open_pages:
                if candidate is page or str(getattr(candidate, "url", "")) not in {
                    "",
                    "about:blank",
                }:
                    continue
                with suppress(Exception):
                    candidate.close()
        self._human_page = page
        return page

    def _refresh_page_without_cache(
        self,
        page: Any,
        *,
        error_code: str,
    ) -> None:
        """Reload one owned tab without HTTP cache while preserving login state."""

        context = self._context
        if context is None:
            raise BrowserReadError("browser_context_closed")
        cdp_session = None
        try:
            cdp_session = context.new_cdp_session(page)
            cdp_session.send("Network.enable")
            cdp_session.send(
                "Network.setCacheDisabled",
                {"cacheDisabled": True},
            )
            cdp_session.send("Network.clearBrowserCache")
            cdp_session.send("Page.reload", {"ignoreCache": True})
            page.wait_for_load_state(
                "domcontentloaded",
                timeout=HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS,
            )
            # Chromium can dispatch DOMContentLoaded while Chengfeng's SPA is
            # still an empty document shell. A cache-disabled refresh is not
            # complete until either the login form or one of the two approved
            # business pages has hydrated. Do not hand an empty shell to the
            # control locators and spend another full locator timeout there.
            for _ in range(
                HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS
                // CHENGFENG_PAGE_HYDRATION_POLL_MS
            ):
                if _page_hydration_score(page) == 2:
                    break
                page.wait_for_timeout(CHENGFENG_PAGE_HYDRATION_POLL_MS)
            else:
                raise BrowserReadError(error_code)
        except BrowserReadError:
            raise
        except Exception as exc:
            raise BrowserReadError(error_code) from exc
        finally:
            if cdp_session is not None:
                with suppress(Exception):
                    cdp_session.send(
                        "Network.setCacheDisabled",
                        {"cacheDisabled": False},
                    )
                with suppress(Exception):
                    cdp_session.detach()

    def _install_single_chengfeng_page_guard(self) -> None:
        """Close only newly opened duplicate Chengfeng tabs during a read."""

        context = self._context
        if context is None:
            raise BrowserReadError("browser_context_closed")
        if self._single_chengfeng_page_handler is not None:
            return

        def inspect(candidate: Any) -> None:
            if candidate is self._human_page:
                return
            try:
                parsed = urlsplit(str(getattr(candidate, "url", "")))
            except ValueError:
                return
            if (
                parsed.scheme == "https"
                and parsed.hostname == "pc.chengfengkuaiyun.com"
                and parsed.port in {None, 443}
                and parsed.username is None
                and parsed.password is None
            ):
                with suppress(Exception):
                    candidate.close()

        def page_handler(candidate: Any) -> None:
            inspect(candidate)
            if str(getattr(candidate, "url", "")) in {"", "about:blank"}:
                on = getattr(candidate, "on", None)
                if callable(on):
                    with suppress(Exception):
                        on("domcontentloaded", lambda: inspect(candidate))

        try:
            context.on("page", page_handler)
        except Exception as exc:
            raise BrowserReadError("browser_single_page_guard_failed") from exc
        self._single_chengfeng_page_handler = page_handler

    def _ensure_visible_human_business_page(
        self,
        entry: str,
        *,
        expected_path: str,
        error_code: str,
    ) -> Any:
        """Reuse one human tab, select the business route, and restore its window."""

        context = self._context
        if context is None:
            raise BrowserReadError("browser_context_closed")
        page = self._human_page_or_create()
        try:
            current = urlsplit(str(getattr(page, "url", "")))
            already_at_entry = (
                current.scheme == "https"
                and current.hostname == "pc.chengfengkuaiyun.com"
                and current.port in {None, 443}
                and current.username is None
                and current.password is None
                and current.path == expected_path
                and not current.query
                and not current.fragment
                and _page_hydration_score(page) > 0
            )
            if not already_at_entry:
                response = page.goto(
                    entry,
                    wait_until="domcontentloaded",
                    timeout=HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS,
                )
                if response is None:
                    raise BrowserReadError(error_code)
                _assert_business_landing(
                    str(getattr(page, "url", "")),
                    response_status=int(getattr(response, "status", 0)),
                    expected_path=expected_path,
                )
            # Older releases could leave multiple platform tabs behind. Keep
            # the explicitly navigated target page and close only same-origin
            # Chengfeng duplicates. A hydrated stale route must never replace
            # the loading target route merely because it rendered first.
            self._human_page = page
            for _ in range(
                HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS
                // CHENGFENG_PAGE_HYDRATION_POLL_MS
            ):
                if _page_hydration_score(page) == 2:
                    break
                page.wait_for_timeout(CHENGFENG_PAGE_HYDRATION_POLL_MS)
            final_url = urlsplit(str(getattr(page, "url", "")))
            if (
                final_url.scheme != "https"
                or final_url.hostname != "pc.chengfengkuaiyun.com"
                or final_url.port not in {None, 443}
                or final_url.username is not None
                or final_url.password is not None
                or (
                    final_url.path != expected_path
                    and final_url.path != "/login"
                    and not final_url.path.startswith("/login/")
                )
                or bool(final_url.query)
                or bool(final_url.fragment)
            ):
                raise BrowserReadError(error_code)
            for candidate in tuple(context.pages):
                if candidate is page:
                    continue
                try:
                    candidate_url = urlsplit(str(getattr(candidate, "url", "")))
                except ValueError:
                    continue
                if (
                    candidate_url.scheme == "https"
                    and candidate_url.hostname == "pc.chengfengkuaiyun.com"
                    and candidate_url.port in {None, 443}
                    and candidate_url.username is None
                    and candidate_url.password is None
                ):
                    with suppress(Exception):
                        candidate.close()
            cdp_session = context.new_cdp_session(page)
            try:
                window = cdp_session.send("Browser.getWindowForTarget")
                if not isinstance(window, Mapping) or type(window.get("windowId")) is not int:
                    raise BrowserReadError(error_code)
                window_id = int(window["windowId"])
                bounds_result = cdp_session.send(
                    "Browser.getWindowBounds",
                    {"windowId": window_id},
                )
                if not isinstance(bounds_result, Mapping) or not isinstance(
                    bounds_result.get("bounds"), Mapping
                ):
                    raise BrowserReadError(error_code)
                state = str(bounds_result["bounds"].get("windowState", ""))
                if state == "minimized":
                    cdp_session.send(
                        "Browser.setWindowBounds",
                        {
                            "windowId": window_id,
                            "bounds": {"windowState": "normal"},
                        },
                    )
                elif state not in {"normal", "maximized", "fullscreen"}:
                    raise BrowserReadError(error_code)
            finally:
                with suppress(Exception):
                    cdp_session.detach()
            page.bring_to_front()
            return page
        except BrowserReadError:
            raise
        except (LoginEntryError, ValueError) as exc:
            raise BrowserReadError(error_code) from exc
        except Exception as exc:
            raise BrowserReadError(error_code) from exc

    def _remove_operational_batch_page(self) -> None:
        page = self._operational_batch_page
        handler = self._operational_batch_route_handler
        if page is not None and handler is not None:
            with suppress(Exception):
                page.unroute("**/*", handler)
        self._operational_batch_page = None
        self._operational_batch_route_handler = None
        self._operational_batch_allowed_ids = set()
        self._operational_batch_seen_ids = set()
        self._operational_batch_list_body = None
        self._operational_batch_list_cache_query = None
        self._operational_batch_list_seen = False
        self._operational_daily_list_body = None
        self._operational_daily_list_seen = False
        self._operational_daily_authority_body = None
        self._operational_daily_authority_seen = False

    def _stage_batch_payload(
        self,
        *,
        request_id: str,
        content: bytes,
        media_type: str,
    ) -> dict[str, object]:
        suffix = (
            ".json" if media_type == "application/json" else _IMAGE_MEDIA_TYPES.get(media_type, "")
        )
        if not suffix:
            raise BrowserReadError("browser_image_contract_changed")
        relative_path = self._stage_read_payload(
            request_id=request_id,
            suffix=suffix,
            content=content,
        )
        return {
            "relative_path": relative_path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "byte_size": len(content),
            "media_type": media_type,
            "status_code": 200,
        }

    def _cleanup_batch_paths(self, relative_paths: list[str]) -> None:
        if self._staging_root is None:
            return
        for relative_path in relative_paths:
            try:
                relative = Path(relative_path)
                target = self._staging_root.joinpath(*relative.parts)
                resolved = target.resolve()
                if self._staging_root not in resolved.parents:
                    continue
                target.unlink(missing_ok=True)
                target.parent.rmdir()
            except OSError:
                continue

    def _prune_detail_image_grants(self) -> None:
        now = self._monotonic()
        expired = tuple(
            image_url
            for image_url, expires_at in self._detail_image_grants.items()
            if expires_at <= now
        )
        for image_url in expired:
            del self._detail_image_grants[image_url]

    def prepare_automated(
        self,
        *,
        scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
    ) -> dict[str, object]:
        if scope not in APPROVED_SETTLEMENT_SCOPES:
            raise BrowserReadError("browser_settlement_scope_invalid")
        if self._context is None or self._capturing:
            raise BrowserReadError("browser_context_closed")
        if self._automated_prepared:
            if (
                self._automated_scope == scope
                and self._session_headers is not None
                and self._session_list_fixed_values is not None
                and self._session_list_cache_query is not None
                and self._session_list_body is not None
                and self._session_list_body_sha256 is not None
                and self._session_native_probe is not None
            ):
                return {
                    **self._session_native_probe,
                    "metrics": dict(self._session_native_probe["metrics"]),
                }
            raise BrowserReadError("browser_settlement_scope_change_rejected")
        human_pages = tuple(self._context.pages)
        self._release_human_freeze_for_automation()
        safe_probe = self._wait_for_session_headers(
            human_pages,
            scope=scope,
        )
        try:
            blank = self._context.new_page()
            blank.route("**/*", lambda route: route.abort())
            blank.goto("about:blank")
            for page in human_pages:
                page.close()
        except Exception as exc:
            raise BrowserReadError("browser_prepare_automated_failed") from exc
        self._automated_prepared = True
        self._automated_scope = scope
        self._operational_compat_prepared = False
        self._operational_first_list_content = None
        self._operational_first_page_number = None
        self._operational_first_page_size = None
        self._operational_query_trace = None
        return safe_probe

    def prepare_operational_compat(
        self,
        *,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> dict[str, object]:
        """Use the exact completed UI query as the current business authority."""

        if self._context is None or self._capturing:
            raise BrowserReadError("browser_context_closed")
        if self._automated_prepared:
            if (
                self._operational_compat_prepared
                and self._automated_scope == CURRENT_PENDING_SETTLEMENT_SCOPE
                and self._session_headers is not None
                and self._session_list_cache_query is not None
                and self._session_list_body is not None
                and self._session_list_body_sha256 is not None
                and self._session_native_probe is not None
                and self._operational_first_list_content is not None
                and self._operational_query_trace is not None
                and self._active_contract_subject_code == contract_subject_code
            ):
                return {
                    **self._session_native_probe,
                    "metrics": dict(self._session_native_probe["metrics"]),
                    "query_trace": dict(self._operational_query_trace),
                    "contract_subject_code": contract_subject_code,
                    "contract_subject_confirmed": True,
                }
            raise BrowserReadError("browser_connection_mode_change_rejected")
        self._release_human_freeze_for_automation()
        human_page = self._ensure_visible_human_business_page(
            CHENGFENG_HUMAN_LOGIN_ENTRY,
            expected_path="/billablewaybill",
            error_code="browser_session_settlement_route_unavailable",
        )
        try:
            if _wait_for_entry_login_state(human_page):
                _login_with_saved_credential(
                    human_page,
                    contract_subject_code=contract_subject_code,
                )
                human_page = self._ensure_visible_human_business_page(
                    CHENGFENG_HUMAN_LOGIN_ENTRY,
                    expected_path="/billablewaybill",
                    error_code="browser_session_settlement_route_unavailable",
                )
        except BrowserReadError:
            raise
        except Exception as exc:
            raise BrowserReadError("browser_session_settlement_route_unavailable") from exc
        subject_evidence = _ensure_contract_subject(
            human_page,
            contract_subject_code=contract_subject_code,
            login_page=False,
        )
        if subject_evidence["contract_subject_switch_performed"] is True:
            _stabilize_contract_subject_business_page(
                human_page,
                contract_subject_code=contract_subject_code,
                entry=CHENGFENG_HUMAN_LOGIN_ENTRY,
                daily=False,
            )
            self._wait_for_operational_ui_idle(human_page)
        self._active_contract_subject_code = contract_subject_code
        self._install_single_chengfeng_page_guard()
        page = human_page
        try:
            self._refresh_page_without_cache(
                page,
                error_code="browser_operational_cache_refresh_failed",
            )
        except BrowserReadError:
            with suppress(Exception):
                page.bring_to_front()
            raise
        pages = tuple(
            candidate for candidate in self._context.pages if not bool(candidate.is_closed())
        )
        current_url = str(getattr(page, "url", ""))
        try:
            parsed = urlsplit(current_url)
        except ValueError as exc:
            raise BrowserReadError("browser_session_settlement_route_unavailable") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname != "pc.chengfengkuaiyun.com"
            or parsed.port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/billablewaybill"
            or parsed.query
            or parsed.fragment
        ):
            raise BrowserReadError("browser_session_settlement_route_unavailable")
        if _page_requires_login(page):
            raise BrowserReadError("browser_read_login_required")

        def validate_operational_entry() -> None:
            # The fixed /billablewaybill route is the current-settlement
            # workspace. Its left navigation can be collapsed or outside the
            # viewport, so operational reads validate the page-owned query
            # controls instead of requiring those navigation labels to be
            # visible. The captured request body remains the scope authority.
            if _page_requires_login(page):
                raise BrowserReadError("browser_read_login_required")
            if _page_hydration_score(page) == 0:
                raise BrowserReadError(
                    "browser_session_waybill_control_unavailable"
                )
            self._wait_for_settlement_controls(
                page,
                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                require_scope_controls=False,
            )

        route_handler = None
        route_installed = False
        query_armed = False
        query_continued = False
        observed_request_count = 0
        approved_request_count = 0
        blocked_request_count = 0
        query_started = self._monotonic()
        query_attempt_id = uuid4().hex
        entry_recovery_refresh_count = 0
        self._session_headers = None
        self._private_batch_cookie_header = None
        self._private_batch_session_frozen = False
        self._session_list_fixed_values = None
        self._session_list_cache_query = None
        self._session_list_body = None
        self._session_list_body_sha256 = None
        self._session_native_probe = None
        self._operational_first_list_content = None
        self._operational_first_page_number = None
        self._operational_first_page_size = None
        self._operational_query_trace = None

        def clear_authoritative_query() -> None:
            self._session_headers = None
            self._session_list_fixed_values = None
            self._session_list_cache_query = None
            self._session_list_body = None
            self._session_list_body_sha256 = None
            self._session_native_probe = None

        def operational_route(route: Any) -> None:
            nonlocal approved_request_count
            nonlocal blocked_request_count
            nonlocal observed_request_count
            nonlocal query_continued
            request = getattr(route, "request", None)
            approved = _is_session_header_request(
                request,
                expected_path=CHENGFENG_LIST_PATH,
            )
            if not query_armed:
                if (
                    approved
                    and _private_list_cache_query_from_request(
                        request,
                        expected_path=CHENGFENG_LIST_PATH,
                    )
                    is not None
                    and _private_list_body_from_request(
                        request,
                        scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                    )
                    is not None
                ):
                    # The official page uses list reads to finish selecting the
                    # current-settlement scope. These reads are allowed to
                    # complete but never become authority and none of their
                    # private values are retained.
                    route.continue_()
                    return
                route.abort()
                return
            observed_request_count += 1
            if not approved or query_continued:
                blocked_request_count += 1
                route.abort()
                return
            headers = _session_headers_from_request(
                request,
                expected_path=CHENGFENG_LIST_PATH,
            )
            cache_query = _private_list_cache_query_from_request(
                request,
                expected_path=CHENGFENG_LIST_PATH,
            )
            body = _private_list_body_from_request(
                request,
                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
            )
            body_sha256 = _private_list_body_sha256_from_request(
                request,
                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
            )
            if headers is None or cache_query is None or body is None or body_sha256 is None:
                blocked_request_count += 1
                route.abort()
                return
            self._session_headers = dict(headers)
            self._session_list_fixed_values = _private_list_fixed_values_from_request(request)
            self._session_list_cache_query = cache_query
            self._session_list_body = dict(body)
            self._session_list_body_sha256 = body_sha256
            query_continued = True
            approved_request_count += 1
            route.continue_()

        def install_operational_route() -> None:
            nonlocal route_installed
            if route_installed:
                return
            page.route("**/*", operational_route)
            route_installed = True

        def remove_operational_route() -> None:
            nonlocal route_installed
            if not route_installed:
                return
            page.unroute("**/*", operational_route)
            route_installed = False

        def execute_authoritative_query() -> tuple[dict[str, object], bytes, Any]:
            nonlocal query_armed, query_continued
            query_armed = False
            query_continued = False
            clear_authoritative_query()
            # Reproduce the complete page-owned business scope before the
            # authoritative query. Each click may redraw the SPA, so reacquire
            # every locator after the corresponding idle boundary.
            self._wait_for_operational_ui_idle(page)
            _, _, waybill_tab, _, _ = self._wait_for_settlement_controls(
                page,
                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                require_scope_controls=False,
            )
            waybill_tab.click(timeout=10_000)
            page.wait_for_timeout(300)
            self._wait_for_operational_ui_idle(page)
            _, _, _, reset_button, _ = self._wait_for_settlement_controls(
                page,
                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                require_scope_controls=False,
            )
            reset_button.click(timeout=10_000)
            page.wait_for_timeout(300)
            self._wait_for_operational_ui_idle(page)
            _, _, waybill_tab, _, _ = self._wait_for_settlement_controls(
                page,
                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                require_scope_controls=False,
            )
            waybill_tab.click(timeout=10_000)
            page.wait_for_timeout(300)
            self._wait_for_operational_ui_idle(page)
            _, _, _, _, query_button = self._wait_for_settlement_controls(
                page,
                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                require_scope_controls=False,
            )
            query_armed = True
            try:
                with page.expect_response(
                    lambda candidate: _is_session_header_request(
                        getattr(candidate, "request", None),
                        expected_path=CHENGFENG_LIST_PATH,
                    ),
                    timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                ) as response_info:
                    query_button.click(timeout=10_000)
                response = response_info.value
            finally:
                query_armed = False
            body = self._session_list_body
            if body is None:
                raise BrowserReadError("browser_operational_query_contract_changed")
            probe, content = _native_list_response(
                response,
                request_body=body,
            )
            return probe, content, response

        try:
            # A freshly rebuilt business context may only have committed its
            # main document. Let the fixed entry finish rendering before the
            # narrow query route is installed; otherwise the route can block
            # the page's remaining bootstrap reads and the controls never
            # become available. A returned login page is already frozen, so
            # this check is also safe and immediate in the normal first-read
            # path.
            try:
                validate_operational_entry()
            except BrowserReadError as exc:
                if exc.code not in {
                    "browser_session_waybill_control_unavailable",
                    "browser_session_query_control_unavailable",
                }:
                    raise
                # A prior operational batch can leave Chengfeng's SPA shell
                # committed while its controls are still absent. Recover once
                # through the same cache-disabled reload contract, before any
                # query route or private authority is installed.
                self._refresh_page_without_cache(
                    page,
                    error_code="browser_operational_cache_refresh_failed",
                )
                entry_recovery_refresh_count = 1
                try:
                    validate_operational_entry()
                except BrowserReadError as recovery_exc:
                    if recovery_exc.code not in {
                        "browser_session_waybill_control_unavailable",
                        "browser_session_query_control_unavailable",
                    }:
                        raise
                    _stabilize_contract_subject_business_page(
                        page,
                        contract_subject_code=contract_subject_code,
                        entry=CHENGFENG_HUMAN_LOGIN_ENTRY,
                        daily=False,
                    )
                    validate_operational_entry()
            route_handler = operational_route
            install_operational_route()
            cache_refresh_count = 1 + entry_recovery_refresh_count
            query_attempt_count = 1
            probe, content, response = execute_authoritative_query()
            metrics = probe["metrics"]
            assert isinstance(metrics, Mapping)
            zero_retry_performed = int(metrics["total_count"]) == 0
            if zero_retry_performed:
                # Match the proven operational behavior: a first zero is not
                # accepted until the visible filters and waybill view have
                # been reset once more. The second zero remains a valid empty
                # business result.
                del content
                with suppress(Exception):
                    response.dispose()
                remove_operational_route()
                self._refresh_page_without_cache(
                    page,
                    error_code="browser_operational_cache_refresh_failed",
                )
                cache_refresh_count += 1
                install_operational_route()
                validate_operational_entry()
                query_attempt_count += 1
                probe, content, response = execute_authoritative_query()
                metrics = probe["metrics"]
                assert isinstance(metrics, Mapping)
            final_subject_evidence = _ensure_contract_subject(
                page,
                contract_subject_code=contract_subject_code,
                login_page=False,
            )
            if final_subject_evidence["contract_subject_switch_performed"] is True:
                raise BrowserReadError(
                    "browser_contract_subject_confirmation_failed"
                )
            response_request = getattr(response, "request", None)
            resource_type = str(getattr(response_request, "resource_type", "")).casefold()
            duration_ms = int(
                min(
                    120_000,
                    max(0.0, (self._monotonic() - query_started) * 1000),
                )
            )
            self._session_native_probe = probe
            self._operational_first_list_content = content
            self._operational_first_page_number = int(metrics["page_number"])
            self._operational_first_page_size = int(metrics["page_size"])
            self._operational_query_trace = {
                "schema_version": 1,
                "query_attempt_id": query_attempt_id,
                "observed_request_count": observed_request_count,
                "approved_request_count": approved_request_count,
                "blocked_request_count": blocked_request_count,
                "query_attempt_count": query_attempt_count,
                "zero_retry_performed": zero_retry_performed,
                "cache_refresh_count": cache_refresh_count,
                "page_count": len(pages),
                "request_method": "POST",
                "request_path": CHENGFENG_LIST_PATH,
                "resource_type": resource_type,
                "response_status": int(response.status),
                "response_byte_size": len(content),
                "response_structure_sha256": probe["response_structure_sha256"],
                "duration_ms": duration_ms,
            }
        except BrowserReadError:
            with suppress(Exception):
                page.bring_to_front()
            raise
        except Exception as exc:
            with suppress(Exception):
                page.bring_to_front()
            raise BrowserReadError("browser_operational_query_failed") from exc
        finally:
            if route_handler is not None and route_installed:
                with suppress(Exception):
                    remove_operational_route()
        if (
            not query_continued
            or self._session_headers is None
            or self._session_list_cache_query is None
            or self._session_list_body is None
            or self._session_list_body_sha256 is None
            or self._session_native_probe is None
            or self._operational_first_list_content is None
            or self._operational_query_trace is None
        ):
            raise BrowserReadError("browser_operational_query_not_completed")
        try:
            self._install_operational_batch_page(page)
            # The page is still retained for bounded list pagination, but
            # frozen detail and image reads no longer need Playwright routing.
            # Using the worker-private HTTP path preserves the same headers,
            # cookies, allowlist and audit envelope without serializing every
            # request through the synchronous page route handler.
            self._prefer_private_http_batch_reads = True
            human_page.bring_to_front()
        except Exception as exc:
            with suppress(Exception):
                page.bring_to_front()
            raise BrowserReadError("browser_prepare_automated_failed") from exc
        self._automated_prepared = True
        self._automated_scope = CURRENT_PENDING_SETTLEMENT_SCOPE
        self._operational_compat_prepared = True
        return {
            **self._session_native_probe,
            "metrics": dict(self._session_native_probe["metrics"]),
            "query_trace": dict(self._operational_query_trace),
            "contract_subject_code": contract_subject_code,
            "contract_subject_confirmed": True,
        }

    def prepare_settlement_filter_handoff(
        self,
        waybill_numbers: tuple[str, ...],
        *,
        contract_subject_code: str,
    ) -> dict[str, object]:
        """Populate the official waybill filter and leave the page to the user."""

        if self._context is None or self._capturing or self._automated_prepared:
            raise BrowserReadError("browser_context_closed")
        if (
            not waybill_numbers
            or len(waybill_numbers) > 2000
            or len(set(waybill_numbers)) != len(waybill_numbers)
            or any(re.fullmatch(r"[A-Za-z0-9_-]{1,40}", value) is None for value in waybill_numbers)
        ):
            raise BrowserReadError("browser_settlement_filter_values_invalid")
        page = self._human_page_or_create()
        try:
            current = urlsplit(str(getattr(page, "url", "")))
        except ValueError:
            current = None
        if (
            current is None
            or current.scheme != "https"
            or current.hostname != "pc.chengfengkuaiyun.com"
            or current.path != "/billablewaybill"
            or current.query
            or current.fragment
        ):
            _open_human_login_entry(page)
        if _page_requires_login(page):
            raise BrowserReadError("browser_read_login_required")
        _ensure_contract_subject(
            page,
            contract_subject_code=contract_subject_code,
            login_page=False,
        )
        try:
            _, _, waybill_tab, _, _ = self._wait_for_settlement_controls(
                page,
                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                require_scope_controls=False,
            )
            waybill_tab.click(timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS)
            self._wait_for_operational_ui_idle(page)
            batch_search = page.get_by_text("批量搜", exact=True).filter(visible=True).first
            batch_search.wait_for(
                state="visible",
                timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
            )
            batch_search.click(timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS)
            dialog = page.locator(".el-dialog:visible, [role='dialog']:visible").last
            dialog.wait_for(
                state="visible",
                timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
            )
            textarea = dialog.locator("textarea:visible").first
            textarea.fill("\n".join(waybill_numbers))
            confirm = (
                dialog.get_by_role("button", name="确定", exact=True).filter(visible=True).first
            )
            response = None
            try:
                with page.expect_response(
                    lambda candidate: _is_session_header_request(
                        getattr(candidate, "request", None),
                        expected_path=CHENGFENG_LIST_PATH,
                    ),
                    timeout=5_000,
                ) as response_info:
                    confirm.click(timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS)
                response = response_info.value
            except Exception as exc:
                # The current platform sometimes only closes the dialog and
                # writes the filter values. That is safe to continue once by
                # clicking the page's official read-only query button.
                if dialog.is_visible():
                    raise BrowserReadError("browser_settlement_filter_dialog_failed") from exc
            dialog.wait_for(
                state="hidden",
                timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
            )
            if response is None:
                _, _, _, _, query_button = self._wait_for_settlement_controls(
                    page,
                    scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                    require_scope_controls=False,
                )
                with page.expect_response(
                    lambda candidate: _is_session_header_request(
                        getattr(candidate, "request", None),
                        expected_path=CHENGFENG_LIST_PATH,
                    ),
                    timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                ) as response_info:
                    query_button.click(timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS)
                response = response_info.value
            self._wait_for_operational_ui_idle(page)
            try:
                request_body = response.request.post_data_json
            except Exception as exc:
                raise BrowserReadError("browser_settlement_filter_result_changed") from exc
            if not isinstance(request_body, Mapping):
                raise BrowserReadError("browser_settlement_filter_result_changed")
            try:
                content = response.body()
                parsed = json.loads(content.decode("utf-8", errors="strict"))
            except Exception as exc:
                raise BrowserReadError("browser_settlement_filter_result_changed") from exc
            result = _safe_settlement_filter_result(
                parsed,
                request_body=request_body,
                requested_waybills=waybill_numbers,
            )
            page.bring_to_front()
            return result
        except BrowserReadError:
            raise
        except Exception as exc:
            if _page_requires_login(page):
                raise BrowserReadError("browser_read_login_required") from exc
            raise BrowserReadError("browser_settlement_filter_handoff_failed") from exc

    def prepare_daily_from_automated(self) -> dict[str, object]:
        """Switch to the fixed daily page and retain only private read authority."""

        return self._prepare_operational_daily(
            require_automated_transition=True,
            contract_subject_code=(self._active_contract_subject_code or "shanxi_guienbo"),
        )

    def prepare_operational_daily(
        self,
        *,
        contract_subject_code: str = "shanxi_guienbo",
    ) -> dict[str, object]:
        """Prepare the fixed daily page directly from the visible session."""

        return self._prepare_operational_daily(
            require_automated_transition=False,
            contract_subject_code=contract_subject_code,
        )

    def _prepare_operational_daily(
        self,
        *,
        require_automated_transition: bool,
        contract_subject_code: str,
    ) -> dict[str, object]:
        """Build one fresh page-owned daily read authority."""

        previous_controlled_page = self._operational_batch_page
        if (
            self._context is None
            or self._capturing
            or (
                require_automated_transition
                and (
                    not self._automated_prepared
                    or not self._session_headers
                    or previous_controlled_page is None
                    or bool(previous_controlled_page.is_closed())
                )
            )
        ):
            raise BrowserReadError(
                "browser_daily_automated_transition_required"
                if require_automated_transition
                else "browser_read_login_required"
            )
        self._remove_operational_batch_page()
        human_page = self._ensure_visible_human_business_page(
            CHENGFENG_DAILY_ENTRY,
            expected_path="/wayBill",
            error_code="browser_daily_route_unavailable",
        )
        if _wait_for_entry_login_state(human_page, daily=True):
            _login_with_saved_credential(
                human_page,
                contract_subject_code=contract_subject_code,
            )
            human_page = self._ensure_visible_human_business_page(
                CHENGFENG_DAILY_ENTRY,
                expected_path="/wayBill",
                error_code="browser_daily_route_unavailable",
            )
        subject_evidence = _ensure_contract_subject(
            human_page,
            contract_subject_code=contract_subject_code,
            login_page=False,
        )
        # The authoritative cache-disabled reload below is the daily page
        # stabilization boundary. Running the generic shell recovery here as
        # well duplicated one navigation and could exceed the worker budget
        # when switching subjects. The fresh daily list response and the final
        # subject check remain the publication gate.
        del subject_evidence
        self._active_contract_subject_code = contract_subject_code
        self._install_single_chengfeng_page_guard()
        self._automated_prepared = False
        self._automated_scope = None
        self._operational_compat_prepared = False
        self._operational_first_list_content = None
        self._operational_first_page_number = None
        self._operational_first_page_size = None
        self._operational_query_trace = None
        self._session_headers = None
        self._session_list_fixed_values = None
        self._session_list_cache_query = None
        self._session_list_body = None
        self._session_list_body_sha256 = None
        self._session_native_probe = None
        self._daily_session_headers = None
        self._daily_body = None
        self._daily_private_body = None
        self._daily_response_fields = None
        self._daily_probe_body = None
        self._daily_probe_content = None
        self._daily_probe_read_pending = False
        self._daily_authority_scope_sha256 = None
        self._daily_platform_display_total = None
        self._daily_cache_refresh_count = 0
        route_handler = None
        captured_headers: dict[str, str] | None = None
        captured_private_body: dict[str, object] | None = None
        page = human_page
        try:

            def daily_navigation_route(route: Any) -> None:
                nonlocal captured_headers, captured_private_body
                request = getattr(route, "request", None)
                method = str(getattr(request, "method", "")).upper()
                if method in {"GET", "HEAD"}:
                    route.continue_()
                    return
                if _is_daily_native_request(request):
                    headers = _daily_session_headers_from_request(request)
                    private_body = _private_daily_body_from_request(request)
                    if headers is not None and private_body is not None:
                        captured_headers = dict(headers)
                        captured_private_body = dict(private_body)
                        route.continue_()
                        return
                if _approved_discovery_request(request) or _approved_daily_bootstrap_request(
                    request
                ):
                    route.continue_()
                    return
                route.abort()

            route_handler = daily_navigation_route
            page.route("**/*", route_handler)
            self._refresh_page_without_cache(
                page,
                error_code="browser_daily_cache_refresh_failed",
            )
            self._daily_cache_refresh_count = 1
            # Preserve the successful page-owned query scope.  Chengfeng keeps
            # account and page-version filters outside the five business fields;
            # clicking Reset can replace that private scope with a narrower
            # default.  Only the controlled date, location and pagination values
            # are substituted after capture.
            captured_headers = None
            captured_private_body = None
            _, _, query_button = self._wait_for_daily_controls(page)
            with page.expect_response(
                lambda candidate: _is_daily_native_request(getattr(candidate, "request", None)),
                timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
            ) as response_info:
                query_button.click(timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS)
            native_response = response_info.value
            self._wait_for_operational_ui_idle(page)
            native_request = getattr(native_response, "request", None)
            captured_headers = _daily_session_headers_from_request(native_request)
            captured_private_body = _private_daily_body_from_request(native_request)
            if captured_headers is None or captured_private_body is None:
                if _page_requires_login(page):
                    raise BrowserReadError("browser_read_login_required")
                raise BrowserReadError("browser_daily_page_request_not_constructed")
            try:
                native_payload = json.loads(native_response.body().decode("utf-8", errors="strict"))
                native_total = native_payload.get("data", {}).get("total")
            except Exception as exc:
                raise BrowserReadError("browser_daily_response_contract_changed") from exc
            if type(native_total) is not int or native_total < 0:
                raise BrowserReadError("browser_daily_response_contract_changed")
            visible_total = _daily_platform_display_total(page)
            current_url = urlsplit(str(getattr(page, "url", "")))
            if (
                current_url.scheme != "https"
                or current_url.hostname != "pc.chengfengkuaiyun.com"
                or current_url.port not in {None, 443}
                or current_url.path != "/wayBill"
                or current_url.query
                or current_url.fragment
            ):
                raise BrowserReadError("browser_daily_route_unavailable")
            final_subject_evidence = _ensure_contract_subject(
                page,
                contract_subject_code=contract_subject_code,
                login_page=False,
            )
            if final_subject_evidence["contract_subject_switch_performed"] is True:
                raise BrowserReadError(
                    "browser_contract_subject_confirmation_failed"
                )
            page.unroute("**/*", route_handler)
            route_handler = None
            self._daily_session_headers = captured_headers
            self._daily_private_body = captured_private_body
            self._daily_body = _frozen_daily_private_body()
            self._daily_authority_scope_sha256 = _daily_scope_sha256(captured_private_body)
            self._daily_platform_display_total = visible_total
            if visible_total is not None and visible_total != native_total:
                raise BrowserReadError("browser_daily_scope_total_mismatch")
            self._install_operational_batch_page(page)
            probe_body = _daily_discovery_body(datetime.now())
            probe_content, response_fields = self._read_daily_list_in_page(
                body=probe_body,
                # A completed business window may legitimately contain no
                # waybills for one contract subject. The page-authoritative
                # reader performs the required cache-disabled second query
                # before accepting that zero.
                require_nonempty=False,
            )
            observation = {
                "method": "POST",
                "origin": _CHENGFENG_ORIGIN,
                "path": CHENGFENG_DAILY_LIST_PATH,
                "path_sha256": None,
                "query_keys": ["t"],
                "request_fields": _json_fields(probe_body),
                "resource_kind": "json_api",
                "response_status": 200,
                "content_kind": "json",
                "response_fields": response_fields,
            }
            self._daily_response_fields = [dict(field) for field in observation["response_fields"]]
            self._daily_probe_body = dict(probe_body)
            self._daily_probe_content = probe_content
            self._daily_probe_read_pending = True
            self._prefer_private_http_batch_reads = True
            human_page.bring_to_front()
            return {
                **observation,
                "query_keys": list(observation["query_keys"]),
                "request_fields": [dict(field) for field in observation["request_fields"]],
                "response_fields": [dict(field) for field in observation["response_fields"]],
            }
        except BrowserReadError:
            if route_handler is not None:
                with suppress(Exception):
                    page.unroute("**/*", route_handler)
            self._remove_operational_batch_page()
            self._daily_session_headers = None
            self._daily_body = None
            self._daily_private_body = None
            self._daily_response_fields = None
            self._daily_probe_body = None
            self._daily_probe_content = None
            self._daily_probe_read_pending = False
            self._daily_authority_scope_sha256 = None
            self._daily_platform_display_total = None
            self._daily_cache_refresh_count = 0
            with suppress(Exception):
                page.bring_to_front()
            raise
        except Exception as exc:
            if route_handler is not None:
                with suppress(Exception):
                    page.unroute("**/*", route_handler)
            self._remove_operational_batch_page()
            self._daily_session_headers = None
            self._daily_body = None
            self._daily_private_body = None
            self._daily_response_fields = None
            self._daily_probe_body = None
            self._daily_probe_content = None
            self._daily_probe_read_pending = False
            self._daily_authority_scope_sha256 = None
            self._daily_platform_display_total = None
            self._daily_cache_refresh_count = 0
            with suppress(Exception):
                page.bring_to_front()
            raise BrowserReadError(
                "browser_daily_automated_transition_failed"
                if require_automated_transition
                else "browser_daily_direct_prepare_failed"
            ) from exc

    def daily_preparation_evidence(
        self,
        *,
        include_contract_subject: bool = True,
    ) -> dict[str, object]:
        """Return value-free proof for the visible daily preparation."""

        page = self._operational_batch_page
        context = self._context
        if (
            page is None
            or context is None
            or self._daily_cache_refresh_count < 1
            or self._daily_response_fields is None
        ):
            raise BrowserReadError("browser_daily_prepare_required")
        pages = tuple(
            candidate
            for candidate in context.pages
            if not (callable(getattr(candidate, "is_closed", None)) and bool(candidate.is_closed()))
        )
        current_url = urlsplit(str(getattr(page, "url", "")))
        if (
            len(pages) != 1
            or pages[0] is not page
            or current_url.scheme != "https"
            or current_url.hostname != "pc.chengfengkuaiyun.com"
            or current_url.port not in {None, 443}
            or current_url.path != "/wayBill"
            or current_url.query
            or current_url.fragment
        ):
            raise BrowserReadError("browser_platform_tab_not_single")
        evidence: dict[str, object] = {
            "schema_version": 1,
            "evidence_kind": "chengfeng_daily_freshness",
            "cache_disabled_during_reload": True,
            "ignore_cache_reload": True,
            "cache_refresh_count": self._daily_cache_refresh_count,
            "fresh_query_response_observed": True,
            "page_count": 1,
            "route": "/wayBill",
        }
        if include_contract_subject:
            if self._active_contract_subject_code not in CONTRACT_SUBJECT_OPTION_TEXT:
                raise BrowserReadError("browser_contract_subject_confirmation_failed")
            evidence["contract_subject_code"] = self._active_contract_subject_code
            evidence["contract_subject_confirmed"] = True
        return evidence

    def prepare_daily(self) -> dict[str, object]:
        if self._context is None or self._capturing:
            raise BrowserReadError("browser_read_login_required")
        human_pages = tuple(self._context.pages)
        batch_page = None
        self._daily_session_headers = None
        self._daily_body = None
        self._daily_private_body = None
        self._daily_response_fields = None
        self._daily_probe_body = None
        self._daily_probe_content = None
        self._daily_probe_read_pending = False
        self._daily_authority_scope_sha256 = None
        self._daily_platform_display_total = None
        self._daily_cache_refresh_count = 0
        self._automated_prepared = False
        self._automated_scope = None
        self._operational_compat_prepared = False
        self._operational_first_list_content = None
        self._operational_first_page_number = None
        self._operational_first_page_size = None
        self._operational_query_trace = None
        try:
            self._wait_for_session_headers(human_pages)
            captured_headers = self._session_headers
            if not captured_headers:
                raise BrowserReadError("browser_read_login_required")
            probe_body = _daily_discovery_body(datetime.now())
            observation, probe_content = _fetch_daily_discovery_observation(
                self._context.request,
                headers=captured_headers,
                body=probe_body,
            )
            captured_body = {
                "loadEndTime": "",
                "loadStartTime": "",
                "pageNumber": 1,
                "pageSize": 1,
                "receivePlace": "",
            }
            self._session_headers = None
            self._session_list_fixed_values = None
            self._session_list_cache_query = None
            self._session_list_body = None
            self._session_list_body_sha256 = None
            self._session_native_probe = None
            if not human_pages:
                raise BrowserReadError("browser_read_login_required")
            batch_page = human_pages[0]
            self._install_operational_batch_page(batch_page)
            for human_page in human_pages[1:]:
                human_page.close()
            self._daily_session_headers = captured_headers
            self._daily_body = captured_body
            self._daily_response_fields = [dict(field) for field in observation["response_fields"]]
            self._daily_probe_body = dict(probe_body)
            self._daily_probe_content = probe_content
            self._daily_probe_read_pending = True
            self._prefer_private_http_batch_reads = True
            return {
                **observation,
                "query_keys": list(observation["query_keys"]),
                "request_fields": [dict(field) for field in observation["request_fields"]],
                "response_fields": [dict(field) for field in observation["response_fields"]],
            }
        except BrowserReadError:
            self._daily_session_headers = None
            self._daily_body = None
            self._daily_private_body = None
            self._daily_response_fields = None
            self._daily_probe_body = None
            self._daily_probe_content = None
            self._daily_probe_read_pending = False
            if batch_page is not None:
                self._remove_operational_batch_page()
                for human_page in human_pages:
                    with suppress(Exception):
                        human_page.close()
            raise
        except Exception as exc:
            self._daily_session_headers = None
            self._daily_body = None
            self._daily_private_body = None
            self._daily_response_fields = None
            self._daily_probe_body = None
            self._daily_probe_content = None
            self._daily_probe_read_pending = False
            if batch_page is not None:
                self._remove_operational_batch_page()
                for human_page in human_pages:
                    with suppress(Exception):
                        human_page.close()
            raise BrowserReadError("browser_daily_prepare_failed") from exc

    def _install_session_request_handler(self) -> None:
        context = self._context
        if context is None:
            raise RuntimeError("browser context is unavailable")

        def session_request_handler(request: Any) -> None:
            if _is_session_header_request(request):
                self._session_request_seen = True
            headers = _session_headers_from_request(request)
            fixed_values = _private_list_fixed_values_from_request(request)
            cache_query = _private_list_cache_query_from_request(request)
            list_body = _private_list_body_from_request(request)
            body_sha256 = _private_list_body_sha256_from_request(request)
            if headers is not None:
                self._session_headers = headers
            elif self._session_request_seen:
                self._session_headers_rejected = True
            if fixed_values is not None:
                self._session_list_fixed_values = fixed_values
            elif self._session_request_seen:
                self._session_fixed_values_rejected = True
            if cache_query is not None:
                self._session_list_cache_query = cache_query
            elif self._session_request_seen:
                self._session_cache_query_rejected = True
            if body_sha256 is not None:
                self._session_list_body = list_body
                self._session_list_body_sha256 = body_sha256
            elif self._session_request_seen:
                self._session_list_body_rejected = True

        context.on("request", session_request_handler)
        self._session_request_handler = session_request_handler

    def _wait_for_settlement_controls(
        self,
        page: Any,
        *,
        scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
        require_scope_controls: bool = True,
    ) -> tuple[Any, Any, Any, Any, Any]:
        if scope == CURRENT_PENDING_SETTLEMENT_SCOPE:
            scope_control_name = "可结算"
        elif scope == HISTORICAL_SETTLED_SCOPE:
            scope_control_name = None
        else:
            raise BrowserReadError("browser_settlement_scope_invalid")
        settle_ready = None
        settlement_tab = None
        if scope_control_name is not None and require_scope_controls:
            try:
                settle_ready = (
                    page.get_by_text(scope_control_name, exact=True).filter(visible=True).first
                )
                settle_ready.wait_for(
                    state="visible",
                    timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                )
                settlement_tab = page.get_by_text("结算", exact=True).filter(visible=True).first
                settlement_tab.wait_for(
                    state="visible",
                    timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                )
            except Exception as exc:
                if _page_requires_login(page):
                    raise BrowserReadError("browser_read_login_required") from exc
                raise BrowserReadError(
                    "browser_session_settlement_scope_control_unavailable"
                ) from exc
        try:
            role_waybill_tab = page.get_by_role("tab", name="按运单显示", exact=True).filter(
                visible=True
            )
            # Chengfeng's Element UI tab is not consistent about exposing a
            # tab role while the SPA hydrates. Wait once for either exact
            # representation so fallback locators cannot each consume the
            # full browser-control lease.
            combine_locator = getattr(role_waybill_tab, "or_", None)
            if callable(combine_locator):
                text_waybill_tab = page.get_by_text("按运单显示", exact=True).filter(visible=True)
                waybill_tab = combine_locator(text_waybill_tab).first
                waybill_tab.wait_for(
                    state="visible",
                    timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                )
            else:
                # Lightweight protocol test doubles predate Locator.or_. Keep
                # their compatibility path equivalent to the former exact
                # role/text fallback; real Playwright locators always use the
                # single shared timeout above.
                try:
                    waybill_tab = role_waybill_tab.first
                    waybill_tab.wait_for(
                        state="visible",
                        timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                    )
                except Exception:
                    waybill_tab = (
                        page.get_by_text("按运单显示", exact=True).filter(visible=True).first
                    )
                    waybill_tab.wait_for(
                        state="visible",
                        timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                    )
        except Exception:
            try:
                tab_candidates = page.locator("[role='tab']:visible, .el-tabs__item:visible")
                waybill_tab = None
                for index in range(min(tab_candidates.count(), 12)):
                    candidate = tab_candidates.nth(index)
                    if not candidate.is_visible():
                        continue
                    label = candidate.text_content()
                    if isinstance(label, str) and "".join(label.split()) == "按运单显示":
                        waybill_tab = candidate
                        break
                if waybill_tab is None:
                    raise RuntimeError("settlement waybill tab structure is unavailable")
            except Exception as structural_exc:
                raise BrowserReadError(
                    "browser_session_waybill_control_unavailable"
                ) from structural_exc
        try:
            query_regions = page.locator("[role='search']:visible, form:visible, .el-form:visible")
            matched_controls: tuple[Any, Any] | None = None
            for index in range(min(query_regions.count(), 8)):
                query_region = query_regions.nth(index)
                if not query_region.is_visible():
                    continue
                try:
                    region_resets = query_region.get_by_role(
                        "button", name="重置", exact=True
                    ).filter(visible=True)
                    region_queries = query_region.get_by_role(
                        "button", name="查询", exact=True
                    ).filter(visible=True)
                    # The first visible .el-form can be Chengfeng's account
                    # header rather than the business query form. Count is a
                    # safe discriminator once the waybill tab has rendered;
                    # do not wait a full timeout inside a form that owns no
                    # query buttons.
                    if region_resets.count() != 1 or region_queries.count() != 1:
                        continue
                    candidate_reset = region_resets.first
                    candidate_query = region_queries.first
                    candidate_reset.wait_for(
                        state="visible",
                        timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                    )
                    candidate_query.wait_for(
                        state="visible",
                        timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                    )
                except Exception:
                    continue
                matched_controls = (candidate_reset, candidate_query)
                break
            if matched_controls is None:
                global_reset = page.get_by_role("button", name="重置", exact=True).filter(
                    visible=True
                )
                global_query = page.get_by_role("button", name="查询", exact=True).filter(
                    visible=True
                )
                candidate_reset = global_reset.first
                candidate_query = global_query.first
                candidate_reset.wait_for(
                    state="visible",
                    timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                )
                candidate_query.wait_for(
                    state="visible",
                    timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
                )
                if global_reset.count() != 1 or global_query.count() != 1:
                    raise RuntimeError("settlement query region is unavailable")
                matched_controls = (candidate_reset, candidate_query)
            reset_button, query_button = matched_controls
        except Exception as exc:
            raise BrowserReadError("browser_session_query_control_unavailable") from exc
        return (
            settle_ready,
            settlement_tab,
            waybill_tab,
            reset_button,
            query_button,
        )

    def _wait_for_daily_controls(self, page: Any) -> tuple[Any, Any, Any]:
        """Return the official daily list, reset and query controls."""

        try:
            daily_title = page.get_by_text("运单管理", exact=True).filter(visible=True).first
            daily_title.wait_for(
                state="visible",
                timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
            )
            reset_button = (
                page.get_by_role("button", name="重置", exact=True).filter(visible=True).first
            )
            reset_button.wait_for(
                state="visible",
                timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
            )
            query_button = (
                page.get_by_role("button", name="查询", exact=True).filter(visible=True).first
            )
            query_button.wait_for(
                state="visible",
                timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
            )
            return daily_title, reset_button, query_button
        except Exception as exc:
            if _page_requires_login(page):
                raise BrowserReadError("browser_read_login_required") from exc
            raise BrowserReadError("browser_daily_query_control_unavailable") from exc

    @staticmethod
    def _wait_for_operational_ui_idle(page: Any) -> None:
        """Wait until the official page has finished its current table redraw."""

        try:
            page.wait_for_function(
                """
                () => !Array.from(document.querySelectorAll(
                  '.el-loading-mask, .el-loading-spinner, [class*="loading-mask"]'
                )).some((element) => {
                  const style = window.getComputedStyle(element);
                  const bounds = element.getBoundingClientRect();
                  return style.display !== 'none'
                    && style.visibility !== 'hidden'
                    && bounds.width > 0
                    && bounds.height > 0;
                })
                """,
                timeout=OPERATIONAL_UI_IDLE_TIMEOUT_MS,
            )
        except Exception as exc:
            raise BrowserReadError("browser_operational_page_busy") from exc

    def _wait_for_session_headers(
        self,
        pages: tuple[Any, ...],
        *,
        scope: str = CURRENT_PENDING_SETTLEMENT_SCOPE,
    ) -> dict[str, object]:
        if not pages:
            raise BrowserReadError("browser_read_login_required")
        settlement_pages = tuple(
            page for page in pages if str(getattr(page, "url", "")) == CHENGFENG_HUMAN_LOGIN_ENTRY
        )
        if len(settlement_pages) != 1:
            for candidate in pages:
                try:
                    candidate_url = urlsplit(str(getattr(candidate, "url", "")))
                except ValueError:
                    continue
                if (
                    candidate_url.scheme == "https"
                    and candidate_url.hostname == "pc.chengfengkuaiyun.com"
                    and (candidate_url.path == "/login" or candidate_url.path.startswith("/login/"))
                ):
                    raise BrowserReadError("browser_read_login_required")
            raise BrowserReadError("browser_session_settlement_route_unavailable")
        page = settlement_pages[0]
        if scope == HISTORICAL_SETTLED_SCOPE:
            try:
                response = page.goto(
                    CHENGFENG_HISTORICAL_ENTRY,
                    wait_until="commit",
                    timeout=HUMAN_LOGIN_NAVIGATION_TIMEOUT_MS,
                )
                if response is None:
                    raise BrowserReadError("browser_session_settlement_route_unavailable")
                response_status = int(getattr(response, "status", 0))
                if response_status < 200 or response_status >= 400:
                    raise BrowserReadError("browser_session_settlement_route_unavailable")
            except BrowserReadError:
                raise
            except Exception as exc:
                raise BrowserReadError("browser_session_settlement_route_unavailable") from exc
        elif scope != CURRENT_PENDING_SETTLEMENT_SCOPE:
            raise BrowserReadError("browser_settlement_scope_invalid")
        current_url = str(getattr(page, "url", ""))
        parsed_current = None
        if current_url:
            try:
                parsed_current = urlsplit(current_url)
            except ValueError:
                parsed_current = None
            if (
                parsed_current is not None
                and parsed_current.hostname == "pc.chengfengkuaiyun.com"
                and (parsed_current.path == "/login" or parsed_current.path.startswith("/login/"))
            ):
                raise BrowserReadError("browser_read_login_required")
        if (
            parsed_current is None
            or parsed_current.scheme != "https"
            or parsed_current.hostname != "pc.chengfengkuaiyun.com"
            or parsed_current.port not in {None, 443}
            or parsed_current.username is not None
            or parsed_current.password is not None
            or parsed_current.path
            != ("/rejectedReturnBill" if scope == HISTORICAL_SETTLED_SCOPE else "/billablewaybill")
            or parsed_current.query
            or parsed_current.fragment
        ):
            raise BrowserReadError("browser_session_settlement_route_unavailable")
        if _page_requires_login(page):
            raise BrowserReadError("browser_read_login_required")
        route_handler = None
        expected_list_path = (
            CHENGFENG_HISTORICAL_LIST_PATH
            if scope == HISTORICAL_SETTLED_SCOPE
            else CHENGFENG_LIST_PATH
        )
        (
            settle_ready,
            settlement_tab,
            waybill_tab,
            reset_button,
            query_button,
        ) = self._wait_for_settlement_controls(
            page,
            scope=scope,
        )

        try:
            self._session_headers = None
            self._session_list_fixed_values = None
            self._session_list_cache_query = None
            self._session_list_body = None
            self._session_list_body_sha256 = None
            self._session_native_probe = None
            self._session_request_seen = False
            self._session_headers_rejected = False
            self._session_fixed_values_rejected = False
            self._session_cache_query_rejected = False
            self._session_list_body_rejected = False
            self._session_trigger_shapes = set()
            native_probe_armed = False
            native_probe_attempted = False
            native_probe_error_code: str | None = None

            def aborting_session_trigger(route: Any) -> None:
                nonlocal native_probe_attempted, native_probe_error_code
                request = getattr(route, "request", None)
                self._session_trigger_shapes.add(
                    _session_request_shape(
                        request,
                        expected_path=expected_list_path,
                    )
                )
                approved_request = _is_session_header_request(
                    request,
                    expected_path=expected_list_path,
                )
                if approved_request:
                    self._session_request_seen = True
                headers = _session_headers_from_request(
                    request,
                    expected_path=expected_list_path,
                )
                fixed_values = (
                    _historical_list_fixed_values_from_request(request)
                    if scope == HISTORICAL_SETTLED_SCOPE
                    else _private_list_fixed_values_from_request(request)
                )
                cache_query = _private_list_cache_query_from_request(
                    request,
                    expected_path=expected_list_path,
                )
                list_body = _private_list_body_from_request(
                    request,
                    scope=scope,
                )
                body_sha256 = _private_list_body_sha256_from_request(
                    request,
                    scope=scope,
                )
                if headers is not None:
                    self._session_headers = headers
                elif self._session_request_seen:
                    self._session_headers_rejected = True
                if fixed_values is not None:
                    self._session_list_fixed_values = dict(fixed_values)
                elif self._session_request_seen:
                    self._session_fixed_values_rejected = True
                if cache_query is not None:
                    self._session_list_cache_query = cache_query
                elif self._session_request_seen:
                    self._session_cache_query_rejected = True
                if body_sha256 is not None:
                    self._session_list_body = list_body
                    self._session_list_body_sha256 = body_sha256
                elif self._session_request_seen:
                    self._session_list_body_rejected = True
                try:
                    if native_probe_armed and approved_request and not native_probe_attempted:
                        native_probe_attempted = True
                        if (
                            headers is not None
                            and fixed_values is not None
                            and cache_query is not None
                            and list_body is not None
                            and body_sha256 is not None
                        ):
                            try:
                                self._session_native_probe = _fetch_native_list_probe(
                                    route,
                                    request_body=list_body,
                                    scope=scope,
                                )
                            except BrowserReadError as exc:
                                native_probe_error_code = exc.code
                finally:
                    route.abort()

            route_handler = aborting_session_trigger
            page.route("**/*", route_handler)
            if settle_ready is not None and settlement_tab is not None:
                settle_ready.click(timeout=10_000)
                page.wait_for_timeout(300)
                settlement_tab.click(timeout=10_000)
                page.wait_for_timeout(300)
            waybill_tab.click(timeout=10_000)
            page.wait_for_timeout(300)
            reset_button.click(timeout=10_000)
            page.wait_for_timeout(300)
            if scope == CURRENT_PENDING_SETTLEMENT_SCOPE:
                # Chengfeng redraws the list on reset and can drop the
                # "display by waybill" selection. Re-activate that view
                # before capturing the account-specific native query.
                waybill_tab.click(timeout=10_000)
                page.wait_for_timeout(300)
            self._session_headers = None
            self._session_list_fixed_values = None
            self._session_list_cache_query = None
            self._session_list_body = None
            self._session_list_body_sha256 = None
            self._session_native_probe = None
            self._session_request_seen = False
            self._session_headers_rejected = False
            self._session_fixed_values_rejected = False
            self._session_cache_query_rejected = False
            self._session_list_body_rejected = False
            self._session_trigger_shapes = set()
            native_probe_armed = True
            query_button.click(timeout=10_000)
        except Exception as exc:
            if route_handler is not None:
                with suppress(Exception):
                    page.unroute("**/*", route_handler)
            if isinstance(exc, BrowserReadError):
                raise
            raise BrowserReadError("browser_session_trigger_failed") from exc
        try:
            for _ in range(SESSION_HEADER_CAPTURE_WAIT_STEPS):
                try:
                    page.wait_for_timeout(SESSION_HEADER_CAPTURE_POLL_MS)
                except Exception as exc:
                    raise BrowserReadError("browser_context_closed") from exc
                if native_probe_error_code is not None:
                    break
                if (
                    self._session_headers is not None
                    and self._session_list_fixed_values is not None
                    and self._session_list_cache_query is not None
                    and self._session_list_body is not None
                    and self._session_list_body_sha256 is not None
                    and self._session_native_probe is not None
                ):
                    break
        finally:
            if route_handler is not None:
                with suppress(Exception):
                    page.unroute("**/*", route_handler)
        if native_probe_error_code is not None:
            raise BrowserReadError(native_probe_error_code)
        if (
            self._session_headers is not None
            and self._session_list_fixed_values is not None
            and self._session_list_cache_query is not None
            and self._session_list_body is not None
            and self._session_list_body_sha256 is not None
            and self._session_native_probe is not None
        ):
            return {
                **self._session_native_probe,
                "metrics": dict(self._session_native_probe["metrics"]),
            }
        if self._session_fixed_values_rejected:
            raise BrowserReadError("browser_session_fixed_values_rejected")
        if self._session_cache_query_rejected:
            raise BrowserReadError("browser_session_cache_query_rejected")
        if self._session_list_body_rejected:
            raise BrowserReadError("browser_session_list_body_rejected")
        if self._session_headers_rejected:
            raise BrowserReadError("browser_session_headers_rejected")
        shape_priority = (
            ("list_path_variant", "browser_session_list_path_variant"),
            ("query_present", "browser_session_query_present"),
            ("same_origin_other_api", "browser_session_other_api_constructed"),
            ("same_origin_non_api", "browser_session_non_api_constructed"),
            ("resource_mismatch", "browser_session_resource_mismatch"),
            ("method_mismatch", "browser_session_method_mismatch"),
            ("origin_mismatch", "browser_session_origin_mismatch"),
            ("url_invalid", "browser_session_url_invalid"),
        )
        for shape, code in shape_priority:
            if shape in self._session_trigger_shapes:
                raise BrowserReadError(code)
        if native_probe_attempted:
            raise BrowserReadError("browser_session_native_probe_failed")
        raise BrowserReadError("browser_session_request_not_constructed")

    def _stage_read_payload(
        self,
        *,
        request_id: str,
        suffix: str,
        content: bytes,
    ) -> str:
        staging_root = self._staging_root
        if staging_root is None:
            raise BrowserReadError("browser_context_closed")
        directory = staging_root / request_id
        target = directory / f"payload{suffix}"
        temporary = directory / ".payload.part"
        try:
            directory.mkdir()
            with temporary.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            return target.relative_to(staging_root).as_posix()
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            target.unlink(missing_ok=True)
            with suppress(OSError):
                directory.rmdir()
            raise BrowserReadError("browser_read_staging_failed") from exc

    def _record_request(self, request: Any) -> None:
        if not self._capturing or len(self._observations) >= 200:
            return
        if not _approved_discovery_request(request):
            return
        observation = _request_observation(request)
        if observation is None:
            return
        self._request_indexes[id(request)] = len(self._observations)
        self._observations.append(observation)

    def _record_response(self, response: Any) -> None:
        if not self._capturing:
            return
        request = getattr(response, "request", None)
        index = self._request_indexes.get(id(request))
        if index is None or index >= len(self._observations):
            return
        observation = self._observations[index]
        try:
            status = int(response.status)
            headers = {str(key).casefold(): str(value) for key, value in response.headers.items()}
        except (AttributeError, TypeError, ValueError):
            return
        content_type = headers.get("content-type", "").split(";", 1)[0].casefold()
        observation["response_status"] = status
        if content_type == "application/json" or content_type.endswith("+json"):
            observation["content_kind"] = "json"
            content_length = headers.get("content-length")
            if content_length is not None:
                try:
                    if int(content_length) > 2 * 1024 * 1024:
                        return
                except ValueError:
                    return
            try:
                payload = response.json()
            except Exception:
                return
            observation["response_fields"] = _json_fields(payload)
        elif content_type.startswith("image/"):
            observation["content_kind"] = "image"
        else:
            observation["content_kind"] = "other"

    def _attach_page(self, page: Any) -> None:
        page_id = id(page)
        if page_id in self._page_handlers:
            return

        def route_handler(route: Any) -> None:
            request = getattr(route, "request", None)
            if request is not None and _approved_discovery_request(request):
                route.continue_()
                return
            raw_method = str(getattr(request, "method", "")).upper()
            method = (
                raw_method
                if raw_method and raw_method.isascii() and len(raw_method) <= 16
                else "UNKNOWN"
            )
            self._discovery_blocked_method_counts[method] = (
                self._discovery_blocked_method_counts.get(method, 0) + 1
            )
            route.abort()

        def request_handler(request: Any) -> None:
            self._record_request(request)

        def response_handler(response: Any) -> None:
            self._record_response(response)

        page.route("**/*", route_handler)
        try:
            page.on("request", request_handler)
            page.on("response", response_handler)
        except Exception:
            with suppress(Exception):
                page.unroute("**/*", route_handler)
            raise
        self._page_handlers[page_id] = (
            page,
            request_handler,
            response_handler,
            route_handler,
        )

    def _freeze_page(self, page: Any) -> None:
        page_id = id(page)
        if page_id in self._human_freeze_handlers:
            return

        is_closed = getattr(page, "is_closed", None)
        if callable(is_closed) and bool(is_closed()):
            return

        def abort_before_send(route: Any) -> None:
            route.abort()

        try:
            page.route("**/*", abort_before_send)
        except Exception:
            if callable(is_closed) and bool(is_closed()):
                return
            raise
        self._human_freeze_handlers[page_id] = (page, abort_before_send)

    def _release_human_freeze_for_automation(self) -> None:
        """Replace the handoff freeze only inside an approved read transition."""

        if self._context is None:
            raise BrowserReadError("browser_context_closed")
        try:
            context_handler = self._human_freeze_context_page_handler
            if context_handler is not None:
                self._context.remove_listener("page", context_handler)
                self._human_freeze_context_page_handler = None
            frozen_pages = tuple(self._human_freeze_handlers.values())
            for page, route_handler in frozen_pages:
                page.unroute("**/*", route_handler)
            self._human_freeze_handlers = {}
        except Exception as exc:
            with suppress(Exception):
                self.close()
            raise BrowserReadError("browser_session_automation_unfreeze_failed") from exc

    def resume_human_session(self) -> None:
        """Return one owned page to explicit human control."""

        if self._context is None or self._capturing or self._automated_prepared:
            raise BrowserReadError("browser_human_session_resume_unavailable")
        try:
            context_handler = self._human_freeze_context_page_handler
            if context_handler is not None:
                self._context.remove_listener("page", context_handler)
                self._human_freeze_context_page_handler = None
            frozen_pages = tuple(self._human_freeze_handlers.values())
            for page, route_handler in frozen_pages:
                page.unroute("**/*", route_handler)
            self._human_freeze_handlers = {}

            pages = tuple(
                page
                for page in self._context.pages
                if not (callable(getattr(page, "is_closed", None)) and bool(page.is_closed()))
            )
            exact_pages = tuple(
                page
                for page in pages
                if str(getattr(page, "url", "")) == CHENGFENG_HUMAN_LOGIN_ENTRY
            )
            if exact_pages:
                target = exact_pages[0]
            elif pages:
                target = pages[0]
            else:
                target = self._context.new_page()
            _open_human_login_entry(target)
        except Exception as exc:
            with suppress(Exception):
                self.close()
            if isinstance(exc, BrowserReadError):
                raise
            raise BrowserReadError("browser_human_session_resume_failed") from exc

    def handoff_operational_session(self) -> None:
        """Close only the controlled tab and return the visible window."""

        if (
            self._context is None
            or self._capturing
            or not self._automated_prepared
            or not self._operational_compat_prepared
        ):
            raise BrowserReadError("browser_operational_handoff_unavailable")
        try:
            controlled_page = self._operational_batch_page
            self._clear_private_read_authority()
            if controlled_page is not None and controlled_page is not self._human_page:
                with suppress(Exception):
                    controlled_page.close()
            target = self._human_page_or_create()
            with suppress(Exception):
                target.bring_to_front()
        except Exception as exc:
            with suppress(Exception):
                self.close()
            if isinstance(exc, BrowserReadError):
                raise
            raise BrowserReadError("browser_operational_handoff_failed") from exc

    def park_operational_session(self) -> None:
        """Erase job authority, close its tab, and retain the person's page."""

        if self._context is None or self._capturing:
            raise BrowserReadError("browser_operational_park_unavailable")
        try:
            controlled_page = self._operational_batch_page
            self._clear_private_read_authority()
            if controlled_page is not None and controlled_page is not self._human_page:
                with suppress(Exception):
                    controlled_page.close()
            target = self._human_page_or_create()
            with suppress(Exception):
                target.bring_to_front()
        except Exception as exc:
            with suppress(Exception):
                self.close()
            if isinstance(exc, BrowserReadError):
                raise
            raise BrowserReadError("browser_operational_park_failed") from exc

    def _clear_private_read_authority(self) -> None:
        """Erase browser-private request values without closing the profile."""

        self._remove_operational_batch_page()
        if self._context is not None and self._single_chengfeng_page_handler is not None:
            with suppress(Exception):
                self._context.remove_listener(
                    "page",
                    self._single_chengfeng_page_handler,
                )
        self._single_chengfeng_page_handler = None
        if self._context is not None and self._session_request_handler is not None:
            with suppress(Exception):
                self._context.remove_listener(
                    "request",
                    self._session_request_handler,
                )
        self._session_request_handler = None
        self._session_headers = None
        self._private_batch_cookie_header = None
        self._private_batch_session_frozen = False
        self._prefer_private_http_batch_reads = False
        self._session_list_fixed_values = None
        self._session_list_cache_query = None
        self._session_list_body = None
        self._session_list_body_sha256 = None
        self._session_native_probe = None
        self._session_request_seen = False
        self._session_headers_rejected = False
        self._session_fixed_values_rejected = False
        self._session_cache_query_rejected = False
        self._session_list_body_rejected = False
        self._session_trigger_shapes = set()
        self._daily_session_headers = None
        self._daily_body = None
        self._daily_private_body = None
        self._daily_response_fields = None
        self._daily_probe_body = None
        self._daily_probe_content = None
        self._daily_probe_read_pending = False
        self._daily_authority_scope_sha256 = None
        self._daily_platform_display_total = None
        self._daily_cache_refresh_count = 0
        self._automated_prepared = False
        self._automated_scope = None
        self._operational_compat_prepared = False
        self._operational_first_list_content = None
        self._operational_first_page_number = None
        self._operational_first_page_size = None
        self._operational_query_trace = None
        self._active_contract_subject_code = None
        self._detail_image_grants = {}

    def probe_settlement_views(self) -> dict[str, object]:
        """Read bounded metadata from both official pending-settlement tabs."""

        if self._context is None or self._capturing:
            raise BrowserReadError("browser_settlement_view_probe_unavailable")
        self._human_page_or_create()
        pages = tuple(
            page
            for page in self._context.pages
            if not (callable(getattr(page, "is_closed", None)) and bool(page.is_closed()))
        )
        settlement_pages = tuple(
            page for page in pages if str(getattr(page, "url", "")) == CHENGFENG_HUMAN_LOGIN_ENTRY
        )
        if len(settlement_pages) != 1:
            raise BrowserReadError("browser_session_settlement_route_unavailable")
        page = settlement_pages[0]
        if _page_requires_login(page):
            raise BrowserReadError("browser_read_login_required")
        (
            settle_ready,
            settlement_tab,
            waybill_tab,
            _reset_button,
            query_button,
        ) = self._wait_for_settlement_controls(
            page,
            scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
        )
        if settle_ready is None or settlement_tab is None:
            raise BrowserReadError("browser_session_settlement_scope_control_unavailable")
        try:
            credit_tab = page.get_by_text("\u4fe1\u7528", exact=True).filter(visible=True).first
            credit_tab.wait_for(
                state="visible",
                timeout=SESSION_HEADER_QUERY_BUTTON_TIMEOUT_MS,
            )
        except Exception as exc:
            raise BrowserReadError("browser_session_credit_scope_control_unavailable") from exc

        probes: dict[str, dict[str, object]] = {}
        body_hashes: dict[str, str] = {}
        active_view: str | None = None
        armed = False
        attempted: set[str] = set()
        probe_error_code: str | None = None

        def bounded_probe_route(route: Any) -> None:
            nonlocal probe_error_code
            request = getattr(route, "request", None)
            try:
                if (
                    armed
                    and active_view is not None
                    and active_view not in attempted
                    and _is_session_header_request(
                        request,
                        expected_path=CHENGFENG_LIST_PATH,
                    )
                ):
                    attempted.add(active_view)
                    fixed_values = _private_list_fixed_values_from_request(request)
                    request_body = _private_list_body_from_request(
                        request,
                        scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                    )
                    body_sha256 = _private_list_body_sha256_from_request(
                        request,
                        scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                    )
                    expected_settle_type = 1 if active_view == "settlement" else 2
                    if (
                        fixed_values is None
                        or request_body is None
                        or body_sha256 is None
                        or fixed_values.get("settleQueryType") != expected_settle_type
                    ):
                        probe_error_code = "browser_settlement_view_probe_contract_changed"
                    else:
                        try:
                            probes[active_view] = _fetch_native_list_probe(
                                route,
                                request_body=request_body,
                                scope=CURRENT_PENDING_SETTLEMENT_SCOPE,
                            )
                            body_hashes[active_view] = body_sha256
                        except BrowserReadError as exc:
                            probe_error_code = exc.code
            finally:
                route.abort()

        frozen_entry = self._human_freeze_handlers.pop(id(page), None)
        freeze_removed = False
        route_installed = False
        try:
            if frozen_entry is not None:
                frozen_page, frozen_handler = frozen_entry
                if frozen_page is not page:
                    raise BrowserReadError("browser_settlement_view_probe_unavailable")
                page.unroute("**/*", frozen_handler)
                freeze_removed = True
            page.route("**/*", bounded_probe_route)
            route_installed = True
            settle_ready.click(timeout=10_000)
            page.wait_for_timeout(300)
            for view, tab in (
                ("settlement", settlement_tab),
                ("credit", credit_tab),
            ):
                active_view = view
                armed = False
                tab.click(timeout=10_000)
                page.wait_for_timeout(300)
                waybill_tab.click(timeout=10_000)
                page.wait_for_timeout(300)
                armed = True
                query_button.click(timeout=10_000)
                for _ in range(SESSION_HEADER_CAPTURE_WAIT_STEPS):
                    if probe_error_code is not None or view in probes:
                        break
                    page.wait_for_timeout(SESSION_HEADER_CAPTURE_POLL_MS)
                armed = False
                if probe_error_code is not None:
                    raise BrowserReadError(probe_error_code)
                if view not in probes:
                    raise BrowserReadError("browser_settlement_view_probe_not_constructed")
        except BrowserReadError:
            raise
        except Exception as exc:
            raise BrowserReadError("browser_settlement_view_probe_failed") from exc
        finally:
            if route_installed:
                with suppress(Exception):
                    page.unroute("**/*", bounded_probe_route)
            if frozen_entry is not None:
                frozen_page, frozen_handler = frozen_entry
                try:
                    if freeze_removed:
                        frozen_page.route("**/*", frozen_handler)
                    self._human_freeze_handlers[id(frozen_page)] = (
                        frozen_page,
                        frozen_handler,
                    )
                except Exception as exc:
                    with suppress(Exception):
                        self.close()
                    raise BrowserReadError("browser_session_refreeze_failed") from exc

        if (
            set(probes) != {"settlement", "credit"}
            or set(body_hashes) != {"settlement", "credit"}
            or body_hashes["settlement"] == body_hashes["credit"]
        ):
            raise BrowserReadError("browser_settlement_view_probe_not_distinct")
        return {
            "schema_version": 1,
            "probe_kind": "chengfeng_settlement_views",
            "operation": "list_waybills",
            "views": [
                {
                    "view": view,
                    "metrics": dict(probes[view]["metrics"]),
                    "response_structure_sha256": probes[view]["response_structure_sha256"],
                }
                for view in ("settlement", "credit")
            ],
        }

    def freeze_human_session(self) -> None:
        """Freeze all current and future page traffic before control is returned."""

        if self._context is None or self._capturing:
            raise BrowserReadError("browser_session_freeze_failed")
        self._human_page_or_create()
        pages = tuple(
            page
            for page in self._context.pages
            if not (callable(getattr(page, "is_closed", None)) and bool(page.is_closed()))
        )
        settlement_pages = tuple(
            page for page in pages if str(getattr(page, "url", "")) == CHENGFENG_HUMAN_LOGIN_ENTRY
        )
        if len(settlement_pages) != 1:
            raise BrowserReadError("browser_session_settlement_route_unavailable")
        settlement_page = settlement_pages[0]
        if _page_requires_login(settlement_page):
            raise BrowserReadError("browser_read_login_required")
        if self._human_freeze_context_page_handler is not None:
            try:
                for page in pages:
                    self._freeze_page(page)
            except Exception as exc:
                with suppress(Exception):
                    self.close()
                raise BrowserReadError("browser_session_existing_page_freeze_failed") from exc
            return
        try:
            for page in pages:
                self._freeze_page(page)
        except Exception as exc:
            with suppress(Exception):
                self.close()
            raise BrowserReadError("browser_session_existing_page_freeze_failed") from exc

        try:

            def context_page_handler(page: Any) -> None:
                self._freeze_page(page)

            self._human_freeze_context_page_handler = context_page_handler
            self._context.on("page", context_page_handler)
        except Exception as exc:
            with suppress(Exception):
                self.close()
            raise BrowserReadError("browser_session_future_page_freeze_failed") from exc

    def start_capture(self) -> None:
        if self._context is None or self._capturing:
            raise RuntimeError("browser capture cannot start in the current state")
        pages = tuple(self._context.pages)
        if not pages or not any(
            urlsplit(str(getattr(page, "url", ""))).scheme == "https" for page in pages
        ):
            raise RuntimeError("browser capture requires a logged-in HTTPS page")
        self._observations = []
        self._request_indexes = {}
        self._discovery_blocked_method_counts = {}
        self._capturing = True
        try:
            for page in pages:
                self._attach_page(page)

            def context_page_handler(page: Any) -> None:
                self._attach_page(page)

            self._context_page_handler = context_page_handler
            self._context.on("page", self._context_page_handler)
        except Exception:
            self._capturing = False
            for (
                page,
                request_handler,
                response_handler,
                route_handler,
            ) in self._page_handlers.values():
                with suppress(Exception):
                    page.remove_listener("request", request_handler)
                with suppress(Exception):
                    page.remove_listener("response", response_handler)
                with suppress(Exception):
                    page.unroute("**/*", route_handler)
            self._page_handlers = {}
            raise

    def stop_capture(self) -> list[dict[str, object]]:
        if self._context is None or not self._capturing:
            raise RuntimeError("browser capture is not active")
        pages = tuple(self._context.pages)
        if pages:
            pages[0].wait_for_timeout(250)
        self._capturing = False
        if self._context_page_handler is not None:
            self._context.remove_listener(
                "page",
                self._context_page_handler,
            )
        self._context_page_handler = None
        for (
            page,
            request_handler,
            response_handler,
            route_handler,
        ) in self._page_handlers.values():
            page.remove_listener("request", request_handler)
            page.remove_listener("response", response_handler)
            page.unroute("**/*", route_handler)
        self._page_handlers = {}
        unique: dict[str, dict[str, object]] = {}
        for observation in self._observations:
            canonical = json.dumps(
                observation,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            unique[canonical] = observation
        self._request_indexes = {}
        self._observations = []
        return [unique[key] for key in sorted(unique)]

    def close(self) -> None:
        if self._capturing:
            try:
                self.stop_capture()
            except Exception:
                self._capturing = False
        if self._context is not None:
            if self._session_request_handler is not None:
                with suppress(Exception):
                    self._context.remove_listener(
                        "request",
                        self._session_request_handler,
                    )
            self._context.close()
            self._context = None
        if self._playwright is not None:
            self._playwright.stop()
            self._playwright = None
        self.selected_browser = None
        self._human_page = None
        self._clear_private_read_authority()
        self._staging_root = None
        self._discovery_blocked_method_counts = {}
        self._human_freeze_handlers = {}
        self._human_freeze_context_page_handler = None
        self._single_chengfeng_page_handler = None
