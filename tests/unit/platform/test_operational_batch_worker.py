from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parents[3]
BROWSER_SOURCE = PROJECT_ROOT / "browser-runtime" / "src"


def _worker_modules(monkeypatch: pytest.MonkeyPatch) -> tuple[object, object]:
    monkeypatch.syspath_prepend(str(BROWSER_SOURCE))
    for name in (
        "dahe_browser_worker.engine",
        "dahe_browser_worker.protocol",
    ):
        sys.modules.pop(name, None)
    import dahe_browser_worker.engine as engine
    import dahe_browser_worker.protocol as protocol

    return engine, protocol


def _command_payload(
    *,
    count: int = 15,
    start: int = 1000,
    request_id: str = "batch-fixture",
) -> dict[str, object]:
    return {
        "schema_version": 6,
        "command": "read_operational_batch",
        "request_id": request_id,
        "details": [
            {
                "platform_waybill_id": str(start + index),
                "url": (
                    "https://pc.chengfengkuaiyun.com/api/"
                    "order-center-server/app/clientOrderItem/"
                    "getOrderItemDetailsByIdPC"
                ),
                "parameters": {"id": str(start + index)},
                "reuse": None,
            }
            for index in range(count)
        ],
        "detail_concurrency": 4,
        "image_concurrency": 6,
    }


def test_image_jpg_alias_requires_real_jpeg_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _protocol = _worker_modules(monkeypatch)

    assert (
        engine._validated_image_media_type(
            "image/jpg",
            b"\xff\xd8\xff\xe0fixture-jpeg",
        )
        == "image/jpeg"
    )
    with pytest.raises(engine.BrowserReadError) as error:
        engine._validated_image_media_type(
            "image/jpg",
            b"\x89PNG\r\n\x1a\nfixture-png",
        )

    assert error.value.code == "browser_image_contract_changed"


def test_image_validator_probe_falls_back_to_bounded_get_when_head_is_forbidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _protocol = _worker_modules(monkeypatch)
    open_calls: list[tuple[str, str, str | None]] = []

    class Response:
        status = 206

        def __init__(self) -> None:
            self.headers = {
                "content-type": "image/jpeg",
                "etag": '"stable-ticket"',
                "content-range": "bytes 0-0/2048",
            }

        @staticmethod
        def close() -> None:
            return None

    class Opener:
        @staticmethod
        def open(request: object, *, timeout: float) -> object:
            assert timeout > 0
            method = str(request.get_method())  # type: ignore[attr-defined]
            range_header = request.get_header("Range")  # type: ignore[attr-defined]
            open_calls.append(  # type: ignore[attr-defined]
                (str(request.full_url), method, range_header)
            )
            if method == "HEAD":
                raise engine.HTTPError(
                    "https://evidence.invalid/ticket.jpg",
                    403,
                    "Forbidden",
                    {},
                    None,
                )
            return Response()

    monkeypatch.setattr(engine, "build_opener", lambda *_handlers: Opener())
    unsupported_hosts: set[str] = set()

    first = engine._bounded_http_image_probe(
        url="https://evidence.invalid/ticket.jpg",
        headers={},
        timeout_seconds=1.0,
        unsupported_hosts=unsupported_hosts,
    )

    assert first is not None
    assert first[0] == "image/jpeg"
    assert unsupported_hosts == {"evidence.invalid"}
    assert open_calls == [
        ("https://evidence.invalid/ticket.jpg", "HEAD", None),
        ("https://evidence.invalid/ticket.jpg", "GET", "bytes=0-0"),
    ]


def test_image_validator_probe_caches_hosts_without_stable_validators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, _protocol = _worker_modules(monkeypatch)
    open_calls: list[str] = []

    class Response:
        status = 200

        def __init__(self) -> None:
            self.headers = {"content-type": "image/jpeg"}

        @staticmethod
        def close() -> None:
            return None

    class Opener:
        @staticmethod
        def open(request: object, *, timeout: float) -> object:
            assert timeout > 0
            open_calls.append(str(request.full_url))  # type: ignore[attr-defined]
            return Response()

    monkeypatch.setattr(engine, "build_opener", lambda *_handlers: Opener())
    unsupported_hosts: set[str] = set()

    assert (
        engine._bounded_http_image_probe(
            url="https://evidence.invalid/ticket.jpg",
            headers={},
            timeout_seconds=1.0,
            unsupported_hosts=unsupported_hosts,
        )
        is None
    )
    assert unsupported_hosts == {"evidence.invalid", "!evidence.invalid"}
    assert (
        engine._bounded_http_image_probe(
            url="https://evidence.invalid/other.jpg",
            headers={},
            timeout_seconds=1.0,
            unsupported_hosts=unsupported_hosts,
        )
        is None
    )
    assert open_calls == [
        "https://evidence.invalid/ticket.jpg",
        "https://evidence.invalid/ticket.jpg",
    ]


@pytest.mark.parametrize(
    ("declared", "content"),
    [
        ("image/jpeg", b"not-a-jpeg"),
        ("application/octet-stream", b"\xff\xd8\xff\xe0fixture-jpeg"),
        ("text/plain", b"\xff\xd8\xff\xe0fixture-jpeg"),
    ],
)
def test_image_media_contract_rejects_unapproved_or_mismatched_content(
    monkeypatch: pytest.MonkeyPatch,
    declared: str,
    content: bytes,
) -> None:
    engine, _protocol = _worker_modules(monkeypatch)

    with pytest.raises(engine.BrowserReadError) as error:
        engine._validated_image_media_type(declared, content)

    assert error.value.code == "browser_image_contract_changed"


def test_batch_protocol_is_bounded_and_has_no_arbitrary_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _engine, protocol = _worker_modules(monkeypatch)
    command = protocol.parse_command(
        json.dumps(_command_payload(count=100))
    )

    assert len(command.details) == 100
    assert command.detail_concurrency == 4
    assert command.image_concurrency == 6

    too_many = _command_payload(count=101)
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_command(json.dumps(too_many))
    arbitrary = _command_payload(count=1)
    arbitrary["details"][0]["url"] = "https://example.invalid/read"  # type: ignore[index]
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_command(json.dumps(arbitrary))
    secret = _command_payload(count=1)
    secret["cookie"] = "must-not-pass"
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_command(json.dumps(secret))


def test_batch_protocol_returns_current_incremental_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _engine, protocol = _worker_modules(monkeypatch)
    command = protocol.parse_command(
        json.dumps(_command_payload(count=1))
    )
    payload = {
        "relative_path": "batch-fixture/payload.json",
        "sha256": "a" * 64,
        "byte_size": 42,
        "media_type": "application/json",
        "status_code": 200,
    }
    image_payload = {
        "relative_path": "batch-image/payload.jpeg",
        "sha256": "b" * 64,
        "byte_size": 84,
        "media_type": "image/jpeg",
        "status_code": 200,
    }

    wire = json.loads(
        protocol.response(
            command,
            ok=True,
            selected_browser="msedge",
            browser_open=False,
            batch_result=[
                {
                    "platform_waybill_id": "1000",
                    "source_revision_sha256": "c" * 64,
                    "detail": payload,
                    "images": [
                        {
                            "slot": "loading",
                            "payload": image_payload,
                            "validator_sha256": "d" * 64,
                        },
                        {
                            "slot": "unloading",
                            "reused": {
                                "sha256": "e" * 64,
                                "media_type": "image/png",
                                "validator_sha256": "f" * 64,
                            },
                        },
                    ],
                }
            ],
        )
    )

    assert wire["ok"] is True
    assert wire["browser_open"] is False
    assert wire["batch_result"] == [
        {
            "platform_waybill_id": "1000",
            "source_revision_sha256": "c" * 64,
            "detail": payload,
            "images": [
                {
                    "slot": "loading",
                    "payload": image_payload,
                    "validator_sha256": "d" * 64,
                },
                {
                    "slot": "unloading",
                    "reused": {
                        "sha256": "e" * 64,
                        "media_type": "image/png",
                        "validator_sha256": "f" * 64,
                    },
                },
            ],
        }
    ]


def test_worker_batch_enforces_concurrency_and_never_returns_private_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _worker_modules(monkeypatch)
    command = protocol.parse_command(json.dumps(_command_payload()))
    counters = {
        "image_active": 0,
        "image_max": 0,
    }
    events: list[str] = []
    page_calls: list[dict[str, object]] = []
    lock = threading.Lock()

    def fake_fetch(
        *,
        url: str,
        method: str,
        headers: object,
        body: bytes | None,
        maximum_bytes: int,
        expected_image: bool,
        timeout_seconds: float,
    ) -> tuple[bytes, str]:
        del headers, maximum_bytes, timeout_seconds
        assert expected_image is True
        kind = "image"
        with lock:
            events.append(kind)
            counters[f"{kind}_active"] += 1
            counters[f"{kind}_max"] = max(
                counters[f"{kind}_max"],
                counters[f"{kind}_active"],
            )
        try:
            time.sleep(0.015)
            assert method == "GET"
            assert body is None
            assert "signature=private" in url
            return b"fixture-image", "image/jpeg"
        finally:
            with lock:
                counters[f"{kind}_active"] -= 1

    class Page:
        owner: object | None = None

        @staticmethod
        def is_closed() -> bool:
            return False

        @staticmethod
        def evaluate(script: str, arguments: object) -> list[dict[str, object]]:
            assert "Promise.all" in script
            assert isinstance(arguments, dict)
            page_calls.append(arguments)
            requests = arguments["requests"]
            assert isinstance(requests, list)
            assert Page.owner is not None
            Page.owner._operational_batch_seen_ids.update(  # type: ignore[attr-defined]
                request["platformWaybillId"] for request in requests
            )
            return [
                {
                    "index": index,
                    "status": 200,
                    "redirected": False,
                    "contentType": "application/json;charset=UTF-8",
                    "body": json.dumps(
                        {
                            "data": [
                                {
                                    "id": request["platformWaybillId"],
                                    "sn": f"YD-{request['platformWaybillId']}",
                                    "carNumber": (f"TEST-{request['platformWaybillId']}"),
                                    "originalTon": "32.80",
                                    "currentTon": "32.76",
                                    "originalTonImageUrl": (
                                        "https://cfky.oss-cn-zhangjiakou."
                                        "aliyuncs.com/loading.jpg?signature=private"
                                    ),
                                    "image": (
                                        "https://cfky.oss-cn-zhangjiakou."
                                        "aliyuncs.com/unloading.jpg?signature=private"
                                    ),
                                }
                            ]
                        },
                        separators=(",", ":"),
                    ),
                }
                for index, request in enumerate(requests)
            ]

    class Context:
        def __init__(self) -> None:
            self.pages = [Page()]

        @staticmethod
        def cookies(urls: list[str]) -> list[dict[str, str]]:
            assert len(urls) == 1
            return [{"name": "session", "value": "private-cookie"}]

    monkeypatch.setattr(engine_module, "_bounded_http_fetch", fake_fetch)
    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context
    worker._staging_root = tmp_path
    worker._operational_compat_prepared = True
    worker._operational_batch_page = context.pages[0]
    worker._operational_batch_route_handler = object()
    Page.owner = worker
    worker._session_headers = {
        "authorization": "private-token",
        "user-agent": "fixture-agent",
    }

    result = worker.read_operational_batch(command)
    serialized = json.dumps(result, ensure_ascii=False)

    assert len(result) == 15
    assert all(len(item["images"]) == 2 for item in result)
    assert 2 <= counters["image_max"] <= 6
    assert events
    assert len(page_calls) == 1
    assert page_calls[0]["concurrency"] == 4
    assert page_calls[0]["timeoutMs"] == 30_000
    assert len(page_calls[0]["requests"]) == 15
    assert "private-cookie" not in serialized
    assert "private-token" not in serialized
    assert "signature=private" not in serialized
    for item in result:
        relative = Path(str(item["detail"]["relative_path"]))
        content = (tmp_path / relative).read_text(encoding="utf-8")
        assert "worker-image:loading" in content
        assert "signature=private" not in content


def test_worker_batch_uses_private_direct_read_when_prepared_page_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _worker_modules(monkeypatch)
    command = protocol.parse_command(
        json.dumps(_command_payload(count=3))
    )
    detail_active = 0
    detail_max = 0
    detail_headers: list[dict[str, str]] = []
    lock = threading.Lock()

    def fake_fetch(
        *,
        url: str,
        method: str,
        headers: object,
        body: bytes | None,
        maximum_bytes: int,
        expected_image: bool,
        timeout_seconds: float,
    ) -> tuple[bytes, str, str | None]:
        nonlocal detail_active, detail_max
        del maximum_bytes, timeout_seconds
        if expected_image:
            assert method == "GET"
            return b"\xff\xd8\xff\xe0fixture-jpeg", "image/jpeg", None
        assert method == "POST"
        assert body is not None and body.startswith(b"id=")
        assert isinstance(headers, dict)
        detail_headers.append(headers)
        identity = body.decode("ascii").split("=", 1)[1]
        with lock:
            detail_active += 1
            detail_max = max(detail_max, detail_active)
        try:
            time.sleep(0.01)
            return (
                json.dumps(
                    {
                        "data": [
                            {
                                "id": identity,
                                "sn": f"YD-{identity}",
                                "carNumber": f"TEST-{identity}",
                                "originalTon": "32.80",
                                "currentTon": "32.76",
                                "originalTonImageUrl": (
                                    "https://cfky.oss-cn-zhangjiakou."
                                    "aliyuncs.com/loading.jpg"
                                ),
                                "image": (
                                    "https://cfky.oss-cn-zhangjiakou."
                                    "aliyuncs.com/unloading.jpg"
                                ),
                            }
                        ]
                    },
                    separators=(",", ":"),
                ).encode("utf-8"),
                "application/json",
                None,
            )
        finally:
            with lock:
                detail_active -= 1

    class ClosedPage:
        @staticmethod
        def is_closed() -> bool:
            return True

    class Context:
        def __init__(self) -> None:
            self.pages = [ClosedPage()]

        @staticmethod
        def cookies(urls: list[str]) -> list[dict[str, str]]:
            assert len(urls) == 1
            return [{"name": "session", "value": "private-cookie"}]

    monkeypatch.setattr(engine_module, "_bounded_http_fetch", fake_fetch)
    worker = engine_module.BrowserEngine()
    worker._context = Context()
    worker._staging_root = tmp_path
    worker._operational_compat_prepared = True
    worker._operational_batch_page = ClosedPage()
    worker._operational_batch_route_handler = object()
    worker._session_headers = {
        "authorization": "private-token",
        "user-agent": "fixture-agent",
    }
    worker._freeze_private_batch_session()
    worker._context = None

    result = worker.read_operational_batch(command)

    assert len(result) == 3
    assert detail_max >= 2
    assert detail_headers
    assert all(
        headers.get("cookie") == "session=private-cookie"
        for headers in detail_headers
    )
    assert all(len(item["images"]) == 2 for item in result)
    serialized = json.dumps(result, ensure_ascii=False)
    assert "private-cookie" not in serialized
    assert "private-token" not in serialized


def test_worker_batch_uses_private_direct_read_when_page_closes_during_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _worker_modules(monkeypatch)
    command = protocol.parse_command(json.dumps(_command_payload(count=2)))
    detail_ids: list[str] = []

    def fake_fetch(
        *,
        url: str,
        method: str,
        headers: object,
        body: bytes | None,
        maximum_bytes: int,
        expected_image: bool,
        timeout_seconds: float,
    ) -> tuple[bytes, str, str | None]:
        del url, headers, maximum_bytes, timeout_seconds
        if expected_image:
            assert method == "GET"
            return b"\xff\xd8\xff\xe0fixture-jpeg", "image/jpeg", None
        assert method == "POST"
        assert body is not None and body.startswith(b"id=")
        identity = body.decode("ascii").split("=", 1)[1]
        detail_ids.append(identity)
        return (
            json.dumps(
                {
                    "data": [
                        {
                            "id": identity,
                            "sn": f"YD-{identity}",
                            "carNumber": f"TEST-{identity}",
                            "originalTon": "32.80",
                            "currentTon": "32.76",
                            "originalTonImageUrl": (
                                "https://cfky.oss-cn-zhangjiakou."
                                "aliyuncs.com/loading.jpg"
                            ),
                            "image": (
                                "https://cfky.oss-cn-zhangjiakou."
                                "aliyuncs.com/unloading.jpg"
                            ),
                        }
                    ]
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            "application/json",
            None,
        )

    class Page:
        @staticmethod
        def is_closed() -> bool:
            return False

        @staticmethod
        def evaluate(_script: str, _arguments: object) -> object:
            raise RuntimeError("fixture page closed during fetch")

    class Context:
        def __init__(self) -> None:
            self.pages = [Page()]

        @staticmethod
        def cookies(urls: list[str]) -> list[dict[str, str]]:
            assert len(urls) == 1
            return [{"name": "session", "value": "private-cookie"}]

    monkeypatch.setattr(engine_module, "_bounded_http_fetch", fake_fetch)
    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context
    worker._staging_root = tmp_path
    worker._operational_compat_prepared = True
    worker._operational_batch_page = context.pages[0]
    worker._operational_batch_route_handler = object()
    worker._session_headers = {
        "authorization": "private-token",
        "user-agent": "fixture-agent",
    }

    result = worker.read_operational_batch(command)

    assert detail_ids == ["1000", "1001"]
    assert [item["platform_waybill_id"] for item in result] == ["1000", "1001"]
    assert all(len(item["images"]) == 2 for item in result)
    serialized = json.dumps(result, ensure_ascii=False)
    assert "private-cookie" not in serialized
    assert "private-token" not in serialized


def test_worker_uses_bounded_private_http_after_authoritative_list_freezes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _worker_modules(monkeypatch)
    command = protocol.parse_command(json.dumps(_command_payload(count=4)))
    detail_active = 0
    detail_max = 0
    lock = threading.Lock()

    def fake_fetch(
        *,
        url: str,
        method: str,
        headers: object,
        body: bytes | None,
        maximum_bytes: int,
        expected_image: bool,
        timeout_seconds: float,
    ) -> tuple[bytes, str, str | None]:
        nonlocal detail_active, detail_max
        del url, headers, maximum_bytes, timeout_seconds
        if expected_image:
            assert method == "GET"
            return b"fixture-image", "image/jpeg", None
        assert method == "POST"
        assert body is not None and body.startswith(b"id=")
        identity = body.decode("ascii").split("=", 1)[1]
        with lock:
            detail_active += 1
            detail_max = max(detail_max, detail_active)
        try:
            time.sleep(0.01)
            return (
                json.dumps(
                    {
                        "data": [
                            {
                                "id": identity,
                                "sn": f"YD-{identity}",
                                "carNumber": f"TEST-{identity}",
                                "originalTon": "32.80",
                                "currentTon": "32.76",
                                "originalTonImageUrl": (
                                    "https://cfky.oss-cn-zhangjiakou."
                                    "aliyuncs.com/loading.jpg"
                                ),
                                "image": (
                                    "https://cfky.oss-cn-zhangjiakou."
                                    "aliyuncs.com/unloading.jpg"
                                ),
                            }
                        ]
                    },
                    separators=(",", ":"),
                ).encode("utf-8"),
                "application/json",
                None,
            )
        finally:
            with lock:
                detail_active -= 1

    class Page:
        owner: object | None = None

        @staticmethod
        def is_closed() -> bool:
            return False

        @classmethod
        def evaluate(cls, _script: str, arguments: object) -> object:
            assert isinstance(arguments, dict)
            requests = arguments["requests"]
            assert isinstance(requests, list)
            assert cls.owner is not None
            identities = [str(request["platformWaybillId"]) for request in requests]
            cls.owner._operational_batch_seen_ids.update(identities)  # type: ignore[attr-defined]
            return [
                {
                    "status": 200,
                    "redirected": False,
                    "contentType": "application/json",
                    "body": json.dumps(
                        {
                            "data": [
                                {
                                    "id": identity,
                                    "sn": f"YD-{identity}",
                                    "carNumber": f"TEST-{identity}",
                                    "originalTon": "32.80",
                                    "currentTon": "32.76",
                                    "originalTonImageUrl": None,
                                    "image": None,
                                }
                            ]
                        },
                        separators=(",", ":"),
                    ),
                }
                for identity in identities
            ]

    class Context:
        def __init__(self) -> None:
            self.pages = [Page()]

        @staticmethod
        def cookies(urls: list[str]) -> list[dict[str, str]]:
            assert len(urls) == 1
            return [{"name": "session", "value": "private-cookie"}]

    monkeypatch.setattr(engine_module, "_bounded_http_fetch", fake_fetch)
    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context
    worker._staging_root = tmp_path
    worker._operational_compat_prepared = True
    worker._operational_batch_page = context.pages[0]
    worker._operational_batch_route_handler = object()
    worker._session_headers = {"authorization": "private-token"}
    worker._freeze_private_batch_session()
    worker._prefer_private_http_batch_reads = True
    Page.owner = worker

    result = worker.read_operational_batch(command)

    assert len(result) == 4
    assert detail_max == command.detail_concurrency
    assert all(len(item["images"]) == 2 for item in result)


def test_worker_reports_private_http_session_expiry_without_page_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _worker_modules(monkeypatch)
    command = protocol.parse_command(json.dumps(_command_payload(count=2)))

    def direct_fetch(**_values: object) -> tuple[bytes, str, str | None]:
        raise engine_module.BrowserReadError("browser_read_login_required")

    class Page:
        owner: object | None = None

        @staticmethod
        def is_closed() -> bool:
            return False

        @classmethod
        def evaluate(cls, _script: str, arguments: object) -> object:
            assert isinstance(arguments, dict)
            requests = arguments["requests"]
            assert isinstance(requests, list)
            assert cls.owner is not None
            identities = {
                str(request["platformWaybillId"])
                for request in requests
                if isinstance(request, dict)
            }
            cls.owner._operational_batch_seen_ids.update(identities)  # type: ignore[attr-defined]
            return [
                {
                    "status": 200,
                    "redirected": False,
                    "contentType": "application/json",
                    "body": json.dumps(
                        {
                            "data": [
                                {
                                    "id": identity,
                                    "sn": f"YD-{identity}",
                                    "carNumber": f"TEST-{identity}",
                                    "originalTon": "32.80",
                                    "currentTon": "32.76",
                                    "originalTonImageUrl": None,
                                    "image": None,
                                }
                            ]
                        },
                        separators=(",", ":"),
                    ),
                }
                for identity in sorted(identities)
            ]

    class Context:
        def __init__(self) -> None:
            self.pages = [Page()]

        @staticmethod
        def cookies(_urls: list[str]) -> list[dict[str, str]]:
            return [{"name": "session", "value": "private-cookie"}]

    monkeypatch.setattr(engine_module, "_bounded_http_fetch", direct_fetch)
    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context
    worker._staging_root = tmp_path
    worker._operational_compat_prepared = True
    worker._operational_batch_page = context.pages[0]
    worker._operational_batch_route_handler = object()
    worker._session_headers = {"authorization": "private-token"}
    worker._freeze_private_batch_session()
    worker._prefer_private_http_batch_reads = True
    Page.owner = worker

    with pytest.raises(engine_module.BrowserReadError) as exc_info:
        worker.read_operational_batch(command)

    assert exc_info.value.code == "browser_read_login_required"
    assert worker._prefer_private_http_batch_reads is True


def test_worker_reuses_images_only_after_source_and_validator_match(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _worker_modules(monkeypatch)
    raw = _command_payload(count=1)
    sanitized = json.dumps(
        {
            "data": [
                {
                    "carNumber": "TEST-1000",
                    "currentTon": "32.76",
                    "id": "1000",
                    "image": "worker-image:unloading",
                    "originalTon": "32.80",
                    "originalTonImageUrl": "worker-image:loading",
                    "sn": "YD-1000",
                }
            ]
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    source_revision = hashlib.sha256(sanitized).hexdigest()
    validator = "a" * 64
    raw["details"][0]["reuse"] = {  # type: ignore[index]
        "source_revision_sha256": source_revision,
        "images": [
            {
                "slot": slot,
                "sha256": sha,
                "media_type": "image/jpeg",
                "validator_sha256": validator,
            }
            for slot, sha in (("loading", "b" * 64), ("unloading", "c" * 64))
        ],
    }
    command = protocol.parse_command(json.dumps(raw))

    class Page:
        owner: object | None = None

        @staticmethod
        def is_closed() -> bool:
            return False

        @staticmethod
        def evaluate(script: str, arguments: object) -> list[dict[str, object]]:
            assert "Promise.all" in script
            assert isinstance(arguments, dict)
            assert Page.owner is not None
            Page.owner._operational_batch_seen_ids.add("1000")  # type: ignore[attr-defined]
            return [
                {
                    "index": 0,
                    "status": 200,
                    "redirected": False,
                    "contentType": "application/json",
                    "body": json.dumps(
                        {
                            "data": [
                                {
                                    "id": "1000",
                                    "sn": "YD-1000",
                                    "carNumber": "TEST-1000",
                                    "originalTon": "32.80",
                                    "currentTon": "32.76",
                                    "originalTonImageUrl": "https://cfky.oss-cn-zhangjiakou.aliyuncs.com/loading.jpg?signature=private",
                                    "image": "https://cfky.oss-cn-zhangjiakou.aliyuncs.com/unloading.jpg?signature=private",
                                }
                            ]
                        },
                        separators=(",", ":"),
                    ),
                }
            ]

    class Context:
        def __init__(self) -> None:
            self.pages = [Page()]

        @staticmethod
        def cookies(urls: list[str]) -> list[dict[str, str]]:
            assert len(urls) == 1
            return []

    monkeypatch.setattr(
        engine_module,
        "_bounded_http_image_probe",
        lambda **_values: ("image/jpeg", validator),
    )
    monkeypatch.setattr(
        engine_module,
        "_bounded_http_fetch",
        lambda **_values: (_ for _ in ()).throw(
            AssertionError("reused image body must not be downloaded")
        ),
    )
    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context
    worker._staging_root = tmp_path
    worker._operational_compat_prepared = True
    worker._operational_batch_page = context.pages[0]
    worker._operational_batch_route_handler = object()
    Page.owner = worker
    worker._session_headers = {"user-agent": "fixture-agent"}

    result = worker.read_operational_batch(command)

    assert result[0]["source_revision_sha256"] == source_revision
    assert result[0]["images"] == [
        {
            "slot": "loading",
            "reused": {
                "sha256": "b" * 64,
                "media_type": "image/jpeg",
                "validator_sha256": validator,
            },
        },
        {
            "slot": "unloading",
            "reused": {
                "sha256": "c" * 64,
                "media_type": "image/jpeg",
                "validator_sha256": validator,
            },
        },
    ]
    staged = tuple(path for path in tmp_path.rglob("*") if path.is_file())
    assert len(staged) == 1


def test_worker_downloads_image_when_validator_is_not_reliable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _worker_modules(monkeypatch)
    raw = _command_payload(count=1)
    raw["details"][0]["reuse"] = {  # type: ignore[index]
        "source_revision_sha256": "a" * 64,
        "images": [
            {
                "slot": "loading",
                "sha256": "b" * 64,
                "media_type": "image/jpeg",
                "validator_sha256": "c" * 64,
            }
        ],
    }
    command = protocol.parse_command(json.dumps(raw))
    fetches: list[str] = []

    class Page:
        owner: object | None = None

        @staticmethod
        def is_closed() -> bool:
            return False

        @staticmethod
        def evaluate(script: str, arguments: object) -> list[dict[str, object]]:
            del script, arguments
            assert Page.owner is not None
            Page.owner._operational_batch_seen_ids.add("1000")  # type: ignore[attr-defined]
            return [
                {
                    "index": 0,
                    "status": 200,
                    "redirected": False,
                    "contentType": "application/json",
                    "body": json.dumps(
                        {
                            "data": [
                                {
                                    "id": "1000",
                                    "sn": "YD-1000",
                                    "carNumber": "TEST-1000",
                                    "originalTon": "32.80",
                                    "currentTon": "32.76",
                                    "originalTonImageUrl": "https://cfky.oss-cn-zhangjiakou.aliyuncs.com/loading.jpg?signature=private",
                                    "image": None,
                                }
                            ]
                        },
                        separators=(",", ":"),
                    ),
                }
            ]

    class Context:
        def __init__(self) -> None:
            self.pages = [Page()]

        @staticmethod
        def cookies(urls: list[str]) -> list[dict[str, str]]:
            assert len(urls) == 1
            return []

    monkeypatch.setattr(
        engine_module,
        "_bounded_http_image_probe",
        lambda **_values: None,
    )

    def fetch(**values: object) -> tuple[bytes, str, None]:
        fetches.append(str(values["url"]))
        return b"fresh-image", "image/jpeg", None

    monkeypatch.setattr(engine_module, "_bounded_http_fetch", fetch)
    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context
    worker._staging_root = tmp_path
    worker._operational_compat_prepared = True
    worker._operational_batch_page = context.pages[0]
    worker._operational_batch_route_handler = object()
    Page.owner = worker
    worker._session_headers = {"user-agent": "fixture-agent"}

    result = worker.read_operational_batch(command)

    assert len(fetches) == 1
    assert "reused" not in result[0]["images"][0]
    assert result[0]["images"][0]["validator_sha256"] is None


def test_worker_reuses_the_same_page_for_consecutive_batches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _worker_modules(monkeypatch)
    commands = tuple(
        protocol.parse_command(
            json.dumps(
                _command_payload(
                    count=2,
                    start=start,
                    request_id=f"batch-{batch_number}",
                )
            )
        )
        for batch_number, start in ((1, 1000), (2, 2000))
    )
    page_calls: list[tuple[str, ...]] = []

    def fake_fetch(
        *,
        url: str,
        method: str,
        headers: object,
        body: bytes | None,
        maximum_bytes: int,
        expected_image: bool,
        timeout_seconds: float,
    ) -> tuple[bytes, str]:
        del url, headers, maximum_bytes, timeout_seconds
        assert method == "GET"
        assert body is None
        assert expected_image is True
        return b"fixture-image", "image/jpeg"

    class Page:
        owner: object | None = None

        @staticmethod
        def is_closed() -> bool:
            return False

        @staticmethod
        def evaluate(_script: str, arguments: object) -> list[dict[str, object]]:
            assert isinstance(arguments, dict)
            requests = arguments["requests"]
            assert isinstance(requests, list)
            identities = tuple(
                str(request["platformWaybillId"])
                for request in requests
            )
            page_calls.append(identities)
            assert Page.owner is not None
            Page.owner._operational_batch_seen_ids.update(identities)  # type: ignore[attr-defined]
            return [
                {
                    "index": index,
                    "status": 200,
                    "redirected": False,
                    "contentType": "application/json",
                    "body": json.dumps(
                        {
                            "data": [
                                {
                                    "id": platform_id,
                                    "sn": f"YD-{platform_id}",
                                    "carNumber": "TEST-01",
                                    "originalTon": "32.80",
                                    "currentTon": "32.76",
                                    "originalTonImageUrl": (
                                        "https://cfky.oss-cn-zhangjiakou."
                                        "aliyuncs.com/loading.jpg?signature=private"
                                    ),
                                    "image": (
                                        "https://cfky.oss-cn-zhangjiakou."
                                        "aliyuncs.com/unloading.jpg?signature=private"
                                    ),
                                }
                            ]
                        },
                        separators=(",", ":"),
                    ),
                }
                for index, platform_id in enumerate(identities)
            ]

    class Context:
        def __init__(self) -> None:
            self.pages = [Page()]

        @staticmethod
        def cookies(urls: list[str]) -> list[dict[str, str]]:
            assert len(urls) == 1
            return []

    monkeypatch.setattr(engine_module, "_bounded_http_fetch", fake_fetch)
    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context
    worker._staging_root = tmp_path
    worker._operational_compat_prepared = True
    worker._operational_batch_page = context.pages[0]
    worker._operational_batch_route_handler = object()
    worker._session_headers = {"user-agent": "fixture-agent"}
    Page.owner = worker

    first = worker.read_operational_batch(commands[0])
    second = worker.read_operational_batch(commands[1])

    assert [item["platform_waybill_id"] for item in first] == ["1000", "1001"]
    assert [item["platform_waybill_id"] for item in second] == ["2000", "2001"]
    assert page_calls == [("1000", "1001"), ("2000", "2001")]


def test_daily_prepared_session_can_reuse_the_same_bounded_batch_reader(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_module, protocol = _worker_modules(monkeypatch)
    command = protocol.parse_command(json.dumps(_command_payload(count=1)))

    def fake_fetch(
        *,
        url: str,
        method: str,
        headers: object,
        body: bytes | None,
        maximum_bytes: int,
        expected_image: bool,
        timeout_seconds: float,
    ) -> tuple[bytes, str]:
        del headers, maximum_bytes, timeout_seconds
        assert expected_image is True
        return b"fixture-image", "image/jpeg"

    class Page:
        owner: object | None = None

        @staticmethod
        def is_closed() -> bool:
            return False

        @staticmethod
        def evaluate(_script: str, arguments: object) -> list[dict[str, object]]:
            assert isinstance(arguments, dict)
            request = arguments["requests"][0]
            assert Page.owner is not None
            Page.owner._operational_batch_seen_ids.add(  # type: ignore[attr-defined]
                request["platformWaybillId"]
            )
            platform_id = request["platformWaybillId"]
            return [
                {
                    "index": 0,
                    "status": 200,
                    "redirected": False,
                    "contentType": "application/json",
                    "body": json.dumps(
                        {
                            "data": [
                                {
                                    "id": platform_id,
                                    "sn": f"YD-{platform_id}",
                                    "carNumber": "TEST-01",
                                    "originalTon": "32.80",
                                    "currentTon": "32.76",
                                    "originalTonImageUrl": None,
                                    "image": None,
                                }
                            ]
                        },
                        separators=(",", ":"),
                    ),
                }
            ]

    class Context:
        def __init__(self) -> None:
            self.pages = [Page()]

        @staticmethod
        def cookies(urls: list[str]) -> list[dict[str, str]]:
            assert len(urls) == 1
            return []

    monkeypatch.setattr(engine_module, "_bounded_http_fetch", fake_fetch)
    context = Context()
    worker = engine_module.BrowserEngine()
    worker._context = context
    worker._staging_root = tmp_path
    worker._operational_compat_prepared = False
    worker._operational_batch_page = context.pages[0]
    worker._operational_batch_route_handler = object()
    Page.owner = worker
    worker._session_headers = None
    worker._daily_session_headers = {"user-agent": "fixture-agent"}

    result = worker.read_operational_batch(command)

    assert len(result) == 1
    assert result[0]["images"] == []


def test_page_owned_detail_request_requires_one_allowed_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_module, _protocol = _worker_modules(monkeypatch)

    class Request:
        method = "POST"
        resource_type = "fetch"
        url = (
            "https://pc.chengfengkuaiyun.com/api/"
            "order-center-server/app/clientOrderItem/"
            "getOrderItemDetailsByIdPC"
        )
        post_data = "id=1000"

    assert (
        engine_module._operational_batch_detail_identity(
            Request(),
            allowed_identities={"1000"},
        )
        == "1000"
    )
    assert (
        engine_module._operational_batch_detail_identity(
            Request(),
            allowed_identities={"1001"},
        )
        is None
    )
    Request.post_data = "id=1000&extra=1"
    assert (
        engine_module._operational_batch_detail_identity(
            Request(),
            allowed_identities={"1000"},
        )
        is None
    )
