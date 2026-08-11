from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from dahe.adapters.chengfeng.discovery import (
    DiscoveryEvidenceError,
    DiscoveryEvidenceStore,
)


def _observation() -> dict[str, object]:
    return {
        "method": "POST",
        "origin": "https://platform.example.invalid",
        "path": "/api/waybills/list",
        "path_sha256": None,
        "query_keys": ["page"],
        "request_fields": [
            {"path": "$.pageNumber", "type": "integer"},
            {"path": "$.filter.status", "type": "string"},
        ],
        "resource_kind": "json_api",
        "response_status": 200,
        "content_kind": "json",
        "response_fields": [
            {"path": "$.data.rows[].id", "type": "string"},
        ],
    }


def test_discovery_evidence_is_atomic_canonical_and_contains_no_raw_values(
    tmp_path,
) -> None:
    store = DiscoveryEvidenceStore(tmp_path)
    result = store.seal(
        observations=[_observation()],
        build_sha256="a" * 64,
        access_window_id="window-one",
        captured_at=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
    )

    assert result.observation_count == 1
    payload = json.loads(result.path.read_text(encoding="utf-8"))
    assert payload["canonical_sha256"] == result.canonical_sha256
    assert payload["status"] == "captured"
    serialized = result.path.read_text(encoding="utf-8")
    for forbidden in (
        "password",
        "cookie",
        "authorization",
        "secret-value",
        "signed-url",
    ):
        assert forbidden not in serialized.casefold()


def test_discovery_evidence_rejects_raw_image_paths_and_sensitive_fields(
    tmp_path,
) -> None:
    store = DiscoveryEvidenceStore(tmp_path)
    image = {
        **_observation(),
        "method": "GET",
        "path": "/private/signed-image.jpeg",
        "path_sha256": "b" * 64,
        "resource_kind": "image",
        "content_kind": "image",
        "request_fields": [],
        "response_fields": [],
    }
    with pytest.raises(DiscoveryEvidenceError):
        store.seal(
            observations=[image],
            build_sha256="a" * 64,
            access_window_id="window-one",
            captured_at=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
        )

    sensitive = {
        **_observation(),
        "request_fields": [{"path": "$.password", "type": "string"}],
    }
    with pytest.raises(DiscoveryEvidenceError):
        store.seal(
            observations=[sensitive],
            build_sha256="a" * 64,
            access_window_id="window-one",
            captured_at=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
        )
