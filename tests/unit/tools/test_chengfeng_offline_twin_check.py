from __future__ import annotations

import pytest

from tools import chengfeng_offline_twin_check as module


def _result() -> dict[str, object]:
    return {
        "schema_version": 2,
        "kind": "chengfeng_offline_query_twin",
        "browser": "msedge",
        "service_workers": "blocked",
        "iframe_loaded": True,
        "hidden_field_preserved": True,
        "blocked_transition_total": 0,
        "transition_read_count": 5,
        "dynamic_total": 137,
        "query_trace": {
            "query_attempt_id": "1" * 32,
            "observed_request_count": 3,
            "approved_request_count": 1,
            "blocked_request_count": 2,
            "request_method": "POST",
            "request_path": "/api/list",
            "resource_type": "fetch",
            "response_status": 200,
            "response_byte_size": 128,
            "response_structure_sha256": "a" * 64,
            "duration_ms": 150,
        },
    }


def test_offline_twin_accepts_only_value_free_dynamic_query_evidence() -> None:
    assert module._validate_result(_result()) == _result()


@pytest.mark.parametrize(
    "patch",
    [
        {"dynamic_total": 121},
        {"hidden_field_preserved": False},
        {"blocked_transition_total": 137},
        {"transition_read_count": 4},
        {"service_workers": "allow"},
        {"request_body": {"private": True}},
    ],
)
def test_offline_twin_rejects_wrong_or_private_evidence(
    patch: dict[str, object],
) -> None:
    result = _result()
    if "request_body" in patch:
        trace = result["query_trace"]
        assert isinstance(trace, dict)
        result["query_trace"] = {**trace, **patch}
    else:
        result.update(patch)

    with pytest.raises(ValueError):
        module._validate_result(result)
