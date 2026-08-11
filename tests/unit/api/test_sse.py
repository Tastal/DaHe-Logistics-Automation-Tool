from __future__ import annotations

from dahe.api.app import format_sse_message


def test_sse_uses_default_message_events_for_browser_onmessage() -> None:
    payload = {
        "event_id": 7,
        "event_type": "job.changed",
        "aggregate_id": "job-1",
        "record_version": 3,
    }

    encoded = format_sse_message(payload)

    assert encoded.startswith("id: 7\n")
    assert "\nevent:" not in encoded
    assert '\ndata: {"aggregate_id":"job-1"' in encoded
    assert encoded.endswith("\n\n")
