from __future__ import annotations

import pytest

from dahe.adapters.sqlite.audit_workflow import (
    _field_issues,
    _review_highlight_roles,
)


def _item(
    *,
    review_reason: str | None,
    business_outcome: str = "awaiting_review",
    loading_ticket_net: str | None = "32.10",
    loading_platform_net: str | None = "32.10",
    unloading_ticket_net: str | None = "32.20",
    unloading_platform_net: str | None = "32.20",
    loading_image_sha256: str | None = "a" * 64,
    unloading_image_sha256: str | None = "b" * 64,
) -> dict[str, object]:
    return {
        "business_outcome": business_outcome,
        "review_reason": review_reason,
        "ticket_loading_net": loading_ticket_net,
        "platform_loading_net": loading_platform_net,
        "ticket_unloading_net": unloading_ticket_net,
        "platform_unloading_net": unloading_platform_net,
        "loading_image_sha256": loading_image_sha256,
        "unloading_image_sha256": unloading_image_sha256,
    }


def _marked(result: dict[str, dict[str, bool]]) -> set[str]:
    return {name for name, issue in result.items() if issue["has_issue"]}


def _observation(
    side: str,
    *,
    ticket_role: str | None = None,
    normalized: str | None = "32.10",
    reliable: bool = True,
    anomaly: str | None = None,
    role_high_confidence: int | None = 1,
) -> dict[str, object]:
    payload: dict[str, object] = {}
    if role_high_confidence is not None:
        payload["role_high_confidence"] = role_high_confidence
    return {
        "image_role": side,
        "ticket_role": ticket_role or side,
        "ordinary_net_normalized": normalized,
        "reliable": int(reliable),
        "anomaly_reason": anomaly,
        "payload_json": payload,
    }


@pytest.mark.parametrize(
    ("item", "expected"),
    (
        (
            _item(
                review_reason="numeric_mismatch",
                unloading_ticket_net="32.19",
            ),
            {"unloading_ocr_weight"},
        ),
        (
            _item(review_reason="ticket_weight_format_suspicious"),
            {"loading_ocr_weight", "unloading_ocr_weight"},
        ),
        (
            _item(review_reason="ocr_weight_disagreement"),
            {"loading_ocr_weight", "unloading_ocr_weight"},
        ),
        (
            _item(
                review_reason="missing_ticket",
                loading_image_sha256=None,
            ),
            {"loading_ocr_weight"},
        ),
        (
            _item(review_reason="suspected_swapped"),
            {"loading_ocr_weight", "unloading_ocr_weight"},
        ),
        (
            _item(review_reason="duplicate_image"),
            {"loading_ocr_weight", "unloading_ocr_weight"},
        ),
        (
            _item(review_reason="role_unknown"),
            {"loading_ocr_weight", "unloading_ocr_weight"},
        ),
    ),
)
def test_field_issue_projection_marks_only_business_evidence_that_needs_attention(
    item: dict[str, object],
    expected: set[str],
) -> None:
    assert _marked(_field_issues(item)) == expected


def test_field_issue_projection_uses_observations_to_locate_one_bad_ticket() -> None:
    result = _field_issues(
        _item(review_reason="role_unknown"),
        observations=(
            _observation("loading", ticket_role="unknown"),
            _observation("unloading"),
        ),
    )

    assert _marked(result) == {"loading_ocr_weight"}


def test_field_issue_projection_locates_one_ocr_anomaly() -> None:
    result = _field_issues(
        _item(review_reason="ticket_weight_format_suspicious"),
        observations=(
            _observation("loading"),
            _observation(
                "unloading",
                normalized="3242",
                reliable=False,
                anomaly="ticket_weight_format_suspicious",
            ),
        ),
    )

    assert _marked(result) == {"unloading_ocr_weight"}


def test_field_issue_projection_never_marks_images_or_platform_values() -> None:
    result = _field_issues(
        _item(review_reason="platform_weight_missing", unloading_platform_net=None)
    )

    assert _marked(result) == {"unloading_ocr_weight"}
    assert all(
        not issue["has_issue"]
        for name, issue in result.items()
        if not name.endswith("_ocr_weight")
    )


def test_field_issue_projection_never_marks_a_normal_business_result() -> None:
    result = _field_issues(
        _item(
            review_reason="numeric_mismatch",
            business_outcome="normal_ready",
            unloading_ticket_net="32.19",
        )
    )

    assert _marked(result) == set()


@pytest.mark.parametrize(
    ("reason", "expected"),
    (
        ("numeric_mismatch", ["unloading"]),
        ("missing_ticket", ["loading"]),
        ("unexpected_historical_reason", ["loading", "unloading"]),
    ),
)
def test_review_highlight_roles_are_backend_authoritative(
    reason: str,
    expected: list[str],
) -> None:
    item = _item(
        review_reason=reason,
        loading_image_sha256=None if reason == "missing_ticket" else "a" * 64,
        unloading_ticket_net="32.19" if reason == "numeric_mismatch" else "32.20",
    )

    assert _review_highlight_roles(item) == expected


def test_review_highlight_roles_are_empty_for_non_review_results() -> None:
    item = _item(
        review_reason="numeric_mismatch",
        business_outcome="normal_ready",
        unloading_ticket_net="32.19",
    )

    assert _review_highlight_roles(item) == []
