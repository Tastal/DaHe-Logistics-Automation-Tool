from __future__ import annotations

import pytest

from dahe.verification.batch_benchmark import (
    NetworkBatchSummary,
    NetworkBatchTrial,
    requires_third_trial,
    select_default_batch_size,
    summarize_trials,
)


def _trial(batch_size: int, elapsed: float, *, ui_p95: float = 0.1) -> NetworkBatchTrial:
    return NetworkBatchTrial(
        batch_size=batch_size,
        elapsed_seconds=elapsed,
        waybill_count=100,
        ui_response_p95_seconds=ui_p95,
    )


def test_third_trial_is_only_required_after_more_than_fifteen_percent_spread() -> None:
    assert not requires_third_trial((_trial(20, 100), _trial(20, 115)))
    assert requires_third_trial((_trial(20, 100), _trial(20, 116)))


def test_summary_uses_middle_value_for_three_trials() -> None:
    summary = summarize_trials(
        (_trial(50, 120), _trial(50, 90), _trial(50, 100))
    )

    assert summary.median_elapsed_seconds == 100
    assert summary.median_waybills_per_minute == pytest.approx(60)
    assert summary.trial_count == 3


def test_selector_prefers_smaller_batch_when_speed_is_within_five_percent() -> None:
    selected = select_default_batch_size(
        (
            NetworkBatchSummary(20, 2, 102, 98, 0.2),
            NetworkBatchSummary(50, 2, 97, 103, 0.2),
            NetworkBatchSummary(100, 2, 94, 105, 0.2),
        )
    )

    assert selected == 50


def test_selector_rejects_fastest_batch_when_ui_gate_fails() -> None:
    selected = select_default_batch_size(
        (
            NetworkBatchSummary(20, 2, 120, 80, 0.2),
            NetworkBatchSummary(50, 2, 100, 100, 0.2),
            NetworkBatchSummary(100, 2, 80, 125, 0.6),
        )
    )

    assert selected == 50


def test_selector_allows_a_failed_batch_size_to_be_disqualified() -> None:
    selected = select_default_batch_size(
        (
            NetworkBatchSummary(20, 2, 110, 90, 0.2),
            NetworkBatchSummary(50, 2, 97, 103, 0.2),
        ),
        ineligible_batch_sizes=frozenset({100}),
    )

    assert selected == 50


def test_selector_requires_every_batch_size_to_be_accounted_for() -> None:
    with pytest.raises(ValueError, match="cover or explicitly disqualify"):
        select_default_batch_size(
            (
                NetworkBatchSummary(20, 2, 102, 98, 0.2),
                NetworkBatchSummary(50, 2, 97, 103, 0.2),
            )
        )
