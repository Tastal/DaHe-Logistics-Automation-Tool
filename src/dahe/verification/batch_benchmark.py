from __future__ import annotations

from dataclasses import dataclass
from statistics import median

ALLOWED_NETWORK_BATCH_SIZES = (20, 50, 100)


@dataclass(frozen=True, slots=True)
class NetworkBatchTrial:
    batch_size: int
    elapsed_seconds: float
    waybill_count: int
    ui_response_p95_seconds: float
    retries: int = 0
    committed_batches: int = 0

    def __post_init__(self) -> None:
        if self.batch_size not in ALLOWED_NETWORK_BATCH_SIZES:
            raise ValueError("unsupported network batch size")
        if self.elapsed_seconds <= 0:
            raise ValueError("elapsed_seconds must be positive")
        if self.waybill_count <= 0:
            raise ValueError("waybill_count must be positive")
        if self.ui_response_p95_seconds < 0:
            raise ValueError("ui_response_p95_seconds cannot be negative")
        if self.retries < 0 or self.committed_batches < 0:
            raise ValueError("trial counters cannot be negative")

    @property
    def waybills_per_minute(self) -> float:
        return self.waybill_count * 60.0 / self.elapsed_seconds


@dataclass(frozen=True, slots=True)
class NetworkBatchSummary:
    batch_size: int
    trial_count: int
    median_elapsed_seconds: float
    median_waybills_per_minute: float
    worst_ui_response_p95_seconds: float


def requires_third_trial(trials: tuple[NetworkBatchTrial, ...]) -> bool:
    if len(trials) != 2:
        return False
    first, second = (trial.elapsed_seconds for trial in trials)
    return abs(first - second) / min(first, second) > 0.15


def summarize_trials(
    trials: tuple[NetworkBatchTrial, ...],
) -> NetworkBatchSummary:
    if len(trials) < 2:
        raise ValueError("at least two trials are required")
    sizes = {trial.batch_size for trial in trials}
    if len(sizes) != 1:
        raise ValueError("all trials must use one batch size")
    return NetworkBatchSummary(
        batch_size=trials[0].batch_size,
        trial_count=len(trials),
        median_elapsed_seconds=median(
            trial.elapsed_seconds for trial in trials
        ),
        median_waybills_per_minute=median(
            trial.waybills_per_minute for trial in trials
        ),
        worst_ui_response_p95_seconds=max(
            trial.ui_response_p95_seconds for trial in trials
        ),
    )


def select_default_batch_size(
    summaries: tuple[NetworkBatchSummary, ...],
    *,
    ineligible_batch_sizes: frozenset[int] = frozenset(),
    maximum_ui_p95_seconds: float = 0.5,
    equivalent_speed_fraction: float = 0.05,
) -> int:
    summary_sizes = {summary.batch_size for summary in summaries}
    allowed_sizes = set(ALLOWED_NETWORK_BATCH_SIZES)
    if (
        not ineligible_batch_sizes <= allowed_sizes
        or summary_sizes & ineligible_batch_sizes
        or summary_sizes | set(ineligible_batch_sizes) != allowed_sizes
    ):
        raise ValueError(
            "summaries must cover or explicitly disqualify 20, 50, and 100"
        )
    eligible = tuple(
        summary
        for summary in summaries
        if summary.worst_ui_response_p95_seconds <= maximum_ui_p95_seconds
    )
    if not eligible:
        raise ValueError("no batch size meets the UI response gate")
    fastest_rate = max(
        summary.median_waybills_per_minute for summary in eligible
    )
    equivalent = tuple(
        summary
        for summary in eligible
        if (
            fastest_rate - summary.median_waybills_per_minute
        ) / fastest_rate
        < equivalent_speed_fraction
    )
    return min(summary.batch_size for summary in equivalent)
