from dahe.adapters.chengfeng.browser_runtime import (
    OPERATIONAL_BATCH_WORKER_TIMEOUT_SECONDS,
    PREPARE_OPERATIONAL_WORKER_TIMEOUT_SECONDS,
)
from dahe.application.chengfeng.settlement_live_execution import (
    _CONTROL_TTL as SETTLEMENT_CONTROL_TTL,
)
from dahe.application.daily.live_execution import (
    _CONTROL_TTL as DAILY_CONTROL_TTL,
)


def test_operational_browser_control_outlives_all_batch_retries() -> None:
    required_seconds = (
        PREPARE_OPERATIONAL_WORKER_TIMEOUT_SECONDS
        + (3 * OPERATIONAL_BATCH_WORKER_TIMEOUT_SECONDS)
        + 60
    )

    assert SETTLEMENT_CONTROL_TTL.total_seconds() >= required_seconds
    assert DAILY_CONTROL_TTL.total_seconds() >= required_seconds
