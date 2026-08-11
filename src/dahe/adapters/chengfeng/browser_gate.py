from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from dahe.adapters.sqlite.browser_control import (
    BrowserControlStore,
    NavigationRejectedError,
)
from dahe.adapters.sqlite.platform_access import (
    PlatformAccessConflictError,
    SqlitePlatformAccessRepository,
)
from dahe.application.chengfeng.access_window import AccessWindowError
from dahe.ports.chengfeng import BrowserCommandAuthority


class SqliteBrowserNavigationAuthorizer:
    """Authorize one connector command against the current physical session."""

    def __init__(
        self,
        store: BrowserControlStore,
        *,
        access_repository: SqlitePlatformAccessRepository | None = None,
        build_sha256: str | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if (access_repository is None) != (build_sha256 is None):
            raise ValueError(
                "platform access repository and build identity must be "
                "configured together"
            )
        self._store = store
        self._access_repository = access_repository
        self._build_sha256 = build_sha256
        self._clock = clock

    def authorize(
        self,
        authority: BrowserCommandAuthority,
        *,
        now: datetime | None = None,
    ) -> None:
        authorization_time = self._clock() if now is None else now
        if self._access_repository is not None:
            windows = self._access_repository.unconsumed_for_job(
                session_id=authority.session_id,
                job_id=authority.job_id,
            )
            if len(windows) != 1 or self._build_sha256 is None:
                raise NavigationRejectedError(
                    "platform access window is unavailable"
                )
            window = windows[0]
            try:
                self._access_repository.authorize(
                    access_window_id=window.access_window_id,
                    purpose=window.purpose,
                    job_id=authority.job_id,
                    session_id=authority.session_id,
                    build_sha256=self._build_sha256,
                    now=authorization_time,
                )
            except (
                AccessWindowError,
                PlatformAccessConflictError,
                ValueError,
            ) as exc:
                raise NavigationRejectedError(
                    "platform access window is invalid"
                ) from exc
        self._store.authorize_navigation(
            session_id=authority.session_id,
            instance_id=authority.instance_id,
            worker_id=authority.worker_id,
            job_id=authority.job_id,
            control_epoch=authority.control_epoch,
            fencing_token=authority.fencing_token,
            now=authorization_time,
        )
