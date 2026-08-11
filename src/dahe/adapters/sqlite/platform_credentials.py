from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.engine import Connection

from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    PLATFORM_CREDENTIAL_CONFIG,
    PLATFORM_CREDENTIAL_IDEMPOTENCY,
)
from dahe.adapters.windows.credential_manager import CHENGFENG_CREDENTIAL_TARGET
from dahe.application.chengfeng.credential_service import (
    PlatformCredentialConfig,
    PlatformCredentialConflictError,
)
from dahe.ports.jobs import IdempotencyConflictError


class SqlitePlatformCredentialConfigStore:
    def __init__(self, runtime: SqliteRuntime) -> None:
        self._engine = runtime.engine
        self._commit_gate = runtime.commit_gate

    @staticmethod
    def _config(connection: Connection) -> PlatformCredentialConfig:
        row = (
            connection.execute(
                select(PLATFORM_CREDENTIAL_CONFIG).where(
                    PLATFORM_CREDENTIAL_CONFIG.c.config_id == 1
                )
            )
            .mappings()
            .one()
        )
        if str(row["credential_reference"]) != CHENGFENG_CREDENTIAL_TARGET:
            raise PlatformCredentialConflictError(
                "stored credential reference is invalid"
            )
        return PlatformCredentialConfig(
            configured=bool(row["configured"]),
            masked_username=(
                None
                if row["masked_username"] is None
                else str(row["masked_username"])
            ),
            record_version=int(row["record_version"]),
        )

    def get(self) -> PlatformCredentialConfig:
        with self._engine.connect() as connection:
            return self._config(connection)

    def replay(
        self,
        *,
        operation: str,
        idempotency_key: str,
        request_fingerprint: str,
    ) -> PlatformCredentialConfig | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    select(PLATFORM_CREDENTIAL_IDEMPOTENCY).where(
                        PLATFORM_CREDENTIAL_IDEMPOTENCY.c.operation
                        == operation,
                        PLATFORM_CREDENTIAL_IDEMPOTENCY.c.idempotency_key
                        == idempotency_key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            if str(row["request_fingerprint"]) != request_fingerprint:
                raise IdempotencyConflictError(
                    "the idempotency key belongs to another credential request"
                )
            current = self._config(connection)
            if current.record_version < int(row["result_record_version"]):
                raise PlatformCredentialConflictError(
                    "stored credential replay version is invalid"
                )
            result_configured = row["result_configured"]
            if result_configured is None:
                if current.record_version != int(row["result_record_version"]):
                    raise PlatformCredentialConflictError(
                        "legacy credential replay result is unavailable"
                    )
                return current
            return PlatformCredentialConfig(
                configured=bool(result_configured),
                masked_username=(
                    None
                    if row["result_masked_username"] is None
                    else str(row["result_masked_username"])
                ),
                record_version=int(row["result_record_version"]),
            )

    def commit(
        self,
        *,
        operation: str,
        configured: bool,
        masked_username: str | None,
        expected_record_version: int,
        idempotency_key: str,
        request_fingerprint: str,
    ) -> PlatformCredentialConfig:
        timestamp = datetime.now(UTC).isoformat()
        with self._commit_gate.transaction(self._engine) as connection:
            replay = (
                connection.execute(
                    select(PLATFORM_CREDENTIAL_IDEMPOTENCY).where(
                        PLATFORM_CREDENTIAL_IDEMPOTENCY.c.operation
                        == operation,
                        PLATFORM_CREDENTIAL_IDEMPOTENCY.c.idempotency_key
                        == idempotency_key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                if str(replay["request_fingerprint"]) != request_fingerprint:
                    raise IdempotencyConflictError(
                        "the idempotency key belongs to another credential request"
                    )
                result_configured = replay["result_configured"]
                if result_configured is None:
                    return self._config(connection)
                return PlatformCredentialConfig(
                    configured=bool(result_configured),
                    masked_username=(
                        None
                        if replay["result_masked_username"] is None
                        else str(replay["result_masked_username"])
                    ),
                    record_version=int(replay["result_record_version"]),
                )
            current = self._config(connection)
            if current.record_version != expected_record_version:
                raise PlatformCredentialConflictError(
                    "credential record version changed"
                )
            next_version = expected_record_version + 1
            changed = connection.execute(
                update(PLATFORM_CREDENTIAL_CONFIG)
                .where(
                    PLATFORM_CREDENTIAL_CONFIG.c.config_id == 1,
                    PLATFORM_CREDENTIAL_CONFIG.c.record_version
                    == expected_record_version,
                )
                .values(
                    configured=1 if configured else 0,
                    masked_username=masked_username,
                    record_version=next_version,
                    updated_at=timestamp,
                )
            )
            if changed.rowcount != 1:
                raise PlatformCredentialConflictError(
                    "credential record version changed"
                )
            connection.execute(
                PLATFORM_CREDENTIAL_IDEMPOTENCY.insert().values(
                    operation=operation,
                    idempotency_key=idempotency_key,
                    request_fingerprint=request_fingerprint,
                    result_record_version=next_version,
                    result_configured=1 if configured else 0,
                    result_masked_username=masked_username,
                    created_at=timestamp,
                )
            )
            return self._config(connection)
