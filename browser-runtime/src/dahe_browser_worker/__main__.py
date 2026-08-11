from __future__ import annotations

import json
import queue
import sys
from contextlib import suppress
from threading import Event, Lock, Thread
from typing import Any

from dahe_browser_worker.engine import (
    BrowserEngine,
    BrowserReadError,
    LoginEntryError,
    run_smoke,
)
from dahe_browser_worker.protocol import (
    PROTOCOL_VERSION,
    AbortCommand,
    BrowserCommand,
    CaptureStartCommand,
    CaptureStopCommand,
    CloseCommand,
    FreezeHumanSessionCommand,
    HandoffOperationalSessionCommand,
    InitializeCommand,
    InitializeHeadlessCommand,
    ParkOperationalSessionCommand,
    PrepareAutomatedCommand,
    PrepareDailyCommand,
    PrepareDailyFromAutomatedCommand,
    PrepareOperationalCompatCommand,
    PrepareSettlementFilterHandoffCommand,
    ProbeSettlementViewsCommand,
    ProtocolError,
    ReadDailyJsonCommand,
    ReadImageCommand,
    ReadJsonCommand,
    ReadOperationalBatchCommand,
    ResumeHumanSessionCommand,
    SmokeCommand,
    StatusCommand,
    parse_command,
    response,
)

_STOP = object()


def main() -> int:
    commands: queue.Queue[BrowserCommand | object] = queue.Queue()
    write_lock = Lock()
    active_lock = Lock()
    active_request_id: str | None = None
    active_abort: Event | None = None
    reader_failed = Event()

    def emit(payload: str | dict[str, object]) -> None:
        line = (
            payload
            if isinstance(payload, str)
            else json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        with write_lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def read_commands() -> None:
        nonlocal active_request_id, active_abort
        try:
            for line in sys.stdin:
                try:
                    command = parse_command(line)
                except ProtocolError:
                    reader_failed.set()
                    commands.put(_STOP)
                    return
                if isinstance(command, AbortCommand):
                    with active_lock:
                        accepted = (
                            active_request_id == command.target_request_id
                            and active_abort is not None
                        )
                        if accepted:
                            active_abort.set()
                    emit(
                        {
                            "schema_version": PROTOCOL_VERSION,
                            "frame_kind": "abort_ack",
                            "request_id": command.request_id,
                            "target_request_id": command.target_request_id,
                            "accepted": accepted,
                        }
                    )
                    continue
                commands.put(command)
        finally:
            commands.put(_STOP)

    reader = Thread(
        target=read_commands,
        name="browser-worker-stdin",
        daemon=True,
    )
    reader.start()
    engine = BrowserEngine()
    should_close = False
    while not should_close:
        queued = commands.get()
        if queued is _STOP:
            break
        command = queued
        assert not isinstance(command, AbortCommand)
        cancel_event = Event()
        if isinstance(command, ReadOperationalBatchCommand):
            with active_lock:
                active_request_id = command.request_id
                active_abort = cancel_event
        try:
            output = _execute_command(
                engine,
                command,
                cancel_event=cancel_event,
                emit=emit,
            )
        except Exception as exc:
            if (
                isinstance(command, ReadOperationalBatchCommand)
                and isinstance(exc, BrowserReadError)
                and exc.code == "browser_read_cancelled"
            ):
                # Abort erases the job-owned request authority and controlled tab,
                # while preserving the visible human platform window.
                with suppress(BrowserReadError):
                    engine.park_operational_session()
            if isinstance(exc, BrowserReadError):
                error_code = exc.code
                discovery = exc.safe_discovery
            elif isinstance(exc, LoginEntryError):
                error_code = "browser_login_entry_failed"
                discovery = None
            elif isinstance(
                command,
                (InitializeCommand, InitializeHeadlessCommand),
            ):
                error_code = "browser_initialize_failed"
                discovery = None
            else:
                error_code = "browser_smoke_failed"
                discovery = None
            output = response(
                command,
                ok=False,
                selected_browser=engine.selected_browser,
                error_code=error_code,
                discovery=discovery,
                browser_open=engine.is_open(),
                read_result=None,
                prepare_result=None,
                batch_result=None,
            )
        finally:
            if isinstance(command, ReadOperationalBatchCommand):
                with active_lock:
                    active_request_id = None
                    active_abort = None
        emit(output)
        should_close = isinstance(command, CloseCommand)
    engine.close()
    return 2 if reader_failed.is_set() else 0


def _execute_command(
    engine: BrowserEngine,
    command: BrowserCommand,
    *,
    cancel_event: Event,
    emit: Any,
) -> str:
    prepare_result = None
    batch_result = None
    if isinstance(command, SmokeCommand):
        selected = run_smoke(command)
        discovery = None
        browser_open = None
        read_result = None
    elif isinstance(command, (InitializeCommand, InitializeHeadlessCommand)):
        selected = engine.initialize(command)
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, CaptureStartCommand):
        engine.start_capture()
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, CaptureStopCommand):
        discovery = engine.stop_capture()
        selected = engine.selected_browser
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, FreezeHumanSessionCommand):
        engine.freeze_human_session()
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, ResumeHumanSessionCommand):
        engine.resume_human_session()
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, HandoffOperationalSessionCommand):
        engine.handoff_operational_session()
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, ParkOperationalSessionCommand):
        engine.park_operational_session()
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, ProbeSettlementViewsCommand):
        discovery = [engine.probe_settlement_views()]
        selected = engine.selected_browser
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, (ReadJsonCommand, ReadDailyJsonCommand, ReadImageCommand)):
        read_result = engine.read(command)
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
    elif isinstance(command, ReadOperationalBatchCommand):
        def progress(phase: str, completed: int, total: int) -> None:
            emit(
                {
                    "schema_version": PROTOCOL_VERSION,
                    "frame_kind": "progress",
                    "request_id": command.request_id,
                    "phase": phase,
                    "completed": completed,
                    "total": total,
                }
            )

        batch_result = engine.read_operational_batch(
            command,
            abort_event=cancel_event,
            progress_callback=progress,
        )
        read_result = None
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
    elif isinstance(command, PrepareAutomatedCommand):
        prepare_result = engine.prepare_automated(scope=command.scope)
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, PrepareOperationalCompatCommand):
        prepare_result = engine.prepare_operational_compat()
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, PrepareSettlementFilterHandoffCommand):
        prepare_result = engine.prepare_settlement_filter_handoff(
            command.waybill_numbers
        )
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, PrepareDailyCommand):
        discovery = [engine.prepare_daily()]
        selected = engine.selected_browser
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, PrepareDailyFromAutomatedCommand):
        discovery = [engine.prepare_daily_from_automated()]
        prepare_result = engine.daily_preparation_evidence()
        selected = engine.selected_browser
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, StatusCommand):
        selected = engine.selected_browser
        discovery = None
        browser_open = engine.is_open()
        read_result = None
    elif isinstance(command, CloseCommand):
        engine.close()
        selected = None
        discovery = None
        browser_open = False
        read_result = None
    else:
        raise ProtocolError("unsupported command")
    return response(
        command,
        ok=True,
        selected_browser=selected,
        discovery=discovery,
        browser_open=browser_open,
        read_result=read_result,
        prepare_result=prepare_result,
        batch_result=batch_result,
    )


if __name__ == "__main__":
    raise SystemExit(main())
