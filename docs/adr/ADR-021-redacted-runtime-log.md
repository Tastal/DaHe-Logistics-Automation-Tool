# ADR-021: Redacted local runtime log

## Context

The deployment computer needs enough live and historical runtime detail to diagnose failures without opening a development terminal. Raw process output can contain credentials, maintenance codes, absolute paths, OCR text, or protocol messages.

## Decision

- Store runtime events as segmented JSONL under the application's configured log directory.
- Retain at most seven days, five megabytes per segment, and fifty megabytes in total.
- Use a fixed event schema and sanitize application and owned-process stdout and stderr before persistence or streaming.
- Never persist protocol stdout, raw OCR text, credentials, maintenance codes, absolute paths, or URL query values.
- Expose session-protected read, SSE, and UTF-8 export endpoints.
- Display the live terminal inside System Diagnostics rather than adding another navigation destination.
- Treat log persistence failures as diagnostic faults that cannot change business outcomes or stop committed work.
- Keep Playwright as a development-only dependency for repeatable Edge-based layout checks; do not ship it as an operator-console runtime dependency.

## Consequences

The operator can copy or export useful runtime evidence from another computer. The log is intentionally not a literal terminal transcript, and protocol payloads remain available only through their approved structured evidence stores.

This change is a post-Loop-8 UX and diagnostics improvement. It does not change the accepted Loop 8 ledger or start Loop 9.
