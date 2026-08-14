# ADR-052: Backend login coordination and local shutdown

## Decision

Operational login recovery is a backend-owned, one-shot process bound to the current Job. The coordinator reuses a valid session or saved credential, opens at most one visible login window when human input is required, waits for a stable logged-in state, and returns control exactly once. Frontend refreshes and SSE reconnects are read-only; they cannot open a browser, navigate, or return control.

Login window closure, CAPTCHA, credential rejection, timeout, and control-return failure stop automatic retries with distinct diagnostics. A later retry requires an explicit business action and cannot inherit a stale fencing token.

The local console also exposes an idempotent, same-origin shutdown action. Shutdown stops new work, preserves committed results and checkpoints, and asks the current server instance to close only its registered browser, OCR, scheduler, and logging resources. After its scheduler and owned Workers stop, the instance terminalizes active settlement and daily browser reads as cancelled with a fixed finish time. A restart does not resume them. If the instance disappears without this explicit shutdown intent, the next startup fails the orphaned browser read as interrupted and releases its stale browser authority. A five-second watchdog may force only the current DaHe server to exit; it does not enumerate or terminate unknown processes.

## Consequences

- Rendering or refreshing a page cannot create a browser open-close loop.
- Login lifecycle tests belong to the backend contract rather than UI timers.
- The browser page can show a stable terminal message after the local service exits.
- A normal console exit freezes browser-read elapsed time; a crash cannot appear as a continuously running read after restart.
- Shutdown remains unavailable in embedded test modes that do not register a server callback.
