# ADR-023: Fixed Human Login Entry

## Context

ADR-022 prohibited programmatic navigation while a person owned the login
window. The first implementation therefore launched a valid isolated browser
at `about:blank` and expected a finance user to know and enter the platform
address. That behavior was safe at the protocol boundary but unusable and made
a successful browser launch look like a failure.

The legacy implementation provides read-only static evidence that the intended
starting point is Chengfeng's settlement page and that an unauthenticated
session redirects to a same-origin login path. No legacy process, database, or
browser profile is needed to use that evidence.

## Decision

Allow exactly one programmatic navigation when an authorized human-login
session starts. The browser worker owns the fixed Chengfeng settlement entry;
the local API and NDJSON command contain no URL field and expose no generic
navigation command. The worker accepts only the fixed HTTPS landing or its
same-origin login path, then brings the window to the front and yields control
to the person.

Keep discovery capture detached throughout login. After the initial landing,
no programmatic navigation is allowed until control is explicitly returned.
Launch Chromium with its sandbox enabled and without Playwright's fixed
emulated viewport. The page viewport must follow the actual Windows browser
window when it is maximized, restored, or resized. Treat an empty landing,
disallowed redirect, insecure URL, failed response, timeout, or browser process
failure as a technical startup failure: close the owned runtime, preserve the
access window for a safe retry while it remains valid, and show a specific
local error.

Yield human control as soon as the approved HTTPS main-document response
commits and its origin, path, protocol, and status pass validation. Do not wait
for page-wide `DOMContentLoaded` or unrelated third-party assets: the real
login page can remain usable even when an optional external resource is slow or
unavailable. Keep a bounded worker navigation deadline, and require the parent
process response deadline to be strictly longer so the supervisor cannot
terminate a valid in-flight navigation first.

Probe only whether the owned browser context still has an open page. If the
person closes the physical window or the status probe fails, terminate the
worker, reconcile the control record to `stopped`, and preserve an unexpired
access window for a new fixed-entry start. Closing a window is never treated as
a successful login return.

The offline runtime smoke remains an `about:blank` test. It proves installation,
process supervision, browser selection, and sandbox startup without contacting
Chengfeng. The fixed landing behavior is covered by contract tests and an
intercepted browser check; a real login still requires the fresh Loop 9 access
confirmation.

## Consequences

Finance users no longer need to know or type the platform address, and a blank
browser cannot be reported as a successful human-login start. Maximizing the
controlled window now gives Chengfeng the full available viewport instead of
leaving a fixed-width page inside a larger window. The URL cannot be changed
through configuration, UI input, or a worker message; a future platform entry
change requires a reviewed code and contract update. This exception does not
grant general navigation, does not permit platform writes, and does not weaken
the separation between login and discovery capture.
