# ADR-022: Loop 9 Read-Only Browser Runtime

## Context

Loop 9 needs real Chengfeng reads without reusing the legacy browser, adding a
generic request surface, or installing Playwright into the main or OCR Python
environments. The available account is also used by the legacy application,
but the business owner will keep the legacy application stopped during every
approved real-data window and accepts that a new login may invalidate its saved
session.

## Decision

Run Playwright in a separately locked Python environment and communicate with
it only through a versioned NDJSON protocol. Store its persistent profile under
the new application's data root. Human login owns the browser until an explicit
handoff; automated navigation then requires the current fenced session, a
single-use purpose-bound access window, `shadow` mode, and an immutable
manifest whose exact read operations are enforced before transport.

Qualify the browser through the same restricted child environment used at
runtime. Discover a system Edge installation only from whitelisted Windows
Program Files roots; do not inherit the real user profile directory or hard-code
a developer-machine browser path. The installation manifest is valid only after
this isolated blank-page smoke passes.

Use the same account only under the recorded legacy-idle and session-risk
confirmations. Never inspect, copy, open, or modify the legacy profile. Contract
discovery data is development-only. The formal locked set and production-shadow
batch are captured after the executable contract is frozen and remain disjoint.

Separate login from contract discovery capture. Capture is disabled while the
person enters credentials. After login control is explicitly returned, the
person may start a `human_handoff` capture and manually perform only the required
read-only list, detail, and ticket views. The worker records request and response
shapes, not navigation instructions or values. Durable discovery evidence keeps
only normalized origins, fixed API paths, methods, parameter names, JSON field
paths and types, status codes, and hashes of image paths. It excludes headers,
session material, credentials, request and response values, raw responses, and
complete signed image URLs.

An image URL returned by a validated detail response is not converted into a
domain-wide permission. The connector issues a short-lived capability for the
exact complete URL hash, binds it to the authorized detail request and validated
response hash, and rejects every redirect or changed URL. Signed query text is
never included in the capability representation, logs, or durable diagnostics.

## Consequences

The default application remains offline and real access cannot be enabled by a
plain boolean or arbitrary URL. The browser runtime can be replaced or
qualified independently of OCR. Every real access window requires fresh user
confirmation, and resuming the legacy application may require a new manual
login. Discovery requires a short explicit manual viewing step and cannot infer
the contract from login traffic. Loop 7 history remains unchanged; Loop 9 must establish a new current
build locked-set gate before `shadow_accepted` is possible.
