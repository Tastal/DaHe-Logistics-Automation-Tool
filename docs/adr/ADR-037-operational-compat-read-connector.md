# ADR-037: Operational Compatibility Read Connector

## Context

The strict Loop 9 connector successfully established isolated login, browser
ownership, request fencing, and read-contract evidence, but its reconstructed
pending-settlement request returned an authenticated empty business scope while
the official page showed current billable waybills. Continuing to widen the
formal contract would block urgent daily work and would weaken evidence
semantics.

The legacy application obtained reliable list scope by letting the official
page submit its real reset query, capturing that request and response, and
reusing the request inside the same browser session. Its persistent profile,
stored credentials, fixed browser choice, state machine, and data directories
remain unsuitable for reuse.

## Decision

Keep `ChengfengReadPort` as the only downstream platform interface and provide
two explicit adapters:

- `operational_compat`, shown as Business Connection and selected by default
  for the company deployment;
- `strict_shadow`, shown as Validation Connection and retained for Loop 9
  formal evidence.

The compatibility adapter runs only inside DaHe's isolated browser worker. It
selects the fixed current-settlement and waybill controls, resets filters, and
allows the exact approved list POST to complete normally. The successful first
request and response become session-private authority. Request values, session
headers, and signed image URLs never leave the worker. Pagination changes only
the captured page-number and page-size fields. Detail and image reads retain
the existing identity, redirect, media, size, and hash checks.

Install a deny-by-default route before business automation. Permit required
static resources and the exact list, detail, and response-derived image reads;
deny every other API request and every unapproved POST, PUT, PATCH, or DELETE
before sending. Do not add settlement, payment, receipt cancellation, or
arbitrary request surfaces.

Bind one connector mode to each job. Mode changes require an idle scheduler and
a closed platform browser session. Never fall back silently between adapters.
An operational session lasts until application or browser shutdown, with a
maximum of one working day, and reuses the isolated persistent login when valid.

## Consequences

Daily work can use the official page's actual account-specific query semantics
without duplicating OCR, audit, persistence, or job logic. The compatibility
path is intentionally more dependent on current page controls than the formal
connector, so selector or response changes fail as technical diagnostics.

Compatibility results are excluded from the formal locked set, real shadow
batch, request-contract gate, and `shadow_accepted` evidence. Passing its
operational checks may establish only `operational_read_only_ready`; Loop 9
remains in progress until the strict gates pass independently.
