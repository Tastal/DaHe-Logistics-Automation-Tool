# ADR-026: Worker-Private Chengfeng Session Continuity

## Context

The fixed Chengfeng page can remain visibly logged in while direct requests
made through the same Playwright browser context receive an authentication
business response. Browser cookies alone are insufficient because the page
adds session headers to its API requests. Sending those values through the
main process, NDJSON protocol, logs, database, or evidence would weaken the
credential boundary established for Loop 9.

## Decision

Allow only the isolated browser Worker to observe a POST request constructed
by the fixed pending-settlement page for the exact approved list origin and
path. Copy a bounded, filtered set of that request's headers into Worker
memory. This header decision does not authorize retaining its body; ADR-028
separately permits only three bounded list-control values. Exclude cookies, host and length headers,
connection headers, compression headers, proxy authorization, and browser
fetch metadata.

After human control has been returned and the coordinator has acquired
automated control, the Worker may wait for the fixed Waybill View and Query
controls. If the page has not naturally constructed the approved request,
install a temporary route that aborts all network traffic, select the waybill
view, reset the filters, and click Query once. The route may copy headers from the exact approved
path before aborting it. ADR-028 permits the single bounded `t` cache query
to remain Worker-private and to be reused only for the formal list read. No request created by this
local trigger may reach Chengfeng, and no response is read or retained.

The private headers may be attached only to the exact approved Chengfeng list
and detail JSON requests. They must never be attached to ticket image
requests. Header names and values are not returned through the Worker
protocol, logged, persisted, exported, included in diagnostics, or added to
evidence. Closing the context, ending the session, or failing the Worker
clears the in-memory copy.

Before human pages are closed for an automated formal read, wait for a bounded
period for session continuity to be established. If the fixed button is
unavailable or no eligible request is constructed, fail as login required. Do
not inspect login or authentication requests, broaden the accepted path,
navigate automatically, let the local trigger reach the network, or fall back
to credential probing.

## Consequences

Formal reads can reuse the authenticated state that the Chengfeng application
itself established while keeping credential material inside one short-lived
process. The Worker now contains a narrowly scoped credential-handling
responsibility and therefore requires exact-path tests, non-persistence tests,
image-header isolation tests, bounded waiting, and close-time clearing.
Changes to Chengfeng authentication may still fail closed and require another
explicitly authorized investigation.
