# ADR-025: Isolated Chengfeng Live Read Transport

## Context

The discovery-derived candidate in ADR-024 defines the minimum Chengfeng read
surface, but selecting a contract file is not enough to make live collection
safe. A normal Chengfeng page can continue background traffic after human
login, signed image URLs are sensitive and short lived, and returning raw
responses through worker stdout would leak platform data into protocol logs.

## Decision

Require an explicit immutable selection of one content-addressed frozen
candidate before live validation. Selection rechecks the contract file,
canonical contract, freeze evidence, discovery binding, and safety flags. It
is offline and idempotent and does not pass the real-request gate.

Use browser worker protocol version 2 for formal reads. When human control is
returned, close every Chengfeng page and keep one `about:blank` page with
network requests aborted. Formal collection does not navigate a page or run
page scripts. It uses only three typed commands:

- bounded pending-settlement list JSON;
- one numeric waybill-detail JSON;
- one response-derived signed ticket image.

Every command is checked by the existing frozen manifest firewall before it is
sent. Redirects are disabled. JSON and image size and media type are bounded.
The worker writes a response to a controlled staging directory under the
selected DaHe data root and returns only its relative path, size, media type,
status, and SHA-256. The main process resolves the path again, rejects links or
boundary changes, rehashes the file, normalizes it through the existing
connector, and removes the staged response immediately.

Keep each complete signed image URL only in main-process memory behind an
opaque capability bound to the detail request, sanitized response, exact URL
hash, origin, and a five-minute expiry. The private NDJSON request may carry
the URL to the worker, but worker stdout, logs, database records, checkpoints,
and evidence must not return or persist it. Restart or expiry requires a new
detail read.

## Consequences

Formal collection cannot inherit uncontrolled background requests from the
human page. A worker crash may leave only bounded staging data in the new
application's directory; startup recovery may remove it after validating the
boundary. Signed image reads cannot be resumed after restart without repeating
the detail read. The implementation has more protocol and cleanup checks, but
it provides a replayable deny-by-default boundary and keeps raw platform data
out of diagnostics. A fresh authorized live validation is still required
before the real-request-contract gate can pass.
