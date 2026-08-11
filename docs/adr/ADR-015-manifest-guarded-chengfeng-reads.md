# ADR-015: Manifest-Guarded Chengfeng Reads

## Context

Loop 5 needs an offline contract for Chengfeng waybill list, detail, and ticket
image reads. The repository does not contain an approved real host, endpoint,
payload, redirect, login, or response capture, and this Loop is not authorized
to log in or access the network.

A connector that accepts a generic URL or request payload would create a
platform-write surface and make offline tests unable to prove the effective
boundary. Treating upload slots or platform values as trusted document evidence
would also violate the audit contract.

## Decision

Use a versioned, sanitized synthetic manifest as the only Loop 5 connector
contract. The manifest fixes one HTTPS `.invalid` origin and exactly three read
operations. Each request is authorized only when origin, path, method,
parameter location, keys, values, and value types exactly match one declaration.
Redirects and undeclared requests are denied before the transport runs.

The frozen transport verifies fixture paths, stored bytes, decoded image bytes,
sizes, and SHA-256 identities, then replays them without opening a socket. The
public adapter exposes no generic request method and no settlement, payment, or
receipt-cancellation operation.

Browser navigation authority reuses the existing `BrowserControlSession` and
is fenced by session, instance, worker, job, control epoch, expiry, and a
process-local token. Every atomic read crosses the versioned NDJSON boundary,
is correlated to its originating command, and exposes only a command-scoped
staged file reference. The main process verifies the path, hash, size, media
signature, and browser authority before accepting immutable bytes. It removes
the command staging after consumption and recovers safe orphan staging when the
isolated runtime starts. Connector checkpoints are committed only after this
verification, with a final authority check inside the SQLite transaction. DNS
probing is diagnostic and non-blocking; login needed, page contract changed,
image timeout, transient network failure, and browser closure remain distinct
technical outcomes.

## Consequences

Loop 5 can prove its deny-by-default request surface, parsing, error classes,
redaction, and recovery behavior entirely offline without creating a second
scheduler or browser authority.

The synthetic contract does not prove compatibility with Chengfeng production.
A future real adapter requires explicit approval for a safe read-only capture,
sanitized frozen evidence, a verified request allowlist, and the same fencing
and no-write guarantees before it may replace the frozen transport.
