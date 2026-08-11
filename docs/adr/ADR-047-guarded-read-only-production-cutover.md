# ADR-047: Guarded Read-only Production Cutover

## Context

The strict Loop 9 path collected 100 waybills and 200 ticket images but the
result had already influenced connector development and could not provide the
new unseen 50-waybill gate. Repeating another large strict capture and manual
review would delay the company's immediate need for a stable read-only tool.

The operational `batch_v1` connector already demonstrated complete dynamic
pagination, bounded fifteen-item commits, and materially faster collection.
The product still cannot accept a false automatic pass, a Chengfeng write, a
credential leak, a silently overwritten report, or an unrecoverable local
database.

## Decision

Keep the historical strict evidence and `shadow_accepted` validator unchanged
as a future verification path. Do not claim that the failed or development
sets passed. Add a separate production outcome with two explicit states:
`operational_read_only_with_guard` and
`operational_read_only_accepted`.

The first state routes every machine-normal item to the existing two-button
manual decision while the first thirty unique production waybills are reviewed.
The stable identity is an irreversible hash of the normalized waybill number;
recapturing the same waybill remains protected but cannot consume another gate
slot or advance the displayed progress. If no
machine-normal item is marked as a problem, the guard releases later protected
normal items and moves to the accepted state. Any false normal keeps the guard
active for subsequent items. The guard records only item, action, version, and
time identities; it does not add people or operator fields.

An operational cutover may be published with the guard still in progress when
the platform exposes fewer than thirty unique unsettled waybills. Its evidence
must retain the actual registered and reviewed counts and the status remains
`operational_read_only_with_guard`; incomplete protection is never represented
as the accepted state.

Production uses only `batch_v1`, the existing local OCR runtimes, the existing
scheduler, and the existing SQLite database. It enables `audit` and `daily` in
operational mode while settlement and dispatch remain disabled. Chengfeng
remains deny-by-default and read-only.

The settlement capture must sustain at least twenty-one waybills per minute
and at least three times the recorded 44m31s/315-waybill legacy baseline when
the current dynamic list contains at least one complete fifteen-item batch.
A smaller live list records its end-to-end rate but does not apply that
throughput threshold because fixed browser startup dominates the sample; it
still has to reconcile every identity, detail, ticket and request-audit event,
while the existing 315-item `batch_v1` run remains the comparable performance
evidence. A daily capture records throughput for diagnosis but does not apply
the settlement-specific threshold: its release gate is complete business-day
reconciliation, terminal OCR outcomes, and a verified workbook.

One operational batch has an eight-minute owned Worker deadline within the
ten-minute browser-control lease. A whole-batch Worker timeout is not replayed
inside that same lease: the Job remains at its last committed batch and moves
to external waiting. Bounded downshift retries remain available for explicit
rate limiting and transient server responses, but cannot create a control-lease
expiry loop.

Daily Excel output uses one confirmed settings record and XlsxWriter 3.2.9.
Files are written to a sibling temporary file, reopened and checked, then
renamed atomically. Stored file and data hashes prevent overwriting a workbook
changed outside DaHe. The first file remains pending until a person confirms
it; an externally changed file can only be preserved as a new version or left
untouched.

For the operational daily read, the exact page-owned request remains the
authority for the configured location and date scope. Chengfeng may omit the
location display field from returned rows, render it with a different label,
or return a broader candidate date set for local filtering, so those response
echoes are not release gates. Returned loading times must still be parseable;
the application's authoritative 14:00 business-window filter excludes wider
candidates before detail reads, OCR, or report materialization. This change
does not relax the approved host, path, method, request scope, reconciliation,
or zero-write boundaries.

After a guarded replacement instance registers for the same data root, it
marks every other database instance still recorded as running as crashed, not
only the instance retained by the latest lock-file pointer. Active atomic
leases remain fenced until their existing expiry, after which recovery
abandons only the uncommitted attempt and preserves committed batches. This
allows forced application termination and verification-tool interruption to
recover without inspecting or terminating unrelated processes.

## Consequences

- The company can use the new system before the separate strict unseen-set
  program is complete, without representing operational evidence as formal
  accuracy acceptance.
- The first thirty items add manual work, and a detected false normal extends
  that work until a later fix passes the guard again.
- Production deployment is initially a local versioned release directory and
  virtual environment, not an installer or auto-updater.
- Rollback stops DaHe-owned work and returns to the legacy program without
  deleting or translating either system's data.
- This ADR follows ADR-046 because ADR numbers 044 through 046 already exist in
  the current baseline; it implements the product decision originally planned
  as the next production-cutover ADR without rewriting those accepted records.
