# ADR-020: Use one freight workspace and retire active weight corrections

## Context

The operator console split audit, manual review, and settlement into separate
top-level pages. That duplicated lists and made a small single-computer product
feel like a large ERP. The accepted workflow only needs evidence comparison and
a local normal-or-problem decision. Editing a recognized weight in the console
does not match the current business process.

Loop 8 already sealed four historical correction actions. Rewriting or deleting
those rows would break accepted evidence and is unnecessary.

## Decision

- The user-facing audit and settlement flow is one `Freight settlement`
  workspace. Internal stages may keep the `audit.*` namespace.
- Every manual-review item offers `Confirm normal` and `Mark as problem`.
- The server derives a preset business reason from the current review reason.
  New manual decisions contain no corrected weight, note, or human identity.
- The active correction endpoint and write path are removed.
- Existing correction rows and sealed Loop 8 evidence remain byte-for-byte
  compatible and readable as legacy history. The repository rejects new
  correction actions without dropping the old database columns.
- Local decisions never modify OCR observations, platform weights, ticket
  images, or the Chengfeng platform.
- This is a post-Loop-8 UX change. It neither changes Loop 8 acceptance nor
  starts Loop 9.

## Consequences

Finance users make one direct business choice in the same page where they see
the evidence. A false-positive dismissal can produce a local normal result even
when the machine result requested review, so the action remains append-only,
versioned, idempotent, evidence-bound, and invalidated when evidence changes.

Historical correction values can still appear in the timeline with a legacy
label, but they cannot be edited, copied into a new decision, or used to reopen
the retired workflow.
