# ADR-030: Separate Loop 9 Daily Read Contract

## Context

Loop 9 originally validated only the freight-audit read path. The user has now
required the loading and unloading detail module to obtain real Chengfeng data
before Loop 9 closes, while its full UI, Excel output, and production workflow
remain deferred.

Chengfeng exposes different list endpoints and request semantics for pending
settlement waybills and general waybill management. A zero pending-settlement
result does not prove that the platform has no waybills. Reusing one list as a
silent fallback for the other would make counts and business meaning
untrustworthy.

## Decision

Loop 9 will validate two separate deny-by-default list contracts:

- pending settlement for the freight-audit workspace;
- waybill management for loading and unloading data acquisition.

Both contracts share the controlled browser session, browser resource lease,
detail transport, response-derived image capability, content-addressed
evidence store, and cooperative scheduler. They do not share list request
bodies, response decoders, domain records, checkpoints, or persistence tables.

The daily slice included in Loop 9 is limited to:

- a frozen business-date query scope;
- bounded list pagination repeated twice per snapshot, with exact identity
  reconciliation before the snapshot is committed;
- detail and available ticket-image reads;
- immutable nullable observations and revisions;
- restartable checkpoints and resource-coordination evidence.

Formal daily validation uses the latest fully completed business day. It
requires three independently captured snapshots with the same frozen query
scope, contract, count, and identity set. Discovery, daily validation, the new
50-waybill locked set, and the 30-waybill shadow set are separately classified
and must pass exact and perceptual-overlap checks against development and
historical exclusions.

It does not include the business page, OCR field completion, Excel generation,
formal report paths, historical migration, automatic cleanup, or any platform
write.

An empty pending-settlement list remains an explicit result. A non-empty daily
list may validate the shared detail and image contracts, but it must not be
reported as a non-empty settlement result.

## Consequences

- `daily` can enter `shadow` for this bounded backend capability before the
  sixth development stage.
- The sixth stage starts from the accepted read adapter and adds OCR, business
  date assignment, UI, Excel, refresh, history, and cleanup behavior.
- Discovery, locked-set, settlement-shadow, and daily-validation samples remain
  separately classified, build-bound, source-bound, hashed, and replayable.
- The implementation must not create a second scheduler or general-purpose
  platform request endpoint.
