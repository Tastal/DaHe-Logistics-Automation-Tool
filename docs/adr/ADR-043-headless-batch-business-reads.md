# ADR-043: Headless Batch Business Reads

## Context

The operational Chengfeng connector completed a 315-waybill read in about
forty-five minutes. It advanced and persisted one browser operation at a time,
which produced nearly two thousand checkpoints and kept the shared platform
account occupied for too long. The existing human-handoff session also added
steps that a small single-company deployment does not need for every read.

DaHe still needs the strict Loop 9 connector and its fine-grained formal
evidence. Operational speed must not weaken or replace that validation path.

## Decision

Treat a click on either business page as authorization for exactly one read-only
Job. Settlement and daily-detail reads use separate scopes, conflict keys,
snapshots, and downstream work items. They share the existing browser resource
slot and scheduler; no second service or state machine is introduced.

New `operational_compat` Jobs use a `batch_v1` strategy. The worker obtains one
page-authoritative list query, freezes the ordered unique identity set, and
processes batches of fifteen. Detail concurrency is capped at four and image
concurrency at six. A detail feeds its two image reads immediately. One fully
validated batch is committed atomically and can release OCR work before the next
batch finishes. Existing stepwise checkpoints remain readable and resumable.

Normal reads use a headless browser in a DaHe-owned profile. The worker reuses a
valid session or makes one automated login attempt. The fixed generic credential
`DaHeLogistics/Chengfeng/Primary` is stored for the current Windows user through
Windows Credential Manager. Only the worker resolves it; plaintext never enters
the main-process protocol, command line, database, logs, diagnostics, or
evidence. A visible login context is created only after a person explicitly
chooses it in response to a login challenge or failure. Normal completion closes
the background browser and does not enter human handoff.

## Consequences

The platform account is occupied for a shorter bounded collection period, and
OCR can overlap later browser batches through the existing resource scheduler.
Crashes can repeat at most the current fifteen-item batch. A credential or login
failure stops safely at the most recent committed batch instead of retrying a
password loop.

ADR-042 remains historical compatibility for already stored business-session
records and APIs. The main UI no longer creates those sessions. Operational
batch evidence is ineligible for the Loop 9 locked set, real shadow batch, or
`shadow_accepted`; strict validation must collect its own evidence.
