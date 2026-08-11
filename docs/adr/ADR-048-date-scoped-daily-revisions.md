# ADR-048: Date-scoped daily items and append-only field revisions

## Decision

The daily workspace reads locally persisted waybills by business date. It does not use a Job picker and does not recapture data when the date changes.

Four fields may be revised: loading net weight, loading time, unloading net weight, and unloading time. Each save appends a versioned revision. Machine observations and prior revisions remain immutable. An explicit null is a durable human choice.

Loading-field revisions remain effective only while the loading ticket hash is unchanged. Unloading-field revisions use the corresponding unloading hash. Any effective revision marks existing reports for that business date stale; report regeneration is an explicit user action.

## Consequences

- Existing business-day records can be viewed and repaired without another platform read.
- Evidence history is preserved and stale clients cannot overwrite newer values.
- The report generator reads the current effective projection, while old files remain historical artifacts.
