# ADR-075: Keep platform time outside business-time fields

## Context

Chengfeng exposes operational timestamps that are useful for querying and ordering candidates, but they are not evidence of the time printed on a loading or unloading ticket. A v1.1.4 candidate copied platform loading time into the machine observation and also used it to complete OCR dates. Non-standard tickets could therefore appear automatically reviewed, and the report could include or populate a row without qualified ticket evidence.

## Decision

Loading and unloading business times may come only from a manual revision or qualified OCR evidence that still matches the current ticket SHA-256. Manual values, including explicit null, are authoritative. Missing labels, conflicting candidates, non-standard layouts and time-only loading OCR without an independent date remain unresolved for human review.

Platform timestamps remain immutable capture evidence. They may define the candidate query range and, only when both report times are blank after explicit human confirmation, act as an in-memory ordering key. They cannot determine report inclusion, fill an OCR date, populate an API or workbook field, appear in operator prefill, or mark a record reviewed. The hidden key is not exported or logged.

The report order is: qualified loading time, then unloading time when loading is blank, then hidden platform time when both are blank, then stable waybill and vehicle identity. A pending-unloading row has `0.00` unloading weight and a blank unloading time. Formal filenames include the date, contract subject and mine.

## Consequences

- Reusing a historical machine decision cannot reintroduce a platform-derived business time because current views are projected again from current-image OCR evidence and manual revisions.
- More non-standard tickets correctly require human review.
- Candidate capture and report inclusion remain separate contracts.
- Platform evidence is retained for technical reconciliation without becoming business data.
- ADR-073 remains authoritative for candidate-range separation, but its platform-time inclusion fallback is superseded by this decision.
