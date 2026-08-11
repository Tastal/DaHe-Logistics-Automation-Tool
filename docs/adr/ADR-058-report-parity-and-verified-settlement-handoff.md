# ADR-058: Locked report parity and verified settlement handoff

## Decision

The daily workbook format is locked to the approved reference workbook and its SHA-256. New reports are written directly to the final business-date filename. Regeneration writes and validates a temporary workbook before atomically replacing the final file. A file lock stops replacement without changing the existing file. Each generation remains an immutable database record with before and after file hashes.

The settlement browser handoff is successful only after the batch-search dialog closes, the read-only query finishes, and the returned count and identities are reconciled. Missing current-settlement identities are reported separately while the browser remains open for human use.

## Consequences

- The obsolete pending-confirmation workflow remains read-only for historical records.
- Manual edits to a closed workbook are intentionally replaced by a later explicit generation.
- Browser idle state is not treated as proof that filtering succeeded.
- No settlement, payment, receipt cancellation, or other platform write is added.
