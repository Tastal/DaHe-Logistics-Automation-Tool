# ADR-053: Verified incremental reuse and offline OCR

## Decision

For operational settlement, ADR-055 supersedes the early image-validator shortcut described by the first revision of this decision. Every image body in the current platform snapshot is downloaded and committed before the browser is closed. Only then may the application compare the current SHA-256 values with its local index and reuse OCR or comparison results. A platform identity, waybill number, signed URL, local file, ETag, or Last-Modified value is never sufficient to skip the current image-body read.

Network batches remain fifteen-item atomic recovery boundaries. They no longer materialize OCR after every commit or rescan prior batches. The application completes all required platform reads, closes its owned browser, and then performs one idempotent offline OCR and comparison materialization. Existing committed evidence, OCR observations, and comparison results are reused only at their own validated layer.

The page-owned query remains the authority for the settlement identity list. After that list is frozen, a discarded SPA page must not force the list query to repeat. The isolated browser worker may therefore read only the fixed, protocol-validated detail endpoint with its worker-private session memory. The command cannot provide an arbitrary URL or method, redirects remain rejected, and no session value or raw response may leave the worker.

## Consequences

- Repeated settlement reads do not skip current image bodies; they can skip unchanged OCR and comparison work after local hash verification.
- The platform session is held for the shortest practical period and does not compete with local OCR.
- A crash can redo the current uncommitted network batch but cannot requeue every earlier batch.
- Missing validators reduce performance but never weaken correctness.
- GPU and CPU attribution, cache hits, and stage durations are recorded as diagnostics rather than inferred from Task Manager utilization.
- A closed SPA page between scheduler quanta no longer invalidates the already frozen list or causes a repeated visible login cycle.
