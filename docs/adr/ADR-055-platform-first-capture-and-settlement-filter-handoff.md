# ADR-055: Platform-first capture and settlement filter handoff

## Decision

The operational settlement reader downloads the current list, details, platform weights, and every current ticket image before releasing its owned Chengfeng browser. Local hash comparison, OCR reuse, new GPU OCR, CPU fallback, and audit comparison begin only after that release.

The settlement workspace may copy the stable list of current `normal_ready` waybill numbers or open a visible DaHe-owned Chengfeng window and populate the official batch-search filter. The automation stops on the filtered result page and never selects waybills or invokes settlement, payment, receipt cancellation, or another platform write.

## Reason

Keeping reuse and OCR out of the online phase shortens exclusive platform occupancy and makes the progress boundary truthful. A dedicated read-only filter handoff removes slow manual pasting without expanding the application's settlement authority.

## Consequences

- Every current ticket image is read and content-hashed before local reuse is considered.
- Fifteen-waybill commits remain the network recovery boundary.
- The visible filter handoff is unavailable while a platform read is active.
- Human settlement remains outside DaHe and outside the program request audit.
