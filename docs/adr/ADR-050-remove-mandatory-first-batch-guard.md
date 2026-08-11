# ADR-050: Remove the mandatory first-batch guard

## Decision

The production read-only workflow uses `operational_read_only_active`. A waybill with the machine outcome `normal_ready` proceeds directly to the local “ready for settlement” list. The first 30 unique production waybills are no longer forced into manual confirmation.

All existing business safety routes remain unchanged. Swapped or same-role tickets, missing evidence, weight mismatches, unknown roles, suspicious weight formats, CPU/GPU disagreements, and technical failures cannot use this policy change to pass automatically.

Historical first-batch guard rows and manual actions remain immutable evidence. The transition releases only machine-normal work items waiting solely because of `production_first_batch_guard`; it does not create fake manual decisions or rewrite OCR and platform evidence.

## Reason

DaHe is a single-company read-only assistant. Settlement confirmation and payment remain manual on Chengfeng. Mandatory confirmation of every machine-normal result duplicated the later human settlement step and blocked daily use without changing the platform.

The business owner chose to use the system in production while monitoring results. This is an operational policy change, not evidence that the independent locked set or strict shadow gate passed.

## Consequences

- Production operation is simpler and normal waybills no longer wait for the first-batch quota.
- Business anomalies and technical failures remain fail-closed.
- Existing guard evidence stays available for historical replay.
- `operational_read_only_active` must not be described as `operational_read_only_accepted` or `shadow_accepted`.
- Rollback requires restoring the pre-migration production backup; a later binary must not silently recreate mandatory confirmations.
