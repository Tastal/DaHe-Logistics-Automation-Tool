# ADR-018: Close Loop 7 with a weight-safety waiver

## Context

The formal natural locked-set run remained failed because one image produced
`3270 t` on CPU and `32.7 t` on GPU. The result did not create an incorrect
automatic pass or a high-confidence wrong role, but it proved that runtime
weight parity was not established. The result then informed a new executable
safety rule, which permanently removed the 50-waybill set from independent
acceptance use.

The business owner declined to collect and review a replacement set and
explicitly accepted the remaining validation risk so that Loop 8 may begin.

## Decision

- A tonne OCR amount consisting of four or more digits with no decimal point
  is preserved exactly, marked unreliable, and routed to human review with
  `ticket_weight_format_suspicious`. It is never divided, rounded, or repaired
  automatically.
- A CPU/GPU disagreement in ordinary-net amount, unit, or reliability preserves
  both raw results and routes to human review with
  `ocr_weight_disagreement`. Neither result may drive automatic comparison.
- These routes are `awaiting_review`, not `confirmed_problem`. Runtime details
  remain diagnostic; finance-facing text describes only the business issue.
- The formal failed report remains failed. The affected 100 images are
  invalidated to development evidence through the formal invalidation command.
- Loop 7 is recorded as `closed_with_waiver`, never `accepted` or
  `shadow_accepted`. The waiver permits entry to Loop 8 but cannot support
  natural locked-set acceptance, formal role-accuracy, or CPU/GPU-parity
  claims.
- `last_accepted_git_commit` continues to identify the last genuinely accepted
  gate baseline.

## Consequences

The new rules fail safe and avoid a speculative decimal repair. They add a
small human-review route for unusual OCR formats and runtime disagreement.

There is no independent natural locked set for the final Loop 7 build.
Therefore the remaining role-accuracy and CPU/GPU-parity risks are accepted,
not resolved. This waiver is specific to this closure and is not a reusable
mechanism for bypassing later Loop gates.
