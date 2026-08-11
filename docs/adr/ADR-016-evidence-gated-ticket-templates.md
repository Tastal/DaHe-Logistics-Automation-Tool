# ADR-016: Evidence-gated local ticket templates

## Context

Loop 7 needs a low-cost loading, unloading, or unknown decision without using
the Chengfeng upload position or expected webpage weight. Template editing must
remain understandable, reversible, and isolated from the accepted OCR worker
protocol. A successful unit test or caller-supplied fingerprint is not enough
evidence to publish a template.

## Decision

- The main application consumes the accepted OCR v1 result through a narrow
  adapter containing only the verified image hash, OCR text, confidence, boxes,
  and OCR-derived fixed text. The adapter accepts no platform weight, expected
  role, or upload-slot input.
- Normal matching uses only immutable `shadow` template versions. A separate
  evaluation-only entry point may combine explicit draft or
  `development_tested` candidates with the current shadow set. Its fingerprint
  includes its evaluation purpose, lifecycle, version, and content identity.
- Loading and unloading templates participate together. Weak, conflicting,
  unknown-layout, and non-ticket evidence returns `unknown`; it is never forced
  into a binary role.
- Reference images enter through a staged server boundary. The server validates
  the media signature and resource limits, applies EXIF orientation, rewrites
  the image as a deterministic metadata-free PNG, and stores it by content
  hash. The client submits the staged identity and record version rather than a
  trusted hash or filesystem path.
- The server derives each reference mask from the normalized image dimensions
  and submitted anchor geometry. The normalized image and derived mask have
  separate content-addressed identities; creating the immutable draft consumes
  the staged reference and establishes both durable evidence holds. Editing
  anchor geometry rebuilds the mask instead of retaining stale derived bytes.
  Unconsumed staged references expire after the bounded recovery window and
  release their temporary evidence holds.
- Template definitions, reference hashes, lifecycle events, evaluations,
  candidates, and per-image results are durable. Reference images receive an
  evidence hold in the same transaction as their immutable template version.
- `development_tested` and `shadow` transitions accept an evaluation ID, not a
  caller-provided success flag or opaque fingerprint. Only the code-owned
  frozen runner can create authoritative evidence. Persistent evaluation
  accepts only the version-controlled development dataset whose path and
  canonical SHA-256 are fixed in a code-owned registry; an external, copied,
  changed, or caller-selected dataset cannot self-authorize. Candidate versions
  are loaded by explicit immutable IDs from SQLite rather than supplied by the
  dataset. SQLite verifies that the absolute latest completed evaluation for
  the candidate still matches the accepted dataset, matcher policy, application
  build, qualified OCR runtime set, complete template set, stable pair
  outcomes, item reconciliation, canonical metric hash, gate result, and
  invalidation state in the lifecycle transaction. An invalid or invalidated
  newer evaluation never causes an older record to become authoritative again.
- Completed evaluation records are append-only. A later change appends an
  invalidation instead of editing prior evidence. Invalidating an evaluation
  atomically withdraws a current shadow pointer that the evaluation authorized.
- Unknown samples may enter the tuning queue only from development or
  calibration data. Locked and gate-shadow samples stay isolated unless an
  explicit conversion invalidates their gate status.
- Template maintenance requires a short-lived local developer session.
  Publishing and rollback require a second action-specific grant. Loop 7 has no
  `active` transition.
- The frozen synthetic evaluation proves contracts and failure routing only.
  Code-approved synthetic observations may authorize development and shadow
  transitions, but they are not real images or human labels and cannot prove
  ticket accuracy.
  The independent 50-waybill locked set remains the release authority and
  cannot be used for tuning.
- A formal locked set is sealed in SQLite against exactly 50 source-waybill
  identities and 100 content-addressed images. Its exclusion snapshot comes
  from persisted template-reference, development, calibration, shadow,
  prior-locked-image, and prior-waybill inventory. Exact and versioned
  perceptual fingerprints are both checked before OCR.
- Formal review uses one manifest-bound package. Human quality review contains
  only the 11 real-image conditions: blur, crop, glare, non-ticket, printed,
  0/90/180/270-degree rotation, screen, and unknown layout. Each condition
  binds an image identity. Rotation evidence uses four distinct images,
  printed and screen evidence use distinct images, review time is
  timezone-aware, and each human record has a canonical evidence hash.
- The real locked set preserves the natural historical distribution. Missing
  rare swapped, same-role, or duplicate-pair events are not manufactured and
  do not justify replacing otherwise valid waybills. A versioned deterministic
  generator instead builds four relationship cases from human-confirmed real
  images: `swapped_slots`, `both_loading`, `both_unloading`, and
  `exact_duplicate_image`. Their only accepted outcomes are
  `awaiting_review` with, respectively, `suspected_swapped`, `both_loading`,
  `both_unloading`, and `duplicate_image`.
- Derived relationship cases are bound to the locked manifest, generator
  version, selected source-image identities, and canonical suite hash. They do
  not add to the 50 real waybills or 100 unique real images and do not enter
  real confusion matrices, accuracy, unknown rate, latency, or occurrence-rate
  claims. The exact-duplicate case proves only identical content hashes, not
  repeated-ticket detection across different hashes. The real-image gate and
  derived relationship gate must both pass.
- The formal OCR evaluator accepts only the factory-qualified composition for
  the same application data and repository roots. The report binds both the
  qualified runtime set and the complete composition-evidence fingerprint;
  runtime identities alone are insufficient provenance.
- SQLite atomically retains the full canonical quality-review,
  near-duplicate-decision, and derived-suite records together with their
  hashes, the runner report, and the committed claim. These records are
  append-only and survive normal online backup and restore.
- If a real or derived locked result influences any executable artifact,
  configuration, rule, mapping, error behavior, template, model, threshold, or
  label, an explicit version-checked invalidation permanently converts the
  real set to development evidence. All images and source-waybill identities
  remain excluded from a future locked set. An invalidated claim cannot be
  replayed at either the application or repository boundary.

## Consequences

- The OCR worker protocol and CPU/GPU runtime composition remain unchanged.
- Role precheck adds only local text and geometry work after OCR.
- Evaluation storage is larger because every image result is retained, but a
  lifecycle decision can be reconstructed and audited.
- A new template cannot advance until a compatible development dataset has
  produced a complete evaluation for the current build. A newer evaluation
  supersedes older evidence, and a build change requires fresh compatible
  evidence.
- The offline persistence command takes the application instance lock, reloads
  candidate versions from SQLite, qualifies the real local OCR runtime, and
  atomically stores the accepted manifest and policy contract so a later
  application restart can revalidate lifecycle authority.
- Empty-database setup and later template creation share one staged-reference
  flow, so first use does not require a seeded template or caller-built mask.
- Synthetic success does not complete Loop 7. Human-confirmed unseen data,
  locked-set file verification, and the release metrics are still required.
- Preparing and validating a human review package does not start OCR and does
  not create an accuracy claim. Even a passed locked-set report does not by
  itself mark Loop 7 accepted; independent evidence review and the Loop ledger
  remain authoritative.
- Formal review storage is intentionally larger because exact reviewer,
  subject, time, decision, evidence-binding, and deterministic derived-suite
  records are retained instead of storing only summary counts.

## Rejected alternatives

- Trusting Chengfeng upload positions or webpage weight would create circular
  evidence and could automatically pass swapped tickets.
- Allowing arbitrary evaluation fingerprints would let callers bypass the
  development gate.
- Mutating one template row in place would make historical role decisions
  impossible to reproduce.
- Loading draft templates through the production matcher would blur the
  development and shadow safety boundary.
