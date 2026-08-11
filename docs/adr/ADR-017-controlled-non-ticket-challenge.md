# ADR-017: Controlled non-ticket challenge

## Context

Loop 7 needs evidence that an unrelated uploaded image cannot be treated as a
ticket or pass automatically. The formal 50-waybill locked set must preserve
the natural historical distribution. Replacing a valid waybill image solely to
force a non-ticket condition would no longer measure that distribution and
would fabricate an event that did not occur in the frozen source set.

The user-provided non-ticket image may contain personal, commercial, or other
sensitive content. The challenge therefore needs an evidence path that proves
the safety decision without putting the original image or readable sensitive
fields in the repository.

This ADR supersedes only ADR-016's inclusion of `non_ticket` among the formal
locked-set quality conditions and its resulting two-gate framing. All other
ADR-016 decisions remain in force.

## Decision

- Loop 7 has three independent release gates: the natural 50-waybill locked
  set, one controlled non-ticket challenge, and the four-case derived
  relationship suite. Failure of any gate blocks Loop 7 acceptance.
- The natural locked set remains exactly 50 source waybills and approximately
  100 independent images. It covers `blur`, `crop`, `glare`, `printed`,
  `rotation_0`, `rotation_90`, `rotation_180`, `rotation_270`, `screen`, and
  `unknown_layout`. It is not altered to add a non-ticket image.
- The controlled challenge uses one user-provided image that has not
  participated in development, calibration, template references, a prior
  locked set, or another release gate. Before challenge execution, its original
  content hash and versioned perceptual fingerprint are checked against the
  exclusion inventory. The isolation decision and algorithm versions are
  retained, but the original bytes are not copied into project evidence.
- The original image is read only transiently on the local machine to produce
  an irreversibly redacted, metadata-free copy. The original is not modified.
  Only the redacted copy and its evidence binding may be stored under the
  configured AppData evidence root. The original, unredacted copies, readable
  sensitive fields, and source filesystem location must not enter the
  repository, Git history, logs, or diagnostics.
- Human truth for the challenge is role `unknown` with no ordinary-net truth.
  The role result must be `unknown`; if evaluated in a waybill decision, it must
  produce `awaiting_review` and must never produce an automatic pass. A
  confident ticket role or any automatic pass fails the challenge.
- The challenge report binds the redacted-copy hash, redaction method version,
  exclusion-check result, human truth, application build, runner result, and
  final pass or fail decision. It does not retain or reconstruct the removed
  sensitive content.
- The non-ticket challenge is reported only as pass or fail. It does not enter
  the locked set's real sample count, confusion matrix, accuracy, unknown rate,
  latency, layout distribution, or historical occurrence-rate claims.
- The four relationship anomalies remain deterministic derivations from
  human-confirmed locked images: `swapped_slots`, `both_loading`,
  `both_unloading`, and `exact_duplicate_image`. They remain separate from both
  the natural metrics and the controlled non-ticket challenge.
- If the controlled challenge influences executable code, configuration,
  templates, models, thresholds, rules, mappings, error behavior, or labels,
  its image permanently becomes development evidence. A new unseen
  user-provided image must replace it, and all three gates must be rerun for the
  current build. Existing ADR-016 invalidation rules continue to govern locked
  and derived evidence that influences implementation.

## Consequences

- The natural locked-set metrics continue to describe the frozen historical
  waybill population instead of an intentionally altered sample.
- Non-ticket safety remains a mandatory release condition rather than an
  optional example or a contribution to an aggregate metric.
- The AppData evidence package is reviewable without storing the readable
  source document in the repository.
- A challenge failure cannot be hidden by a strong natural-set accuracy result;
  it blocks Loop 7 independently.
- Any implementation change prompted by the challenge consumes that challenge
  image as development evidence and requires a new unseen user image.

## Rejected alternatives

- Replacing a valid locked-set image with a non-ticket image would alter the
  natural distribution and falsely attach an unrelated document to a historical
  waybill.
- Counting the challenge in accuracy, unknown-rate, latency, or occurrence-rate
  statistics would mix an intentionally selected safety probe with natural
  observations.
- Storing the original image in AppData or Git would retain unnecessary
  sensitive content.
- Treating the challenge as advisory would allow Loop 7 to pass after an
  unrelated image received a confident ticket role or automatic pass.
