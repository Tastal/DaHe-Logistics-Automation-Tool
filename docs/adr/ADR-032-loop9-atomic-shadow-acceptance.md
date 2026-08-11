# ADR-032: Atomic Loop 9 Shadow Acceptance

## Context

Loop 9 closes the first read-only shadow MVP only after several independent
authorities pass. A format-valid summary is insufficient because stale source,
an inactive selection generation, altered request counts, or incomplete
recovery evidence could otherwise be presented as a successful close.

The existing ledger also has a general atomic replacement API. Allowing that
API to write `shadow_accepted` would make the terminal product status easier to
set than the evidence Gate that is supposed to justify it.

## Decision

The final acceptance command is offline and uses the project `.venv`. It
reloads the current build and active data-root authorities, then deeply replays:

- the current read-contract validation;
- the active 50-item selection and its current locked Gate;
- the active 30-item selection, human seal, machine evaluation, and result
  reconciliation;
- the three daily snapshots;
- the full-history dataset-isolation evidence.

The 50-item locked batch and 30-item real shadow batch each bind one
content-addressed request-audit SHA. Each of the three daily snapshots binds
its own request-audit SHA. These five identities come from their upstream
formal authorities and cannot be supplied independently to the final command.
The final Gate replays every audit event chain and reconciles attempted,
allowed, succeeded, denied, and per-operation counts. Denied, platform-write,
and redirect counts must all be zero.

A separate content-addressed formal-run record is mandatory. Its publisher
accepts only technical identities for the 50-item Job, 30-item Job, active
30-item selection, current evaluations, and four fault runs. It derives all
counts and results from the active authorities, immutable machine records, and
the production SQLite Job, WorkItem, StageAttempt, Checkpoint, Lease,
application-instance, and outbox records. It stores the complete five
request-audit evidence bodies, not caller-authored summaries.

Each fault run must contain the protected three-event chain `injected`,
`failure_observed`, and `recovered`, bound to the current build and a fixed
injector contract. The chain must reconcile to the exact failed attempt,
checkpoint, recovery attempt, application instance, leases, terminal Job, and
all terminal WorkItems. Missing production fields, a technical failure routed
to business review, lost results, duplicates, or a recovery not crossing the
required boundary all fail closed.

CPU OCR, GPU OCR, role-validation, and end-to-end P50/P95 are recomputed from
the individual persisted durations. Role timing is an explicit runtime field
and cannot be inferred by subtracting other measurements. The final acceptance
command accepts only raw, typed technical identities and paths needed to
rebuild the acceptance inputs. It does not accept a replay object, pass flags,
counts, timing summaries, or replaceable request-audit files. The single
acceptance entry point performs the deep replay internally, under the same
ledger write lock used for the adjacent terminal update.

Only after every replay passes does the command publish one immutable aggregate
evidence file. It then uses a private ledger commit path to move schema v3 to
`shadow_accepted`; `LedgerStore` exposes no public terminal writer and the
normal replacement method rejects that status. The private path accepts only
the strongly typed `Loop9FinalAcceptanceInputs`, never a caller-constructed
replay object, replacement ledger, or arbitrary JSON. While the same process
and operating-system ledger lock is held, it rereads the current ledger,
revalidates the referenced input manifest through a safe read handle, and
calls the real
`replay_loop9_final_acceptance(inputs)` again, verifies the returned replay,
rebuilds the exact acceptance bytes, and constructs the only permitted
terminal document from the locked current ledger. The evidence `accepted_at`
and ledger
`acceptance.accepted_at` must be identical when the dedicated terminal
replacement is prepared and again immediately before replacement. The general
replacement path has no flag, permit, or duck-typed object that can authorize
this terminal status.

The terminal transition changes schema 2 or 3 to schema 3, increments the
revision once, moves `in_progress` to `shadow_accepted`, clears the waiver and
next inputs, stores only validated remaining risks, and creates acceptance
metadata from the verified evidence. Project identity, Loop identity, run
identity, input-manifest reference, and last accepted commit are copied
unchanged from the locked ledger. Existing Gate identities and order remain
unchanged. Only the four approved Loop 9 Gates are replaced with passed
evidence, after which one fixed final Gate is appended. Every other Gate is
preserved byte-for-byte as structured data.

Every ledger writer shares a process lock and an operating-system file lock,
then rereads the revision and terminal state while holding both locks. The
terminal path additionally requires the active repository ledger path and
verifies that the aggregate evidence is a regular, non-reparse, canonical
content-addressed file in the exact Loop 9 formal directory. It keeps one safe
read handle open, and after any pre-replacement hook it rechecks the path
identity and exact bytes through that same handle immediately before the
ledger `os.replace`. The input manifest uses the same identity-and-byte guard
across deep replay and replacement; missing, changed, symbolic-link, or
reparse-point manifests fail closed. The current ledger remains protected by
both writer locks and has its path identity and original bytes rechecked
before every bounded replacement attempt. The staged ledger replacement is
separately opened with a write-denying, rename-compatible handle and checked
against the exact in-memory bytes after any pre-replacement hook.

The locked 50-item and real 30-item scheduler projections use a strict
allowlist of business outcomes, decisions, and review reasons. Unknown or
technical reasons fail even if a diagnostic field is absent. The four fault
runs must have distinct run and Job identities and the exact protected
test-fixture scope, checkpoint payload, stage boundary, and lease-release
reasons defined by the injector contract.

If validation fails, the ledger remains byte-for-byte unchanged. If evidence
publication succeeds but ledger replacement fails, the orphaned immutable file
is harmless and a retry reuses it. A retry after acceptance must replay current
authorities and return the same evidence without another ledger revision.

## Consequences

- Missing formal request-count instrumentation blocks closure instead of being
  inferred or defaulted.
- Missing protected fault events or raw timing fields also block closure; the
  final Gate does not synthesize them.
- Any changed build, contract, selection generation, evidence hash, count, or
  replay result blocks `shadow_accepted`.
- The final command performs no Chengfeng request and does not change the
  current ledger until real evidence exists.
- The preserved Loop 8 commit remains the last previously accepted baseline;
  the later Loop 9 Git baseline is created after the evidence-backed ledger
  update.
