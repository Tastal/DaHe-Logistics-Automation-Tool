# ADR-004: Separate OCR Runtimes

## Context

CPU and NVIDIA GPU Paddle packages can conflict and have different deployment requirements.

## Decision

Use separate locked environments for the main application, CPU OCR, and GPU
OCR. Build every OCR environment from scratch in a managed staging directory,
verify its complete installed inventory against the selected lock, and pass a
real local-model smoke before atomically replacing the previous environment.
Seal CPU, optional GPU, local models, and their qualification in one immutable
versioned generation. Publish that generation by atomically replacing a single
`active-composition.json` pointer; never update active model or runtime
directories in place. A partial build or model download may leave only an
unreferenced candidate and cannot invalidate the previous composition.

Keep the portable CPU runtime qualified whenever a GPU runtime is installed.
Select GPU profiles by a stable device identity and current qualification
evidence; map that identity to an ephemeral device index only when starting a
worker.

Mark OCR execution as `fake` or `local` on each persisted Job. A fake pipeline
identifier is never sent to a local worker. Local shared evidence is keyed by
the image hash and a full runtime-aware pipeline fingerprint; GPU and CPU
artifacts therefore remain separate immutable records.

Use one image as the OCR lease and checkpoint boundary. A waybill generation
may consume two shared image artifacts only when their runtime, profile, and
pipeline identities agree. If an eligible GPU failure occurs after one image,
the committed GPU image artifact remains reusable globally, while that
waybill switches to CPU and obtains both CPU artifacts before committing.

## Consequences

Deployments are larger and initial setup takes longer, but stale packages
cannot silently survive an upgrade. CPU and GPU packages must never be
installed over each other. A failed candidate leaves the previous environment
available, and an otherwise compatible GPU cannot be used until its current
device, driver, model, worker, lock, memory, and smoke evidence match.
