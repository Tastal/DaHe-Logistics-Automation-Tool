# ADR-072: Qualified installed GPU overlay

## Context

The 1.1.1 GPU release asset contained a portable runtime but no supported
installer, CPU-generation binding, machine qualification or activation
mechanism. Extracting it beside an installed application could not prove that
the models, Worker, CPU fallback, NVIDIA device and driver still formed the
qualified composition. It also gave rollback no explicit way to distinguish a
complete add-on from a partial copy.

## Decision

The formal GPU runtime is an independent overlay below the per-user installation
root:

```text
runtimes/g/
runtimes/gq/qualification.json
runtimes/active-gpu-addon.json
```

The release ZIP contains only the short `g` runtime and a strict internal
manifest. `DaHeUpdater.exe gpu-install` verifies the release version, file name,
size and SHA-256; binds the package to the installed CPU generation, model
manifest and Worker source; rejects links, unsafe archive members, insufficient
space and paths outside the traditional Windows budget; then runs CPU and GPU
Worker hello, preflight and two synthetic OCR fixtures on the target computer.
The CPU/GPU critical fields must match and the GPU memory peak must stay within
the qualified ratio.

Extraction and qualification occur in a short temporary directory. The updater
moves the verified runtime and qualification into place and publishes
`active-gpu-addon.json` last. Failure removes only this attempt and leaves the
CPU composition unchanged. The same package may be qualified again after a
driver change; a different package cannot replace an active overlay implicitly.

`gpu-status`, application runtime selection and local diagnostics recheck the
qualification against the current GPU UUID, driver version and memory. A stale
or damaged overlay is not selected; CPU remains the safe fallback. Older
application versions do not know the overlay pointer and therefore continue to
use their CPU path after rollback.

## Consequences

- GPU is the primary installed runtime only after evidence is produced on that
  computer; CPU fallback cannot be mistaken for GPU acceptance.
- Release and runtime identity are inspectable without adding a database
  migration, service or remote telemetry dependency.
- A driver replacement requires requalification with the matching formal GPU
  package.
- The GPU ZIP is not a standalone installer and manual extraction is not a
  supported activation path.
