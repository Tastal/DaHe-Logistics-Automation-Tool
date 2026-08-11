# Repository Instructions

## Sources of Truth

- Read `PRODUCT.md` before making product-purpose or user-facing language decisions.
- Read `DESIGN.md` before changing navigation, page responsibilities, layout, visual rules, or interaction behavior.
- Read the relevant sections of `DEVELOPMENT_GUIDE.md` before changing business rules, architecture, data, OCR, jobs, browser behavior, or acceptance gates.
- Use accepted ADRs for the reasons behind architecture decisions once ADR files exist.
- Direct user instructions control the current task, but confirmed durable changes must be synchronized back to the appropriate source of truth.
- Do not treat chat history, temporary notes, generated output, or legacy code as a durable product contract.

## Current Product Boundary

- Follow the approved MVP boundary and development stages in `DEVELOPMENT_GUIDE.md`.
- If the current task has an accepted implementation plan, follow its narrower boundary and do not advance later stages implicitly.
- A placeholder or future module boundary is not permission to implement that capability.

## Before Editing

- Identify the affected business module and the governing section in `DEVELOPMENT_GUIDE.md`.
- Inspect the existing implementation, tests, schemas, migrations, configuration, and task state before proposing a change.
- Read `verification/loop-ledger.json` when it exists; use it only as execution evidence, never as a substitute for the guide.
- When an accepted current plan defines Loops, identify and advance only one defined Loop and its acceptance gate.
- Keep the change inside one narrow vertical slice; before expanding scope, update the confirmed business contract or ADR and do not invent missing Loop numbers.
- If the request expands scope or conflicts with a confirmed contract, stop expanding the implementation and surface the conflict.
- Preserve unrelated user changes and do not assume the workspace is clean or already a Git repository.

## Safety Boundaries

- Treat every legacy project, legacy database, legacy browser profile, and running legacy process as read-only.
- Never run legacy scripts, tests, launchers, migrations, or maintenance commands.
- Never attach to, inject into, stop, upgrade, or reuse a legacy process.
- Never reuse a legacy service port, application-data directory, browser profile, credentials file, cache, or log directory.
- Never read a legacy SQLite database while the legacy program may be writing it; use only an explicit consistent snapshot or backup.
- Never kill an unknown Python, Edge, Chrome, OCR, or local service process to resolve a conflict.
- Do not access the real Chengfeng platform unless the user explicitly approves a safe test window.
- Treat the first MVP as read-only shadow work; local decisions must not change real settlement lists or prompt unapproved platform handling.
- Do not automate settlement confirmation, payment, receipt cancellation, or any unapproved platform write.
- Do not add a local API endpoint that performs settlement confirmation, payment, or platform receipt cancellation.
- Keep platform request handling deny-by-default and limited to an approved host, path, method, and payload contract.
- Never use the platform's expected weight to select or rank OCR candidates.
- Do not trust the upload slot as proof of a ticket's real loading or unloading role.
- A suspected swapped ticket must not be exchanged automatically or passed automatically.
- Program defects and infrastructure failures must not be converted into human-review business items.
- Do not modify Windows DNS, proxy, VPN, routing, hosts files, or global browser settings.
- Do not expose passwords, cookies, tokens, signed URLs, personal contact data, or full sensitive responses in source, fixtures, logs, screenshots, or diagnostics.
- Do not copy production images or credentials into tests without an explicit sanitized-fixture process.

## Python and Runtime Rules

- Use the project `.venv`; never use system-global Python for project commands.
- Keep the main application, CPU OCR, and GPU OCR in isolated environments with separate locks.
- Do not install CPU and GPU Paddle packages over each other in one environment.
- Do not hard-code a developer-machine path, GPU index, GPU model, CUDA location, Edge path, account name, or network configuration.
- Treat the NVIDIA driver as a system capability, not as something isolated by a virtual environment.
- Keep a verified CPU OCR path available when a GPU runtime is installed.

## Loop Engineering Workflow

- Freeze the Loop input, assumption, fixture manifest, and allowed external resources.
- Add observable states and failing contract tests before broad implementation.
- Implement the smallest end-to-end capability that can validate the Loop hypothesis.
- Prefer fake adapters and temporary data until the relevant contract gate passes.
- Run automated tests, fault injection, and required human business checks.
- Record the build version, fixture hashes, commands run, results, differences, and unresolved risks.
- Advance only after every safety and acceptance gate for the Loop passes.
- Do not lower a threshold, swallow an exception, or expand scope to disguise a failed gate.
- Keep each completed Loop recoverable to a known Git baseline once Git is initialized.

## Module and Dependency Rules

- Follow the architecture, dependency direction, data separation, and module boundaries in `DEVELOPMENT_GUIDE.md`.
- This project serves one small company. Prefer the simplest implementation that meets the confirmed business, safety, recovery, and data-retention requirements; do not prebuild for hypothetical scale.
- Do not add a service, runtime, framework, daemon, container, telemetry platform, or second state machine unless a measured problem cannot be solved adequately with the existing stack or a small local implementation.
- Any new open-source dependency must have a trustworthy official source, a compatible license, recent maintenance, explicit Windows support, a pinned version, isolated installation where practical, verification evidence, and a documented removal or rollback path. Pin downloaded executables by SHA-256 and never auto-update them.
- Use English by default for code comments, rule documents, file names, and Git commit messages.
- Do not import another business module's internals or persistence tables; use an approved port, event, or query contract.
- Do not create a second scheduler, frontend business state machine, or OCR decision contract.
- Keep backend state and action availability authoritative.

## Verification

- Run the narrowest relevant unit, contract, integration, browser E2E, and fault-injection checks for the changed Loop.
- Verify all local write actions are idempotent and protected by record versions where required.
- Verify item counts reconcile from the source snapshot through the final business outcomes.
- Verify pausing, cancelling, retrying, and restarting do not lose or duplicate committed results.
- Verify one job's controls do not mutate another job's state or UI context.
- Verify no forbidden platform request exists before any approved real-platform test.
- Verify user-facing screens at the required Windows sizes and 100%, 125%, 150%, and 200% scaling when UI code exists.
- Use business language in finance-facing UI; keep technical detail in system diagnostics.
- Until real project check commands exist, do not invent them. Once they exist, keep the authoritative commands in `README.md` and only point to that file here.
- Never claim a check passed unless it was actually run and its result was reviewed.

## Documentation Changes

- Update `PRODUCT.md` only for a confirmed product purpose, user, design-principle, or product-language change.
- Update `DESIGN.md` only for a confirmed durable UX structure, visual rule, interaction contract, or approved design reference.
- Update `DEVELOPMENT_GUIDE.md` only for a confirmed business contract, architecture, data rule, long-term UX rule, development stage, or acceptance-gate change.
- Use an ADR when a technical decision changes and the reason or accepted trade-off matters.
- Do not put temporary progress, routine code details, test counts, or one-off debugging notes into durable guidance.
- Do not copy full schemas, state machines, page structures, or OCR settings into this file.
- A nested `AGENTS.md` may add subtree constraints but must not weaken this file or `DEVELOPMENT_GUIDE.md`.

## Handoff

- List the files changed and the user-visible or architectural outcome.
- List the exact checks run and their results.
- List checks that were not run and explain why.
- When a Loop was advanced, update its evidence ledger atomically and do not mark it accepted without the recorded gate evidence.
- State remaining risks, external approvals, and unverified assumptions directly.
- Report any legacy-process, platform, credential, network, or data-safety concern immediately.
- Do not declare a Loop complete unless the accepted current plan defines it and its evidence passes; do not declare a feature or MVP complete without the applicable guide acceptance gate.
