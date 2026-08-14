# ADR-067: Versioned install, trusted update and local diagnostics

## Context

DaHe is an internal Windows application for one company. It needs safe upgrades across different computers and database histories, but a remote telemetry service, privileged installer or second application state machine would add more maintenance than value.

## Decision

The per-user installation root is `%LOCALAPPDATA%\Programs\DaHeLogisticsAutomationTool`; product data is `%LOCALAPPDATA%\DaHeLogisticsAutomationTool`. One desktop shortcut starts `DaHeLauncher.exe`. Each application release lives under `versions\<version>` and is accepted only when its version, Git commit, complete resource hash and Schema revision equal the atomic current pointer.

The browser, CPU OCR and GPU OCR workers are staged around the pinned official CPython 64-bit embeddable archive. Formal packages use only the root `python.exe`; they do not contain a copied virtual environment, `Scripts`, `pyvenv.cfg`, direct local package references, bytecode caches or developer-machine paths. The formal browser runtime uses the installed Microsoft Edge and never includes a bootstrap smoke store, browser Profile, Cookie, history or login database. Runtime staging preserves the approved dependency inventory and worker source fingerprint, and fails before packaging if either changes or the isolated interpreter cannot start. CPU and GPU dependencies remain in separate runtimes, with the CPU runtime always available as the fallback.

New formal CPU packages use the flat composition layout in ADR-071. The build
retains the qualified generation identity in signed manifests but removes the
development generation directory from installed file paths. Existing version-1
composition layouts remain readable for application updates. A release build
must pass the traditional Windows path budget without relying on the machine's
global long-path policy.

Formal GPU packages use the independently installed overlay in ADR-072. The
versioned updater, rather than manual extraction, binds that overlay to the
installed CPU generation and current application release, performs a
machine-local qualification, and publishes its pointer only after success.
Application rollback can ignore the overlay, and GPU failure never rewrites the
CPU composition.

`DaHeUpdater.exe` is separate from the application. It checks only the fixed `Tastal/DaHe-Logistics-Automation-Tool` release manifest over HTTPS, follows only approved GitHub asset redirects and verifies version direction, names, sizes and SHA-256 values. Application ZIP downloads retain a manifest-bound partial file, resume only after a valid `206` and exact `Content-Range`, restart safely when the server returns `200`, and use bounded exponential retry. A changed manifest or failed hash removes the partial file. A local manifest and application ZIP may be imported by the operator, pass the same version, downgrade, Schema, name, size and hash rules, and remain installable after an application restart. Public proxy sites and a second online release source are not accepted. Each application ZIP carries its versioned updater; the application prefers that copy and retains the stable root updater only for the first upgrade from an older release. A check runs at startup and every six hours, and every manual update-button click performs a fresh check before presenting an online candidate. A failed check clears stale online availability while leaving verified local-package import available. Installation is explicit and blocked while any task is active, paused or recoverable. Failures leave the current version usable.

A formal installer carries every read-only operational contract declared by its seed marker. The release builder and first-start launcher independently validate the declared relative path, size and SHA-256 before copying it into the product data root. A clean installation cannot inherit business-read authority from an unrelated development root, prior version or manual repair, and an incomplete seed is a release failure.

Before pointer switch, the updater extracts to a new version directory, validates the release identity, copies the SQLite database, runs the declared Alembic migration and integrity preflight on the copy, then takes an SQLite online backup and performs the formal migration. The new application must return the exact readiness identity. Failure before the user interface opens restores the database backup and old pointer. After user activity begins, database rollback is never automatic.

Diagnostics remain local. Bounded breadcrumbs contain only page/action class, Job ID, result, timestamp and error code. The environment snapshot contains application/build/Schema identity and coarse runtime capacity. A user-triggered support ZIP contains only those files and recent re-redacted logs, with a seven-day and 20 MB cap. It never contains databases, evidence images, browser profiles, credentials, raw platform data or OCR text and is never uploaded automatically.

The formal public repository begins from a sensitivity-scanned single root commit. Historical local Git data is retained only in an external verified bundle. GitHub stores source and the five formal release assets; no Actions, telemetry or additional service is required.

## Consequences

- Program files, versions and user data have distinct recovery boundaries.
- Worker runtimes are portable across company computers and do not expose or depend on the developer workstation layout.
- Schema compatibility is a release input rather than an assumption based on one developer database.
- Updates are reviewable and recoverable without granting administrator rights.
- Clean installations receive the same hash-bound read-only contracts as verified upgrades instead of depending on machine history.
- Developers receive actionable evidence only when a user deliberately provides the local diagnostic package.
- The project cannot promise that unsigned software will never show SmartScreen reputation warnings; it instead avoids UPX and obfuscation, publishes hashes and requires local Defender scans.
