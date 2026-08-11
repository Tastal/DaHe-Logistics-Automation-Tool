# ADR-041: Isolated Windows packaging tools

The prospective Inno Setup and restic decision in the earlier revision of this ADR is superseded by ADR-067. Restic is not part of the formal product or release path.

## Context

DaHe needs a repeatable Windows installer without adding a paid license, administrator requirement, background service, container or cloud dependency. The compiler must remain outside the application and OCR runtimes.

## Decision

NSIS 3.12 is the only approved installer compiler. Its official portable archive is pinned by SHA-256, downloaded from the checked-in HTTPS SourceForge URL, verified before extraction and stored below the development-only AppData tool directory. It uses the zlib/libpng license and is not bundled as a runtime dependency.

The installer definition accepts only an explicit nonsymlinked frozen payload and an empty output directory. It uses `RequestExecutionLevel user`, installs below the current user's LocalAppData Programs directory, creates one desktop shortcut and does not include the product data root. Uninstall removes program files and the shortcut but retains all user data.

PyInstaller is pinned in the project development lock. The business application is built in one-folder mode with UPX disabled. The small stable launcher and updater are separate executables; they do not change the business-process or database architecture.

## Consequences

- Building an installer needs no purchase, license application or administrator prompt.
- The checked-in pin, source URL, license URL, archive hash and installed compiler evidence are independently reviewable.
- Inno Setup, restic and their obsolete wrappers are no longer part of the release path.
- This tool choice does not weaken Defender scanning, source/package/installed parity or readiness gates.
