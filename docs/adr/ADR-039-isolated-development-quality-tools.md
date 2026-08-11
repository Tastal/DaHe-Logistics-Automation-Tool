# ADR-039: Isolated Development Quality Tools

## Context

DaHe needs better release diagnostics without adding services or changing the
production application. The useful gaps are narrow: accidental secret history,
known vulnerable locked dependencies, basic OpenAPI response conformance, and
occasional Python performance investigation. A general observability platform,
container stack, proxy, or second browser automation framework would add more
maintenance than value for one small company and two Windows computers.

## Decision

Use four development-only tools under the simple-first gate from ADR-038:

- Gitleaks 8.30.1 for release Git-history secret scans. Its official Windows
  x64 archive is pinned by SHA-256. Seven existing alerts were inspected at
  their historical commits and proved to be test-only idempotency keys; only
  their exact commit/path/rule/line fingerprints are ignored.
- pip-audit 2.10.1 for the checked-in main, browser, CPU OCR, and GPU OCR locks.
  It runs with dependency resolution disabled and never uses `--fix`. Packages
  that the PyPI advisory service cannot audit remain explicit coverage gaps.
- Schemathesis 4.24.3 for a bounded local API smoke. It starts a new fake-data
  DaHe service on a random `127.0.0.1` port and selects only the read-only meta
  and resource operations. Its temporary session is never persisted and its
  cache stays in the AppData run directory.
- py-spy 0.4.2 for an offline startup profile. On Windows, a `venv` launcher may
  redirect to the real Python process, so the wrapper reads the PID published
  by the exact child it just created. No user-supplied or existing PID is
  accepted.

Each Python tool has its own virtual environment. None is installed into the
main application, browser, CPU OCR, or GPU OCR runtime. Installation records the
resolved package inventory and hashes. Tool output stays under DaHe's AppData
development-tools directory and is not a business record or Loop 9 acceptance
artifact.

## Consequences

The tools can identify a failed gate without automatically modifying code or
dependencies. In particular, the first dependency audit identified findings in
the development and OCR locks and one vendor-index package not covered by PyPI;
those results remain failures until separately reviewed and retested.

This toolchain does not connect to Chengfeng, accept the operational connector,
change the Loop ledger, or advance Loop 9. Removal is limited to reverting this
ADR and its wrappers, then deleting the corresponding versioned AppData
development-tool directories while no quality check is running.
