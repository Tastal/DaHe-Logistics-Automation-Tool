# ADR-071: Flat installed CPU runtime

## Context

The 1.1.0 installer copied the qualified development composition path
`generations/<generation-id>/ocr-cpu` into the formal CPU archive. On the
development computer, Windows long paths were enabled. Under the default policy
and the company account's longer installation root, the final path could reach
296 characters and the atomic staging path could reach 338 characters. NSIS
therefore completed the application extraction but the CPU runtime bootstrap
failed before the shortcut was created.

## Decision

Development and existing installed compositions keep pointer schema 1 and the
generation directory. New formal CPU packages use pointer and composition schema
2 with one flat root:

```text
active-composition.json
composition-manifest.json
c/
m/official_models/
q/qualification.json
```

The generation ID and all runtime, model and qualification hashes remain in the
two manifests. The resolver reads both schemas; the formal builder writes only
schema 2. Installer extraction uses a short `.c-<8 hex>` sibling and renames it
to `ocr-cpu` only after the archive and active composition are fully verified.

The builder projects every file below the normal per-user installation root with
a 20-character Windows user name. Files must not exceed 259 characters and
directories must not exceed 247 characters. The installer repeats the check for
the actual account, verifies free disk space before extraction and records a
stage-specific, path-redacted error if an operating-system file operation fails.
The product does not enable Windows long paths, request administrator rights or
change a machine-wide policy.

## Consequences

- A normal-user installation works under the default Windows path policy.
- The qualified OCR generation identity and evidence hashes are unchanged.
- Existing 1.1.0 installations can update the application without replacing a
  working schema-1 CPU runtime.
- New packages have one additional internal manifest schema to maintain, but no
  database, API or business migration.
