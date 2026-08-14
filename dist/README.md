# Local release archive

Formal release assets are archived under `dist/releases/<version>/`.

Each version directory must contain exactly the five published assets:

- the per-user NSIS setup executable;
- the Windows x64 application ZIP;
- the optional Windows x64 GPU add-on ZIP;
- `update-manifest.json`;
- `SHA256SUMS.txt`.

The asset directories are intentionally ignored by Git. Before using an
archived release, verify every file against both `SHA256SUMS.txt` and the
corresponding GitHub Release.
