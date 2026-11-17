# Changelog

All notable changes to FileLocker. Versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-17

First public release.

### Features
- Password-protect `.xlsx` and `.docx` files (ECMA-376 Agile, AES-256, the same as Office's
  *Encrypt with Password*) and `.pdf` files (AES-256).
- Sources: a single file, a folder (optionally with subfolders), or a **zip file**. In zip
  mode each document inside the zip is protected individually, and the zip is rebuilt with
  the same structure.
- Every output is verified by decrypting it with the password before it counts as a
  success. Bad outputs are deleted.
- Naming: `<name>_protected.<ext>` next to the original, or the original name in a
  different output folder. Existing files are never overwritten.
- Optional, double-confirmed **Overwrite original files**.
- Preview with the exact output names; progress, per-file results and a summary.
- Warning for passwords shorter than 10 characters.
- Log file without passwords, with optional **Hide file names in log**.
- High-DPI support.

### Security and release engineering
- Network kill switch: sockets and DNS are disabled in-process at startup. Web/SSL modules
  are excluded from the exe. Tests enforce that the code has no networking imports.
- Built-in self-test: `FileLocker.exe --selftest report.txt`.
- Dependencies pinned with SHA-256 hashes, and audited with `pip-audit`. Code scanned with
  `bandit`.
- Releases built by GitHub Actions, with a build provenance attestation, an SBOM, SHA-256
  checksums and a self-test report.
- Version and source commit in the About box and the exe's file properties.
