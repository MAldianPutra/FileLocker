# Security overview

This document is for IT and security reviewers. It describes what FileLocker does, what it
deliberately does not do, and how each claim can be checked. To verify a downloaded
release, see [VERIFYING.md](VERIFYING.md).

## Summary

| Question | Answer | How to check |
|---|---|---|
| Does it use the network? | **No.** No networking code; networking is switched off in-process at startup; web/SSL modules are not in the exe | `tests/test_no_network.py`, `FileLocker.exe --selftest`, TCPView / firewall rule (VERIFYING.md) |
| Does it install anything? | **No.** No installer, registry, services, scheduled tasks, drivers or admin rights | Run it from a folder; it writes only the files listed under [Files it writes](#files-it-writes) |
| Telemetry, update checks, licence checks? | **None** | Source code; network guard |
| Is the password stored? | **No.** Held in memory only while processing; never written to disk or the log | `test_password_never_logged`, `test_password_not_logged_in_zip_mode` |
| What encryption? | Office: ECMA-376 Agile, AES-256-CBC, SHA-512, 100,000 iterations. PDF: AES-256 (revision 6) | `office_crypto.py`, `pdf_crypto.py`; files open in Excel/Word/Acrobat with the password |
| Can originals be damaged? | Not by default. Outputs are new files. Overwrite is opt-in, double-confirmed, and only after verification | `processor.py`, tests |
| How is the exe built? | GitHub Actions on a GitHub-hosted runner, from a tagged commit, with hash-pinned dependencies and a signed provenance attestation | `.github/workflows/release.yml`, `gh attestation verify` |

## What FileLocker does

1. Reads the `.xlsx`, `.docx`, `.pdf` or `.zip` file(s) the user picks.
2. Encrypts each document with the password the user typed, in memory.
3. Writes the encrypted copy to a temporary file next to its destination. It re-opens and
   decrypts that copy in memory to verify it, then renames it to its final name. If
   verification fails, the copy is deleted.
4. For zips: extracts to a private temporary folder, does steps 2-3 for each document, writes
   a new zip, verifies it, and deletes the temporary folder.
5. Appends one line per file to a local log file.

## What FileLocker does not do

- It makes **no network connections** of any kind (see below).
- It does **not start other programs**. The one exception is **Open log**, which opens the
  local log file in the user's default text editor (`os.startfile`).
- It does not write to the registry, install services or tasks, change system settings, or
  need administrator rights.
- It does not upload, collect, or phone home anything. It has no auto-update. New versions
  are deployed by IT.
- It does not decrypt or remove passwords from files. It only adds them.

## Network: three independent layers

1. **No networking code.** `tests/test_no_network.py` parses every application module. It
   fails the build if any module imports `socket`, `ssl`, `http`, `urllib`, `requests`,
   `asyncio`, `subprocess`, `smtplib`, `ftplib`, `webbrowser` or similar. The only allowed
   exceptions are `netguard.py`, which imports `socket` in order to disable it, and
   `selftest.py`, which imports it to prove it is disabled.
2. **Runtime kill switch.** The first thing `main.py` does, before any other import, is call
   `netguard.install()`. This replaces Python's socket entry points (socket creation,
   connect, DNS resolution, ...) with functions that raise an error. Even a bundled library
   could not open a connection through Python. Tests check that sockets, connections, DNS
   lookups and `urllib` are all blocked.
3. **Web/SSL code is not shipped.** The build excludes `ssl`, `http.client`,
   `urllib.request`, `ftplib`, `smtplib`, `xmlrpc`, `socketserver`, `webbrowser` and
   `asyncio` from the exe. The exe's self-test confirms they are absent.

**Limit (stated honestly):** an in-process guard cannot stop native code that calls Windows
networking DLLs directly. Nothing in FileLocker or its dependencies does this. For an
OS-enforced guarantee, add an outbound **Windows Firewall block rule** for `FileLocker.exe`
(command in VERIFYING.md). FileLocker keeps working normally with it in place.

## Files it writes

| What | Where | Contents | Lifetime |
|---|---|---|---|
| Protected copies | Next to the source, or the chosen output folder | Encrypted documents / zip | Permanent (the result) |
| Temporary output | `~filelocker_*.tmp` in the destination folder | Encrypted data being verified | Deleted or renamed within seconds |
| Zip working folder | `%TEMP%\filelocker_zip_*` | **Plain (unencrypted) copies** of the zip's contents | Deleted when the zip run ends, also on errors. Leftovers from a crash are deleted at next start (after 1 hour) |
| Log | `filelocker.log` next to the exe, or `%LOCALAPPDATA%\FileLocker\` if that folder is read-only | Time, outcome, file paths, reason. **Never the password.** File names can be hidden (**Hide file names in log**) | Rotates at 1 MB, keeps 3 old files |

Note: deletion is normal file deletion, not a secure wipe. The zip working folder is in the
user's own `%TEMP%`, which other standard users cannot read. On an encrypted disk
(BitLocker), deleted data stays encrypted at rest.

## Passwords

- Typed into a masked field, compared with the confirmation, and then used only in memory.
- Never written to disk, the log, error messages or the self-test report. Exception
  messages are scrubbed of the password before they are shown or logged.
- Both password fields are cleared after every run.
- Passwords shorter than 10 characters trigger a warning.
- Python cannot reliably wipe a string from memory, so the password may stay in process
  memory until the app closes. Someone who can read the memory of a running process already
  controls the machine.

## Cryptography

| Format | Standard | Details | Library |
|---|---|---|---|
| `.xlsx`, `.docx` | ECMA-376 Agile Encryption (same as Office's *Encrypt with Password*) | AES-256-CBC, SHA-512 key derivation with 100,000 iterations, random salts, HMAC integrity check | `msoffcrypto-tool` (uses `cryptography`) |
| `.pdf` | PDF AES-256 (ISO 32000-2, revision 6) | Same password for opening and permissions | `pypdf` (uses `cryptography`) |

No cryptography is implemented by FileLocker itself. It uses the `cryptography` package
(OpenSSL) through these libraries. After writing each file, FileLocker decrypts it again with
the password to verify it. For PDFs it also checks that the file does **not** open without a
password.

Not supported, on purpose: legacy `.xls`/`.doc`, which only support weak RC4 encryption.

## Dependencies

Bundled at runtime: `msoffcrypto-tool`, `olefile`, `pypdf`, `cryptography`, `cffi`,
`pycparser`, plus Python and Tcl/Tk. PyInstaller's bootloader starts the app.

- Pinned to exact versions **and SHA-256 hashes** (`requirements.txt`, installed with
  `pip --require-hashes`).
- Checked for known vulnerabilities with `pip-audit` on every CI run and release.
- Listed in the SBOM (`FileLocker-<version>-sbom.cdx.json`, CycloneDX) attached to each
  release. Licenses are in `THIRD_PARTY_LICENSES.txt` inside the release.
- Updated only by hand, on purpose: the maintainer edits the pinned versions and every
  update must pass CI before it is merged. Nothing updates automatically.

Application code is scanned with `bandit` (static security analysis) on every CI run.

## Threat model

FileLocker protects the **confidentiality of documents at rest and in transit** (for example
when emailed or uploaded) against anyone who does not have the password.

It does **not** protect against:
- weak or reused passwords. Use 10+ characters or a passphrase.
- sending the password through the same channel as the file. Share it another way, for
  example by phone or a messaging app.
- malware or an attacker already in control of the computer where files are protected or
  opened.
- someone who has the password and shares the decrypted document onwards.

## Antivirus

FileLocker is packaged with PyInstaller in `--onedir` mode. That avoids the self-extracting
behaviour that often triggers antivirus false positives, but some products may still flag
an unsigned PyInstaller exe. Verify the release (VERIFYING.md) and allow it by hash or
signature rather than turning off protection.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (repository → *Security* tab →
*Report a vulnerability*). Do not open a public issue for security problems.
