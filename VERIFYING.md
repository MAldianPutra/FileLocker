# Verifying a FileLocker release

Every release on the GitHub **Releases** page contains:

| File | Purpose |
|---|---|
| `FileLocker-<version>-win64.zip` | The portable app |
| `SHA256SUMS.txt` | SHA-256 checksums of the zip, the exe inside it, the SBOM and the self-test report |
| `FileLocker-<version>-sbom.cdx.json` | Software Bill of Materials (CycloneDX): every bundled third-party package and version |
| `FileLocker-<version>-selftest.txt` | Self-test report of the exact exe in the zip, produced by the build |

Releases are built by the `Release` GitHub Actions workflow on a GitHub-hosted Windows runner,
from the tagged commit. GitHub signs a **build provenance attestation** for the zip and the
exe. Below, replace `<version>` with the release number (for example `1.0.0`).

## 1. Check the checksum (1 minute)

```powershell
Get-FileHash .\FileLocker-<version>-win64.zip -Algorithm SHA256
```

Compare the hash with the line for the zip in `SHA256SUMS.txt`. After extracting, you can
check `FileLocker\FileLocker.exe` the same way.

## 2. Check where it was built (2 minutes)

With the [GitHub CLI](https://cli.github.com/):

```powershell
gh attestation verify .\FileLocker-<version>-win64.zip --repo MAldianPutra/FileLocker
gh attestation verify .\FileLocker\FileLocker.exe    --repo MAldianPutra/FileLocker
```

A successful result proves the file was produced by this repository's GitHub Actions
workflow. The output names the exact workflow file, commit SHA and run. It also proves the
file has not been changed since. A file built anywhere else, or modified afterwards, fails
this check.

## 3. Match it to the source

- The commit SHA appears in the attestation, in **About** in the app, and in the exe's
  **Properties → Details → Product version**.
- Review the code at that commit on GitHub. The application is about 2,000 lines of Python.
  [SECURITY.md](SECURITY.md) describes what each part does.
- Compare `FileLocker-<version>-sbom.cdx.json` (or `requirements.txt` at that commit) with
  your approved-software list.

## 4. Run the self-test on your own machine

The self-test runs without the GUI. It checks the network kill switch, confirms that
web/SSL modules are absent, and round-trips sample `.xlsx`/`.docx`/`.pdf` files and a
zip. It only uses a temporary folder, which it deletes afterwards.

```powershell
Start-Process .\FileLocker\FileLocker.exe -ArgumentList '--selftest', "$PWD\selftest.txt" -Wait
Get-Content .\selftest.txt
```

Expect `RESULT: PASS`, with the same lines as the published `-selftest.txt`.

## 5. Confirm there is no network activity

Any one of these works:

- **Resource Monitor** (`resmon`) → *Network* tab, or Sysinternals **TCPView**: use
  FileLocker normally. `FileLocker.exe` never appears with a connection.
- **Firewall rule (OS-enforced, recommended):** block all outbound traffic for the exe.
  FileLocker works unchanged.
  ```powershell
  New-NetFirewallRule -DisplayName "FileLocker - block outbound" -Direction Outbound `
      -Program "C:\Program Files\FileLocker\FileLocker.exe" -Action Block
  ```
  (Run as administrator, and adjust the path. It can also be pushed by GPO or Intune.)
- **Sysinternals Process Monitor:** filter on `Process Name is FileLocker.exe` and
  `Operation begins with TCP` or `UDP`. Nothing appears.

## 6. Allow it on managed laptops

FileLocker is not code-signed by its authors. To allow it under AppLocker or WDAC (App
Control), choose one:

- **Allow by file hash:** take the SHA-256 of `FileLocker.exe` (and the DLLs in `_internal`
  if your policy covers DLLs). You need a new rule for each release.
- **Sign it with your organisation's code-signing certificate (recommended)** after
  reviewing a release, then allow it by publisher. For example:
  ```powershell
  signtool sign /fd SHA256 /tr <your-timestamp-server> /td SHA256 /a .\FileLocker\FileLocker.exe
  ```

To deploy, copy the extracted `FileLocker` folder to a fixed location, such as
`C:\Program Files\FileLocker`, using Intune, SCCM or GPO. If that folder is read-only for
users, FileLocker writes its log to `%LOCALAPPDATA%\FileLocker\` automatically.

## 7. Or build it yourself

Instead of trusting the published binaries, you can build from the reviewed source on a
clean Windows machine with Python 3.14:

```bat
git clone https://github.com/MAldianPutra/FileLocker
cd FileLocker
git checkout v<version>
build.bat
```

The build installs only hash-verified dependencies, runs the full test suite and the exe
self-test, and produces the same folder layout in `dist\FileLocker`.

PyInstaller output is not byte-for-byte reproducible: timestamps and file order inside the
exe differ, so your hash won't match the published one. Compare behaviour, the self-test
report and the dependency list instead. Or simply deploy your own build.
