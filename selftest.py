"""Built-in self-test: `FileLocker.exe --selftest report.txt`.

Runs without the GUI, on the machine where FileLocker will be used, and writes a
PASS/FAIL report. It lets IT (and the release pipeline) check the actual exe:

  * the network kill switch is active and blocks connections and DNS lookups
  * web/SSL modules are not bundled in the exe
  * .xlsx / .docx / .pdf files and a zip are encrypted, refuse the wrong password
    and open with the right one
  * no temporary files are left behind

It only creates files in a fresh temporary folder, which it deletes afterwards.
The test password is a random throwaway value and is never written anywhere.
"""

from __future__ import annotations

import io
import secrets
import shutil
import socket
import sys
import tempfile
import traceback
import zipfile
from pathlib import Path

import netguard
import version

# Modules that a network-capable program would need. In the built exe they are
# excluded at build time (scripts/build.py), so importing them must fail.
NOT_BUNDLED = ("ssl", "http.client", "urllib.request", "ftplib", "smtplib", "xmlrpc.client",
               "socketserver", "webbrowser", "asyncio")


# ------------------------------------------------------------------ sample files
def _ooxml(path: Path, parts: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, xml in parts.items():
            z.writestr(name, '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + xml)
    return path


_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"  # XML namespace, not a URL fetch
_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_CT = "http://schemas.openxmlformats.org/package/2006/content-types"


def make_docx(path: Path) -> Path:
    return _ooxml(path, {
        "[Content_Types].xml":
            f'<Types xmlns="{_CT}"><Default Extension="rels" ContentType="application/'
            'vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" '
            'ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType='
            '"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels":
            f'<Relationships xmlns="{_PKG_REL}"><Relationship Id="rId1" '
            f'Type="{_REL}/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml":
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>FileLocker self-test</w:t></w:r></w:p></w:body></w:document>',
    })


def make_xlsx(path: Path) -> Path:
    return _ooxml(path, {
        "[Content_Types].xml":
            f'<Types xmlns="{_CT}"><Default Extension="rels" ContentType="application/'
            'vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" '
            'ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType='
            '"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType='
            '"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
        "_rels/.rels":
            f'<Relationships xmlns="{_PKG_REL}"><Relationship Id="rId1" '
            f'Type="{_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml":
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            f'xmlns:r="{_REL}"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels":
            f'<Relationships xmlns="{_PKG_REL}"><Relationship Id="rId1" '
            f'Type="{_REL}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        "xl/worksheets/sheet1.xml":
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>self-test</t></is></c></row>'
            '</sheetData></worksheet>',
    })


def make_pdf(path: Path) -> Path:
    from pypdf import PdfWriter

    w = PdfWriter()
    w.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    w.write(buf)
    path.write_bytes(buf.getvalue())
    return path


# ------------------------------------------------------------------------ checks
def _check_network_blocked() -> str:
    if not netguard.is_installed():
        raise AssertionError("network guard is not installed")
    attempts = {
        "TCP connect": lambda: socket.create_connection(("127.0.0.1", 9), timeout=1),
        "new socket": lambda: socket.socket(),
        "DNS lookup": lambda: socket.getaddrinfo("example.com", 443),
    }
    for name, attempt in attempts.items():
        try:
            attempt()
        except netguard.NetworkBlockedError:
            continue
        raise AssertionError(f"{name} was NOT blocked")
    return "connections, new sockets and DNS lookups are all blocked"


def _check_not_bundled() -> str:
    import importlib

    if not getattr(sys, "frozen", False):
        return "skipped (running from source; applies to the built exe)"
    present = []
    for mod in NOT_BUNDLED:
        try:
            importlib.import_module(mod)
            present.append(mod)
        except ImportError:
            pass
    if present:
        raise AssertionError(f"bundled but should not be: {', '.join(present)}")
    return f"not present in the exe: {', '.join(NOT_BUNDLED)}"


def _check_encrypt(workdir: Path, password: str) -> str:
    import office_crypto
    import pdf_crypto
    import processor
    from scanner import classify

    samples = [make_xlsx(workdir / "sample.xlsx"), make_docx(workdir / "sample.docx"),
               make_pdf(workdir / "sample.pdf")]
    for src in samples:
        res = processor.process_file(classify(src), password)
        if res.status != processor.SUCCEEDED:
            raise AssertionError(f"{src.name}: {res.status} - {res.reason}")
        out = res.output
        if src.suffix == ".pdf":
            from pypdf import PasswordType, PdfReader

            if PdfReader(out).decrypt("wrong-" + password) != PasswordType.NOT_DECRYPTED:
                raise AssertionError("PDF opened with a wrong password")
            pdf_crypto.verify(out, password, expected_pages=1)
        else:
            try:
                office_crypto.verify(out, "wrong-" + password, src.suffix)
            except Exception:
                pass
            else:
                raise AssertionError(f"{src.name} opened with a wrong password")
            office_crypto.verify(out, password, src.suffix)
    return "xlsx, docx and pdf: encrypted, wrong password refused, right password opens"


def _check_zip(workdir: Path, password: str) -> str:
    import processor
    import zip_processor

    src = workdir / "batch.zip"
    with zipfile.ZipFile(src, "w") as z:
        z.write(make_docx(workdir / "z.docx"), "Folder/letter.docx")
        z.write(make_pdf(workdir / "z.pdf"), "Folder/contract.pdf")
        z.writestr("Folder/readme.txt", "unchanged")
    res = zip_processor.process_zip(src, password)
    if res.status != processor.SUCCEEDED:
        raise AssertionError(f"zip: {res.status} - {res.reason}")
    with zipfile.ZipFile(res.output) as z:
        if z.read("Folder/readme.txt") != b"unchanged":
            raise AssertionError("unsupported file was changed")
        if not z.read("Folder/letter.docx").startswith(b"\xd0\xcf\x11\xe0"):
            raise AssertionError("docx inside zip is not encrypted")
    return "zip: documents protected individually, other files unchanged"


def _check_no_leftovers(workdir: Path) -> str:
    import zip_processor

    left = list(workdir.glob("~filelocker_*"))
    left += [d for d in Path(tempfile.gettempdir()).glob(zip_processor.WORKDIR_PREFIX + "*")
             if d.stat().st_mtime >= _started]
    if left:
        raise AssertionError(f"temporary files left behind: {[p.name for p in left]}")
    return "no temporary files left behind"


_started = 0.0


def run(report_path: str | None) -> int:
    import time

    global _started
    _started = time.time() - 1
    netguard.install()
    password = secrets.token_urlsafe(16)  # throwaway; never written anywhere
    workdir = Path(tempfile.mkdtemp(prefix="filelocker_selftest_"))
    info = version.build_info()
    lines = [
        f"{version.version_string()}",
        f"commit: {info['commit']}",
        f"build date: {info['build_date'] or '-'}",
        f"frozen exe: {bool(getattr(sys, 'frozen', False))}",
        f"python: {sys.version.split()[0]}",
        "",
    ]
    checks = [
        ("Network kill switch", _check_network_blocked),
        ("Web/SSL modules not bundled", _check_not_bundled),
        ("Encrypt / verify files", lambda: _check_encrypt(workdir, password)),
        ("Zip workflow", lambda: _check_zip(workdir, password)),
        ("Clean-up", lambda: _check_no_leftovers(workdir)),
    ]
    failed = 0
    try:
        for name, fn in checks:
            try:
                detail = fn()
                lines.append(f"PASS  {name}: {detail}")
            except Exception as exc:
                failed += 1
                msg = str(exc).replace(password, "***")
                lines.append(f"FAIL  {name}: {type(exc).__name__}: {msg}")
                tb = traceback.format_exc().replace(password, "***")
                lines.extend("      " + t for t in tb.rstrip().splitlines()[-6:])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    lines += ["", "RESULT: " + ("PASS" if failed == 0 else f"FAIL ({failed} check(s) failed)")]
    text = "\n".join(lines) + "\n"
    if report_path:
        Path(report_path).write_text(text, encoding="utf-8")
    if sys.stdout is not None:
        print(text)
    return 0 if failed == 0 else 1
