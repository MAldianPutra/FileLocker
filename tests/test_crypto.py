"""Self-tests for FileLocker.

Run:  python tests/test_crypto.py      (needs: msoffcrypto-tool, pypdf, cryptography, openpyxl)

Generates sample .xlsx and .pdf files, encrypts them and checks that they cannot
be opened without the password but open correctly with it. Also exercises the
batch rules (skip encrypted / unsupported, name collisions, overwrite, locked files).
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import msoffcrypto  # noqa: E402
import openpyxl  # noqa: E402
from pypdf import PasswordType, PdfReader, PdfWriter  # noqa: E402
from pypdf.errors import FileNotDecryptedError  # noqa: E402

import office_crypto  # noqa: E402
import logger  # noqa: E402
import pdf_crypto  # noqa: E402
import processor  # noqa: E402
import scanner  # noqa: E402
import zip_processor  # noqa: E402

PASSWORD = "S3cret-Test-Pässwörd!"
WRONG = "not-the-password"


def make_xlsx(path: Path, marker: str = "hello") -> Path:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Data"
    ws["A1"] = marker
    ws["B2"] = 42
    wb.save(path)
    return path


def make_docx(path: Path, marker: str = "hello") -> Path:
    """Minimal valid Word document (no python-docx needed)."""
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/'
          'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/officeDocument" Target="word/document.xml"/></Relationships>')
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           f'<w:body><w:p><w:r><w:t>{marker}</w:t></w:r></w:p></w:body></w:document>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", doc)
    return path


def make_pdf(path: Path, pages: int = 3, title: str = "FileLocker test") -> Path:
    w = PdfWriter()
    for _ in range(pages):
        w.add_blank_page(width=200, height=300)
    w.add_metadata({"/Title": title})
    with open(path, "wb") as f:
        w.write(f)
    return path


def decrypt_xlsx_bytes(path: Path, password: str) -> io.BytesIO:
    with open(path, "rb") as f:
        of = msoffcrypto.OfficeFile(f)
        of.load_key(password=password, verify_password=True)
        out = io.BytesIO()
        of.decrypt(out)
    out.seek(0)
    return out


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="filelocker_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestExcel(Base):
    def test_encrypt_roundtrip(self):
        src = make_xlsx(self.tmp / "book.xlsx", marker="secret-cell")
        dst = self.tmp / "book_protected.xlsx"
        self.assertFalse(office_crypto.is_encrypted(src))
        office_crypto.encrypt(src, dst, PASSWORD)
        office_crypto.verify(dst, PASSWORD, ".xlsx")
        self.assertTrue(office_crypto.is_encrypted(dst))

        # Without the password: not a zip, openpyxl cannot open it, wrong password rejected.
        self.assertFalse(zipfile.is_zipfile(dst))
        with self.assertRaises(Exception):
            openpyxl.load_workbook(dst)
        with self.assertRaises(Exception):
            decrypt_xlsx_bytes(dst, WRONG)
        with self.assertRaises(Exception):
            office_crypto.verify(dst, WRONG, ".xlsx")

        # With the password: content intact.
        wb = openpyxl.load_workbook(decrypt_xlsx_bytes(dst, PASSWORD))
        self.assertEqual(wb["Data"]["A1"].value, "secret-cell")
        self.assertEqual(wb["Data"]["B2"].value, 42)

        # Original untouched.
        self.assertTrue(zipfile.is_zipfile(src))
        self.assertNotIn(b"secret-cell", dst.read_bytes())

    def test_invalid_file(self):
        bad = self.tmp / "fake.xlsx"
        bad.write_bytes(b"this is not a workbook")
        with self.assertRaises(office_crypto.InvalidOfficeFile):
            office_crypto.is_encrypted(bad)


class TestWord(Base):
    def test_encrypt_roundtrip(self):
        src = make_docx(self.tmp / "letter.docx", marker="secret-paragraph")
        dst = self.tmp / "letter_protected.docx"
        self.assertFalse(office_crypto.is_encrypted(src))
        office_crypto.encrypt(src, dst, PASSWORD)
        office_crypto.verify(dst, PASSWORD, ".docx")
        self.assertTrue(office_crypto.is_encrypted(dst))

        # Without the password.
        self.assertFalse(zipfile.is_zipfile(dst))
        with self.assertRaises(Exception):
            decrypt_xlsx_bytes(dst, WRONG)
        with self.assertRaises(Exception):
            office_crypto.verify(dst, WRONG, ".docx")
        self.assertNotIn(b"secret-paragraph", dst.read_bytes())

        # With the password: document text intact.
        with zipfile.ZipFile(decrypt_xlsx_bytes(dst, PASSWORD)) as z:
            self.assertIn(b"secret-paragraph", z.read("word/document.xml"))

        self.assertTrue(zipfile.is_zipfile(src))  # original untouched

    def test_small_files_of_any_size(self):
        # Regression: msoffcrypto produced undecryptable output for packages < 4096 bytes.
        for target in (600, 1500, 3000, 4000, 4100, 6000):
            src = make_docx(self.tmp / f"s{target}.docx")
            with zipfile.ZipFile(src, "a", zipfile.ZIP_STORED) as z:
                z.writestr("docProps/pad.bin", os.urandom(max(0, target - src.stat().st_size - 150)))
            dst = self.tmp / f"s{target}_protected.docx"
            office_crypto.encrypt(src, dst, PASSWORD)
            office_crypto.verify(dst, PASSWORD, ".docx")
            with zipfile.ZipFile(decrypt_xlsx_bytes(dst, PASSWORD)) as z:
                self.assertIn(b"hello", z.read("word/document.xml"))

    def test_verify_rejects_wrong_kind(self):
        # A workbook encrypted fine but checked as .docx must fail verification.
        src = make_xlsx(self.tmp / "book.xlsx")
        dst = self.tmp / "out.bin"
        office_crypto.encrypt(src, dst, PASSWORD)
        with self.assertRaises(ValueError):
            office_crypto.verify(dst, PASSWORD, ".docx")

    def test_invalid_file(self):
        bad = self.tmp / "fake.docx"
        bad.write_bytes(b"not a document")
        with self.assertRaises(office_crypto.InvalidOfficeFile):
            office_crypto.is_encrypted(bad)


class TestPdf(Base):
    def test_encrypt_roundtrip(self):
        src = make_pdf(self.tmp / "doc.pdf", pages=3, title="Quarterly secrets")
        dst = self.tmp / "doc_protected.pdf"
        self.assertFalse(pdf_crypto.is_encrypted(src))
        pages = pdf_crypto.encrypt(src, dst, PASSWORD)
        self.assertEqual(pages, 3)
        pdf_crypto.verify(dst, PASSWORD, expected_pages=3)

        # Without the password.
        r = PdfReader(dst)
        self.assertTrue(r.is_encrypted)
        with self.assertRaises(FileNotDecryptedError):
            _ = r.pages[0]
        self.assertEqual(PdfReader(dst).decrypt(""), PasswordType.NOT_DECRYPTED)
        self.assertEqual(PdfReader(dst).decrypt(WRONG), PasswordType.NOT_DECRYPTED)
        with self.assertRaises(Exception):
            pdf_crypto.verify(dst, WRONG)

        # AES-256 => encryption revision 6 (V=5).
        enc = r.trailer["/Encrypt"].get_object()
        self.assertEqual(enc["/V"], 5)
        self.assertEqual(enc["/R"], 6)

        # With the password.
        r = PdfReader(dst)
        self.assertNotEqual(r.decrypt(PASSWORD), PasswordType.NOT_DECRYPTED)
        self.assertEqual(len(r.pages), 3)
        self.assertEqual(r.metadata.title, "Quarterly secrets")

        self.assertFalse(PdfReader(src).is_encrypted)  # original untouched

    def test_invalid_file(self):
        bad = self.tmp / "fake.pdf"
        bad.write_bytes(b"not a pdf at all")
        with self.assertRaises(pdf_crypto.InvalidPdfFile):
            pdf_crypto.is_encrypted(bad)


class TestScanner(Base):
    def test_scan_folder(self):
        make_xlsx(self.tmp / "a.xlsx")
        make_pdf(self.tmp / "b.PDF")
        (self.tmp / "c.xls").write_bytes(b"x")
        (self.tmp / "d.xlsm").write_bytes(b"x")
        (self.tmp / "e.txt").write_bytes(b"x")
        make_docx(self.tmp / "g.docx")
        (self.tmp / "h.doc").write_bytes(b"x")
        (self.tmp / "~$g.docx").write_bytes(b"x")
        (self.tmp / "~$a.xlsx").write_bytes(b"x")
        sub = self.tmp / "sub"
        sub.mkdir()
        make_pdf(sub / "f.pdf")

        flat = {i.path.name: i for i in scanner.scan(self.tmp)}
        self.assertEqual(set(flat), {"a.xlsx", "b.PDF", "c.xls", "d.xlsm", "~$a.xlsx",
                                     "g.docx", "h.doc", "~$g.docx"})
        self.assertTrue(flat["g.docx"].supported)
        self.assertFalse(flat["h.doc"].supported)
        self.assertIn("only .docx", flat["h.doc"].reason)
        self.assertFalse(flat["~$g.docx"].supported)
        self.assertTrue(flat["a.xlsx"].supported and flat["b.PDF"].supported)
        self.assertFalse(flat["c.xls"].supported)
        self.assertIn("only .xlsx", flat["d.xlsm"].reason)
        self.assertFalse(flat["~$a.xlsx"].supported)

        deep = {i.path.name for i in scanner.scan(self.tmp, include_subfolders=True)}
        self.assertIn("f.pdf", deep)

    def test_scan_single_file(self):
        f = make_pdf(self.tmp / "x.pdf")
        items = scanner.scan(f)
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0].supported)


class TestProcessor(Base):
    def run_folder(self, folder: Path, **kw):
        items = scanner.scan(folder, include_subfolders=kw.pop("include_subfolders", False))
        return processor.run_batch(items, PASSWORD, source_root=folder, **kw)

    def by_name(self, results):
        return {r.source.name: r for r in results}

    def test_batch_rules(self):
        make_xlsx(self.tmp / "a.xlsx")
        make_pdf(self.tmp / "b.pdf")
        (self.tmp / "old.xls").write_bytes(b"x")
        (self.tmp / "macro.xlsm").write_bytes(b"x")
        (self.tmp / "broken.pdf").write_bytes(b"garbage")
        office_crypto.encrypt(make_xlsx(self.tmp / "tmp.xlsx"), self.tmp / "already.xlsx", "other")
        (self.tmp / "tmp.xlsx").unlink()
        make_docx(self.tmp / "w.docx", marker="word-body")
        (self.tmp / "legacy.doc").write_bytes(b"x")
        (self.tmp / "broken.docx").write_bytes(b"garbage")
        office_crypto.encrypt(make_docx(self.tmp / "tmp.docx"), self.tmp / "already.docx", "other")
        (self.tmp / "tmp.docx").unlink()
        w = PdfWriter()
        w.add_blank_page(100, 100)
        w.encrypt("other", algorithm="AES-256")
        with open(self.tmp / "already.pdf", "wb") as f:
            w.write(f)

        res = self.by_name(self.run_folder(self.tmp))
        self.assertEqual(res["a.xlsx"].status, processor.SUCCEEDED)
        self.assertEqual(res["a.xlsx"].output.name, "a_protected.xlsx")
        self.assertEqual(res["b.pdf"].status, processor.SUCCEEDED)
        self.assertEqual(res["old.xls"].status, processor.SKIPPED)
        self.assertEqual(res["macro.xlsm"].status, processor.SKIPPED)
        self.assertEqual(res["already.xlsx"].status, processor.SKIPPED)
        self.assertIn("Already", res["already.xlsx"].reason)
        self.assertEqual(res["already.pdf"].status, processor.SKIPPED)
        self.assertEqual(res["broken.pdf"].status, processor.FAILED)
        self.assertEqual(res["w.docx"].status, processor.SUCCEEDED)
        self.assertEqual(res["w.docx"].output.name, "w_protected.docx")
        self.assertEqual(res["legacy.doc"].status, processor.SKIPPED)
        self.assertIn("only .docx", res["legacy.doc"].reason)
        self.assertEqual(res["already.docx"].status, processor.SKIPPED)
        self.assertEqual(res["broken.docx"].status, processor.FAILED)

        office_crypto.verify(self.tmp / "w_protected.docx", PASSWORD, ".docx")
        self.assertTrue(zipfile.is_zipfile(self.tmp / "w.docx"))
        office_crypto.verify(self.tmp / "a_protected.xlsx", PASSWORD, ".xlsx")
        pdf_crypto.verify(self.tmp / "b_protected.pdf", PASSWORD)
        # Originals untouched; no temp files left behind.
        self.assertTrue(zipfile.is_zipfile(self.tmp / "a.xlsx"))
        self.assertFalse(PdfReader(self.tmp / "b.pdf").is_encrypted)
        self.assertEqual(list(self.tmp.glob("~filelocker_*")), [])

    def test_name_collision(self):
        src = make_pdf(self.tmp / "r.pdf")
        item = scanner.classify(src)
        outs = [processor.process_file(item, PASSWORD).output.name for _ in range(3)]
        self.assertEqual(outs, ["r_protected.pdf", "r_protected(2).pdf", "r_protected(3).pdf"])

    def test_output_folder_mirrors_subfolders(self):
        src = self.tmp / "src"
        (src / "sub").mkdir(parents=True)
        make_xlsx(src / "top.xlsx")
        make_pdf(src / "sub" / "deep.pdf")
        out = self.tmp / "out"
        res = self.run_folder(src, include_subfolders=True, output_dir=out)
        self.assertTrue(all(r.status == processor.SUCCEEDED for r in res), res)
        # Different folder -> original names are kept.
        self.assertEqual(sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()),
                         sorted(["top.xlsx", str(Path("sub") / "deep.pdf")]))
        office_crypto.verify(out / "top.xlsx", PASSWORD, ".xlsx")
        pdf_crypto.verify(out / "sub" / "deep.pdf", PASSWORD)
        # Sources untouched, nothing written next to them.
        self.assertTrue(zipfile.is_zipfile(src / "top.xlsx"))
        self.assertFalse(PdfReader(src / "sub" / "deep.pdf").is_encrypted)
        self.assertEqual(list(src.rglob("*_protected*")), [])

    def test_output_folder_name_collision(self):
        src = make_docx(self.tmp / "memo.docx")
        out = self.tmp / "out"
        out.mkdir()
        (out / "memo.docx").write_bytes(b"someone else's file")
        item = scanner.classify(src)
        names = [processor.process_file(item, PASSWORD, output_dir=out, source_root=self.tmp).output.name
                 for _ in range(2)]
        self.assertEqual(names, ["memo(2).docx", "memo(3).docx"])
        self.assertEqual((out / "memo.docx").read_bytes(), b"someone else's file")  # never overwritten

    def test_output_folder_same_as_source_uses_suffix(self):
        src = make_pdf(self.tmp / "same.pdf")
        # Explicitly choosing the source folder (even spelled differently) still adds the suffix.
        spelled = Path(str(self.tmp).upper() + os.sep)
        r = processor.process_file(scanner.classify(src), PASSWORD, output_dir=spelled, source_root=self.tmp)
        self.assertEqual(r.status, processor.SUCCEEDED)
        self.assertEqual(r.output.name, "same_protected.pdf")
        self.assertFalse(PdfReader(src).is_encrypted)

    def test_planned_output_matches_result(self):
        src = make_xlsx(self.tmp / "plan.xlsx")
        out = self.tmp / "o"
        self.assertEqual(processor.planned_output(src, self.tmp, None).name, "plan_protected.xlsx")
        self.assertEqual(processor.planned_output(src, self.tmp, out), out / "plan.xlsx")
        self.assertEqual(processor.planned_output(src, self.tmp, out, overwrite=True), src)
        r = processor.process_file(scanner.classify(src), PASSWORD, output_dir=out, source_root=self.tmp)
        self.assertEqual(r.output, out / "plan.xlsx")

    def test_overwrite_original(self):
        src = make_xlsx(self.tmp / "o.xlsx", marker="keep-me")
        r = processor.process_file(scanner.classify(src), PASSWORD, overwrite=True)
        self.assertEqual(r.status, processor.SUCCEEDED)
        self.assertEqual(r.output, src)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["o.xlsx"])
        wb = openpyxl.load_workbook(decrypt_xlsx_bytes(src, PASSWORD))
        self.assertEqual(wb.active["A1"].value, "keep-me")

    def test_locked_file_reported(self):
        src = make_pdf(self.tmp / "locked.pdf")
        item = scanner.classify(src)
        import unittest.mock as mock

        with mock.patch.object(pdf_crypto, "is_encrypted", side_effect=PermissionError(13, "denied")):
            r = processor.process_file(item, PASSWORD)
        self.assertEqual(r.status, processor.FAILED)
        self.assertIn("open in another program", r.reason)

    def test_verification_failure_deletes_output(self):
        src = make_pdf(self.tmp / "v.pdf")
        import unittest.mock as mock

        with mock.patch.object(pdf_crypto, "verify", side_effect=ValueError("boom")):
            r = processor.process_file(scanner.classify(src), PASSWORD)
        self.assertEqual(r.status, processor.FAILED)
        self.assertIn("Verification failed", r.reason)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["v.pdf"])

    def test_password_never_in_messages(self):
        src = make_pdf(self.tmp / "p.pdf")
        import unittest.mock as mock

        with mock.patch.object(pdf_crypto, "encrypt", side_effect=RuntimeError(f"leak {PASSWORD}")):
            r = processor.process_file(scanner.classify(src), PASSWORD)
        self.assertEqual(r.status, processor.FAILED)
        self.assertNotIn(PASSWORD, r.reason)

    def test_password_never_logged(self):
        make_xlsx(self.tmp / "l.xlsx")
        self.run_folder(self.tmp)
        log = logger.log_path()
        self.assertIsNotNone(log)
        for h in logger.get_logger().handlers:
            h.flush()
        self.assertNotIn(PASSWORD, log.read_text(encoding="utf-8"))


class TestLogRedaction(Base):
    def test_hidden_names_do_not_reach_the_log(self):
        secret_name = "Client-Acme-Salaries"
        folder = self.tmp / "Confidential-Project-X"
        folder.mkdir()
        make_xlsx(folder / f"{secret_name}.xlsx")
        (folder / f"{secret_name}-broken.pdf").write_bytes(b"garbage")
        z = self.tmp / "Acme-Bundle.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.write(folder / f"{secret_name}.xlsx", f"Inner-Secret-Dir/{secret_name}.xlsx")
        log = logger.log_path()
        before = log.read_text(encoding="utf-8") if log.exists() else ""
        logger.set_redact_names(True)
        try:
            processor.run_batch(scanner.scan(folder), PASSWORD, source_root=folder)
            zip_processor.process_zip(z, PASSWORD)
        finally:
            logger.set_redact_names(False)
        for h in logger.get_logger().handlers:
            h.flush()
        new = log.read_text(encoding="utf-8")[len(before):]
        self.assertIn("<name hidden", new)
        self.assertIn("SUCCEEDED", new)
        for leak in (secret_name, "Confidential-Project-X", "Acme-Bundle", "Inner-Secret-Dir", PASSWORD):
            self.assertNotIn(leak, new)


class TestZip(Base):
    """Zip in -> each document protected -> zip out."""

    def make_client_zip(self, path: Path, extra: dict[str, bytes] | None = None) -> Path:
        docs = self.tmp / "_docs"
        docs.mkdir(exist_ok=True)
        make_xlsx(docs / "x.xlsx", marker="zip-xlsx")
        make_docx(docs / "d.docx", marker="zip-docx")
        make_pdf(docs / "p.pdf", pages=2)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("Report/", b"")
            z.write(docs / "x.xlsx", "Report/Budget 2026.xlsx")
            z.write(docs / "d.docx", "Report/Letter.docx")
            z.write(docs / "p.pdf", "Report/Sub/Contract é.pdf")
            z.writestr("Report/notes.txt", b"plain notes")
            z.writestr("Report/old.xls", b"legacy")
            z.writestr("Empty folder/", b"")
            z.writestr("__MACOSX/Report/._Letter.docx", b"mac metadata")
            for name, data in (extra or {}).items():
                z.writestr(name, data)
        shutil.rmtree(docs)
        return path

    def assert_no_workdirs_left(self):
        left = list(Path(tempfile.gettempdir()).glob(zip_processor.WORKDIR_PREFIX + "*"))
        mine = [d for d in left if d.stat().st_mtime > self.started - 1]
        self.assertEqual(mine, [], "extracted temp copies were not deleted")

    def setUp(self):
        super().setUp()
        self.started = time.time()

    def test_zip_roundtrip(self):
        src = self.make_client_zip(self.tmp / "client.zip")
        original_bytes = src.read_bytes()
        res = zip_processor.process_zip(src, PASSWORD)
        self.assertEqual(res.status, processor.SUCCEEDED, res.reason)
        self.assertEqual(res.output, self.tmp / "client_protected.zip")
        self.assertEqual(src.read_bytes(), original_bytes)  # original zip untouched
        self.assertEqual(res.count(processor.SUCCEEDED), 3)
        self.assertEqual(res.count(processor.SKIPPED), 3)    # txt, xls, mac metadata
        self.assertEqual(res.count(processor.FAILED), 0)
        self.assertIn("NOT password-protected", res.reason)

        with zipfile.ZipFile(src) as zin, zipfile.ZipFile(res.output) as zout:
            self.assertIsNone(zout.testzip())
            # Same entries, same order, same folder structure (incl. empty folder).
            self.assertEqual(zout.namelist(), zin.namelist())
            work = self.tmp / "check"
            work.mkdir()
            for name in ("Report/Budget 2026.xlsx", "Report/Letter.docx", "Report/Sub/Contract é.pdf"):
                data = zout.read(name)
                self.assertNotEqual(data, zin.read(name))
                f = work / Path(name).name
                f.write_bytes(data)
                if name.endswith(".pdf"):
                    pdf_crypto.verify(f, PASSWORD, expected_pages=2)
                    self.assertEqual(PdfReader(f).decrypt(WRONG), PasswordType.NOT_DECRYPTED)
                else:
                    office_crypto.verify(f, PASSWORD, Path(name).suffix)
                    with self.assertRaises(Exception):
                        decrypt_xlsx_bytes(f, WRONG)
            wb = openpyxl.load_workbook(decrypt_xlsx_bytes(work / "Budget 2026.xlsx", PASSWORD))
            self.assertEqual(wb["Data"]["A1"].value, "zip-xlsx")
            # Unsupported files are carried over byte-for-byte.
            for name in ("Report/notes.txt", "Report/old.xls", "__MACOSX/Report/._Letter.docx"):
                self.assertEqual(zout.read(name), zin.read(name))
        self.assertEqual(list(self.tmp.glob("~filelocker_*")), [])
        self.assert_no_workdirs_left()

    def test_preview(self):
        src = self.make_client_zip(self.tmp / "c.zip")
        plans = {p.name: p for p in zip_processor.preview(src)}
        self.assertTrue(plans["Report/Budget 2026.xlsx"].will_encrypt)
        self.assertTrue(plans["Report/Sub/Contract é.pdf"].will_encrypt)
        self.assertFalse(plans["Report/old.xls"].will_encrypt)
        self.assertFalse(plans["Report/notes.txt"].will_encrypt)
        self.assertFalse(plans["__MACOSX/Report/._Letter.docx"].will_encrypt)
        self.assertNotIn("Report", plans)  # folders are not listed

    def test_output_folder_keeps_name_and_collision(self):
        src = self.make_client_zip(self.tmp / "client.zip")
        out = self.tmp / "out"
        r1 = zip_processor.process_zip(src, PASSWORD, output_dir=out)
        r2 = zip_processor.process_zip(src, PASSWORD, output_dir=out)
        self.assertEqual(r1.output, out / "client.zip")
        self.assertEqual(r2.output, out / "client(2).zip")

    def test_overwrite_original_zip(self):
        src = self.make_client_zip(self.tmp / "client.zip")
        res = zip_processor.process_zip(src, PASSWORD, overwrite=True)
        self.assertEqual(res.status, processor.SUCCEEDED, res.reason)
        self.assertEqual(res.output, src)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["client.zip"])
        with zipfile.ZipFile(src) as z:
            self.assertTrue(z.read("Report/Letter.docx").startswith(office_crypto.OLE_MAGIC))

    def test_failed_file_means_no_zip(self):
        src = self.make_client_zip(self.tmp / "client.zip", extra={"Report/broken.pdf": b"garbage"})
        res = zip_processor.process_zip(src, PASSWORD)
        self.assertEqual(res.status, processor.FAILED)
        self.assertIn("no zip was created", res.reason)
        self.assertEqual(res.count(processor.FAILED), 1)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["client.zip"])
        self.assert_no_workdirs_left()

    def test_already_encrypted_file_is_kept_as_is(self):
        enc = self.tmp / "enc.docx"
        office_crypto.encrypt(make_docx(self.tmp / "plain.docx"), enc, "other-password")
        src = self.make_client_zip(self.tmp / "client.zip", extra={"Report/already.docx": enc.read_bytes()})
        res = zip_processor.process_zip(src, PASSWORD)
        self.assertEqual(res.status, processor.SUCCEEDED, res.reason)
        entry = {r.source.as_posix(): r for r in res.entries}["Report/already.docx"]
        self.assertEqual(entry.status, processor.SKIPPED)
        self.assertIn("Already", entry.reason)
        with zipfile.ZipFile(res.output) as z:
            self.assertEqual(z.read("Report/already.docx"), enc.read_bytes())

    def test_unsafe_zips_rejected(self):
        cases = {
            "slip.zip": "../evil.pdf",
            "abs.zip": "/abs.pdf",
            "drive.zip": "C:/x.pdf",
            "reserved.zip": "CON.pdf",
        }
        pdf = make_pdf(self.tmp / "ok.pdf").read_bytes()
        for zname, entry in cases.items():
            z = self.tmp / zname
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("fine.pdf", pdf)
                zf.writestr(zipfile.ZipInfo(entry), pdf)
            with self.assertRaises(zip_processor.ZipRejected, msg=zname):
                zip_processor.preview(z)
            res = zip_processor.process_zip(z, PASSWORD)
            self.assertEqual(res.status, processor.FAILED, zname)
        self.assertFalse((self.tmp.parent / "evil.pdf").exists())
        self.assertEqual(list(self.tmp.glob("*_protected*")), [])
        self.assert_no_workdirs_left()

    def test_duplicate_names_rejected(self):
        z = self.tmp / "dup.zip"
        pdf = make_pdf(self.tmp / "ok.pdf").read_bytes()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("A/report.pdf", pdf)
                zf.writestr("a/REPORT.pdf", pdf)
        with self.assertRaises(zip_processor.ZipRejected):
            zip_processor.preview(z)

    def test_password_protected_zip_rejected(self):
        z = self.tmp / "locked.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("doc.pdf", make_pdf(self.tmp / "x.pdf").read_bytes())
        # zipfile can't write encrypted zips; set the "encrypted" flag bit directly in the
        # local header (offset 6) and central directory header (offset 8), as a real
        # password-protected zip has it.
        data = bytearray(z.read_bytes())
        data[data.index(b"PK\x03\x04") + 6] |= 0x1
        data[data.index(b"PK\x01\x02") + 8] |= 0x1
        z.write_bytes(bytes(data))
        with self.assertRaises(zip_processor.ZipRejected):
            zip_processor.preview(z)
        res = zip_processor.process_zip(z, PASSWORD)
        self.assertEqual(res.status, processor.FAILED)
        self.assertIn("password-protected", res.reason)

    def test_not_a_zip_and_no_documents(self):
        bad = self.tmp / "bad.zip"
        bad.write_bytes(b"not a zip")
        self.assertEqual(zip_processor.process_zip(bad, PASSWORD).status, processor.FAILED)
        empty = self.tmp / "nodocs.zip"
        with zipfile.ZipFile(empty, "w") as zf:
            zf.writestr("readme.txt", b"hi")
        res = zip_processor.process_zip(empty, PASSWORD)
        self.assertEqual(res.status, processor.SKIPPED)
        self.assertIsNone(res.output)

    def test_utf8_names_without_flag_are_repaired(self):
        # Some zip tools store UTF-8 names without setting the UTF-8 flag; Python would
        # show them garbled. The new zip must carry the real name.
        z = self.tmp / "names.zip"
        pdf = make_pdf(self.tmp / "n.pdf").read_bytes()
        import unittest.mock as mock
        orig = zipfile.ZipInfo._encodeFilenameFlags

        def no_flag(self):
            return self.filename.encode("utf-8"), self.flag_bits & ~0x800

        with mock.patch.object(zipfile.ZipInfo, "_encodeFilenameFlags", no_flag):
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("Laporan Keuangan – Café.pdf", pdf)
        self.assertIsNot(zipfile.ZipInfo._encodeFilenameFlags, no_flag)
        self.assertIs(zipfile.ZipInfo._encodeFilenameFlags, orig)
        with zipfile.ZipFile(z) as zf:
            self.assertNotEqual(zf.namelist()[0], "Laporan Keuangan – Café.pdf")  # garbled by Python
        res = zip_processor.process_zip(z, PASSWORD)
        self.assertEqual(res.status, processor.SUCCEEDED, res.reason)
        with zipfile.ZipFile(res.output) as zf:
            self.assertEqual(zf.namelist(), ["Laporan Keuangan – Café.pdf"])

    def test_password_not_logged_in_zip_mode(self):
        src = self.make_client_zip(self.tmp / "client.zip")
        zip_processor.process_zip(src, PASSWORD)
        for h in logger.get_logger().handlers:
            h.flush()
        self.assertNotIn(PASSWORD, logger.log_path().read_text(encoding="utf-8"))


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    sys.exit(0 if result.wasSuccessful() else 1)
