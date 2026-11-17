"""Encrypt Office Open XML files (.xlsx, .docx) with msoffcrypto-tool.

Uses ECMA-376 Agile encryption (AES-256) - the same format Excel and Word produce
with File > Info > Protect > Encrypt with Password, so Office will prompt for the
password when the file is opened.

Legacy binary formats (.xls, .doc) are NOT supported: msoffcrypto-tool can only
decrypt those, not encrypt them.
"""

from __future__ import annotations

import io
import os
import zipfile

import msoffcrypto
from msoffcrypto.format.ooxml import OOXMLFile

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Main part folder inside the package, used to sanity-check the decrypted output.
MAIN_PART_PREFIX = {
    ".xlsx": "xl/",
    ".docx": "word/",
}
SUPPORTED_EXTENSIONS = set(MAIN_PART_PREFIX)

_KIND = {".xlsx": "Excel workbook", ".docx": "Word document"}


class InvalidOfficeFile(Exception):
    pass


def _ext(path) -> str:
    return os.path.splitext(str(path))[1].lower()


def _kind(path) -> str:
    return _KIND.get(_ext(path), "Office file")


def is_encrypted(path) -> bool:
    """True if the file is already password-protected (encrypted)."""
    with open(path, "rb") as f:
        try:
            return bool(msoffcrypto.OfficeFile(f).is_encrypted())
        except Exception as exc:  # msoffcrypto raises FileFormatError & friends
            raise InvalidOfficeFile(
                f"Not a valid {_ext(path)} file ({type(exc).__name__})") from None


# msoffcrypto-tool writes the EncryptedPackage stream into regular 512-byte sectors
# even when it is smaller than the compound-file mini-stream cutoff (4096 bytes).
# Readers (msoffcrypto itself, olefile, Office) then look for it in the mini-stream
# and fail. Packages are therefore padded to at least this size before encrypting.
MIN_PACKAGE_SIZE = 4096


def _pad_package(data: bytes) -> bytes:
    """Pad a small OOXML zip up to MIN_PACKAGE_SIZE using the zip archive comment.

    The archive comment is a standard zip field that Office ignores; the document
    parts themselves are not touched.
    """
    if len(data) >= MIN_PACKAGE_SIZE:
        return data
    buf = io.BytesIO(data)
    with zipfile.ZipFile(buf, "a") as z:
        existing = z.comment or b""
        need = MIN_PACKAGE_SIZE - len(data) + 16
        z.comment = (existing + b" " * need)[:65535]
    padded = buf.getvalue()
    if len(padded) < MIN_PACKAGE_SIZE:  # pragma: no cover - only with a huge existing comment
        raise InvalidOfficeFile("File is too small to encrypt reliably")
    return padded


def encrypt(src, dst, password: str) -> None:
    """Encrypt `src` and write the result to `dst`."""
    if not password:
        raise ValueError("Password must not be empty")
    with open(src, "rb") as fin:
        data = fin.read()
    try:
        office = OOXMLFile(io.BytesIO(data))
    except Exception as exc:
        raise InvalidOfficeFile(
            f"Not a valid {_ext(src)} file ({type(exc).__name__})") from None
    if office.type != "plain":
        raise InvalidOfficeFile(f"{_kind(src)} is already encrypted")
    try:
        office = OOXMLFile(io.BytesIO(_pad_package(data)))
    except zipfile.BadZipFile:
        raise InvalidOfficeFile(f"Not a valid {_ext(src)} file (BadZipFile)") from None
    buf = io.BytesIO()
    office.encrypt(password, buf)
    with open(dst, "wb") as fout:
        fout.write(buf.getvalue())


def verify(path, password: str, ext: str) -> None:
    """Re-open `path`, decrypt it in memory and check it is a sane package of type `ext`.

    `ext` is the extension of the *source* file (the output may be a temp file).
    Raises an exception if anything is wrong.
    """
    prefix = MAIN_PART_PREFIX[ext.lower()]
    with open(path, "rb") as f:
        if f.read(8) != OLE_MAGIC:
            raise ValueError("Output is not an encrypted Office container")
        f.seek(0)
        office = msoffcrypto.OfficeFile(f)
        if not office.is_encrypted():
            raise ValueError("Output is not encrypted")
        office.load_key(password=password, verify_password=True)
        out = io.BytesIO()
        office.decrypt(out)
    out.seek(0)
    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
        if "[Content_Types].xml" not in names or not any(n.startswith(prefix) for n in names):
            raise ValueError(f"Decrypted output is not a valid {ext} file")
        bad = z.testzip()
        if bad is not None:
            raise ValueError(f"Decrypted output is corrupt ({bad})")
