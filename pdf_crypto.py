"""Encrypt PDFs with pypdf using AES-256 (requires the `cryptography` package).

The same password is used as both the user (open) and owner (permissions)
password, so whoever can open the file has full rights and nobody can open it
without the password.
"""

from __future__ import annotations

import io

from pypdf import PasswordType, PdfReader, PdfWriter


class InvalidPdfFile(Exception):
    pass


def _open_reader(path) -> PdfReader:
    try:
        return PdfReader(path)
    except (PermissionError, FileNotFoundError):
        raise
    except Exception as exc:
        raise InvalidPdfFile(f"Not a valid PDF file ({type(exc).__name__})") from None


def is_encrypted(path) -> bool:
    return bool(_open_reader(path).is_encrypted)


def encrypt(src, dst, password: str) -> int:
    """Encrypt `src` into `dst`. Returns the page count of the source."""
    if not password:
        raise ValueError("Password must not be empty")
    reader = _open_reader(src)
    if reader.is_encrypted:
        raise InvalidPdfFile("PDF is already encrypted")
    try:
        writer = PdfWriter(clone_from=reader)
    except Exception as exc:
        raise InvalidPdfFile(f"Could not read PDF content ({type(exc).__name__})") from None
    writer.encrypt(user_password=password, owner_password=password, algorithm="AES-256")
    buf = io.BytesIO()
    writer.write(buf)
    with open(dst, "wb") as fout:
        fout.write(buf.getvalue())
    return len(reader.pages)


def verify(path, password: str, expected_pages: int | None = None) -> None:
    """Re-open `path`, check it is encrypted, refuses an empty password and opens with `password`."""
    reader = PdfReader(path)
    if not reader.is_encrypted:
        raise ValueError("Output is not encrypted")
    if reader.decrypt("") != PasswordType.NOT_DECRYPTED:
        raise ValueError("Output opens without a password")

    reader = PdfReader(path)
    if reader.decrypt(password) == PasswordType.NOT_DECRYPTED:
        raise ValueError("Output does not open with the given password")
    n = len(reader.pages)
    if expected_pages is not None and n != expected_pages:
        raise ValueError(f"Page count mismatch after encryption ({n} != {expected_pages})")
    for page in reader.pages:
        _ = page.mediabox  # force each page object to be decrypted and parsed
