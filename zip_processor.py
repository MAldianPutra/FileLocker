"""Zip workflow: extract a zip -> password-protect each supported file -> zip it again.

The zip itself is NOT password-protected; each .xlsx / .docx / .pdf inside it is.

Rules:
  * The zip is checked before anything is extracted. It is rejected if it has unsafe
    paths (zip-slip: "../", absolute paths, drive letters), file names Windows can't
    use, duplicate names, password-protected entries, or would not fit on the disk.
  * Files are extracted to a private temp folder. That folder holds plain copies of
    the client's documents, so it is always deleted afterwards, even on errors.
  * Each supported file is protected and verified with the password (processor.py).
  * Files that can't be protected (other types, .xls/.doc, already encrypted) are
    put into the new zip unchanged and reported as NOT protected.
  * If any supported file fails, or the run is cancelled, NO zip is created, so a
    zip never silently contains an unprotected copy.
  * The new zip is verified (CRC check, same entries in the same order, and every
    file byte-for-byte equal to the verified copy) before it gets its final name.
  * Naming follows processor.py: "<name>_protected.zip" next to the original zip,
    the original name in a different output folder; existing files are never
    overwritten. With overwrite=True the original zip is replaced.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import shutil
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable

import logger
import processor
from processor import FAILED, SKIPPED, SUCCEEDED, Result
from scanner import SUPPORTED_EXTENSIONS, ScanItem, classify

WORKDIR_PREFIX = "filelocker_zip_"
_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                     *(f"LPT{i}" for i in range(1, 10))}
_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')


class ZipRejected(Exception):
    """The zip as a whole can't be processed safely."""


@dataclass
class ZipEntry:
    info: zipfile.ZipInfo
    name: str          # cleaned, '/'-separated relative path (directories end without '/')
    is_dir: bool

    @property
    def path(self) -> PurePosixPath:
        return PurePosixPath(self.name)


@dataclass
class EntryPlan:
    name: str
    will_encrypt: bool
    note: str = ""     # why it is included unchanged


@dataclass
class ZipResult:
    status: str
    source: Path
    output: Path | None = None
    reason: str = ""
    entries: list[Result] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(r.status == status for r in self.entries)


# --------------------------------------------------------------------------- names
def _oem_codec() -> str:
    try:
        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception:
        return "cp437"


def entry_name(info: zipfile.ZipInfo) -> str:
    """Decode an entry name the way the zip's creator meant it.

    Python decodes names without the UTF-8 flag as cp437. Many tools write UTF-8
    without setting the flag, and Windows Explorer uses the OEM code page, so
    re-decode those names to avoid garbled (mojibake) file names.
    """
    name = info.filename
    if info.flag_bits & 0x800:
        return name
    try:
        raw = name.encode("cp437")
    except UnicodeEncodeError:
        return name
    if raw.isascii():
        return name
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode(_oem_codec())
    except (UnicodeDecodeError, LookupError):
        return name


def _clean_name(raw: str) -> str:
    """Validate an entry name and return it normalised, or raise ZipRejected."""
    name = raw.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ZipRejected(f"Unsafe path in zip (absolute path): {raw}")
    parts = [p for p in name.rstrip("/").split("/")]
    if not parts or any(p == "" for p in parts):
        raise ZipRejected(f"Invalid path in zip: {raw}")
    for p in parts:
        if p in (".", ".."):
            raise ZipRejected(f"Unsafe path in zip (contains '{p}'): {raw}")
        if _BAD_CHARS.search(p) or p.endswith((" ", ".")) or p.split(".")[0].upper() in _WINDOWS_RESERVED:
            raise ZipRejected(f"Zip contains a name Windows can't use: {raw}")
    return "/".join(parts)


# --------------------------------------------------------------------- inspection
def read_entries(zf: zipfile.ZipFile) -> list[ZipEntry]:
    """All entries, validated. Raises ZipRejected if the zip can't be handled safely."""
    entries: list[ZipEntry] = []
    seen: dict[str, str] = {}
    for info in zf.infolist():
        if info.flag_bits & 0x1:
            raise ZipRejected("The zip itself is password-protected; extract it manually first")
        name = _clean_name(entry_name(info))
        key = name.lower()  # Windows file names are case-insensitive
        if key in seen:
            if info.is_dir() and seen[key] == "dir":
                continue
            raise ZipRejected(f"Zip contains duplicate names: {name}")
        seen[key] = "dir" if info.is_dir() else "file"
        entries.append(ZipEntry(info, name, info.is_dir()))
    files = {e.name.lower() for e in entries if not e.is_dir}
    for e in entries:  # a file and a folder with the same name can't both exist
        if e.is_dir and e.name.lower() in files:
            raise ZipRejected(f"Zip contains a file and a folder with the same name: {e.name}")
    return entries


def _open_zip(path: Path) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise ZipRejected("Not a valid zip file") from None


def _plan_for(name: str) -> EntryPlan:
    item = classify(Path(name))
    if item is None:
        ext = PurePosixPath(name).suffix or "no extension"
        return EntryPlan(name, False, f"Not a supported type ({ext})")
    if not item.supported:
        return EntryPlan(name, False, item.reason)
    return EntryPlan(name, True)


def preview(zip_path: str | os.PathLike) -> list[EntryPlan]:
    """What would happen to each file in the zip (directories omitted). Raises ZipRejected."""
    with _open_zip(Path(zip_path)) as zf:
        entries = read_entries(zf)
    return [_plan_for(e.name) for e in entries if not e.is_dir]


# ------------------------------------------------------------------------ helpers
def cleanup_stale_workdirs(max_age_hours: float = 1.0) -> None:
    """Remove temp folders left behind by a crash (they may hold plain documents)."""
    base = Path(tempfile.gettempdir())
    cutoff = time.time() - max_age_hours * 3600
    for d in base.glob(WORKDIR_PREFIX + "*"):
        try:
            if d.is_dir() and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_entry(zf: zipfile.ZipFile, name: str) -> str:
    h = hashlib.sha256()
    with zf.open(name) as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract(zf: zipfile.ZipFile, entries: list[ZipEntry], root: Path) -> None:
    root_resolved = root.resolve()
    for e in entries:
        target = root.joinpath(*e.path.parts)
        # Defence in depth against zip-slip, on top of _clean_name().
        if root_resolved not in target.resolve().parents and target.resolve() != root_resolved:
            raise ZipRejected(f"Unsafe path in zip: {e.name}")
        if e.is_dir:
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(e.info) as src, open(target, "xb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)


def _write_zip(dst: Path, entries: list[ZipEntry], root: Path) -> None:
    with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as out:
        for e in entries:
            arcname = e.name + "/" if e.is_dir else e.name
            zi = zipfile.ZipInfo(arcname, date_time=e.info.date_time)
            zi.external_attr = e.info.external_attr
            if e.is_dir:
                out.writestr(zi, b"")
                continue
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(root.joinpath(*e.path.parts), "rb") as src, out.open(zi, "w") as w:
                shutil.copyfileobj(src, w, 1 << 20)


def _verify_zip(path: Path, entries: list[ZipEntry], root: Path) -> None:
    with zipfile.ZipFile(path) as zf:
        bad = zf.testzip()
        if bad is not None:
            raise ValueError(f"New zip is corrupt ({bad})")
        expected = [e.name + "/" if e.is_dir else e.name for e in entries]
        if zf.namelist() != expected:
            raise ValueError("New zip does not contain the same files as the original")
        for e in entries:
            if not e.is_dir and _sha256_entry(zf, e.name) != _sha256_file(root.joinpath(*e.path.parts)):
                raise ValueError(f"File differs inside the new zip: {e.name}")


# ------------------------------------------------------------------------ process
def process_zip(
    zip_path: str | os.PathLike,
    password: str,
    output_dir: Path | None = None,
    overwrite: bool = False,
    on_progress: Callable[[int, int, Result], None] | None = None,
    cancel: threading.Event | None = None,
) -> ZipResult:
    src = Path(zip_path)
    workdir: Path | None = None
    tmp_zip: Path | None = None
    result = ZipResult(FAILED, src)
    logger.info(f"Zip run started: src={logger.path(src)}, "
                f"output={'(same as source)' if not output_dir else logger.path(output_dir)}, "
                f"overwrite={overwrite}")
    try:
        try:
            with _open_zip(src) as zf:
                entries = read_entries(zf)
                files = [e for e in entries if not e.is_dir]
                plans = [_plan_for(e.name) for e in files]
                if not any(p.will_encrypt for p in plans):
                    result.status, result.reason = SKIPPED, "No .xlsx, .docx or .pdf files in this zip"
                    return result

                needed = sum(e.info.file_size for e in files)
                free = shutil.disk_usage(tempfile.gettempdir()).free
                if needed * 2 + 50_000_000 > free:
                    raise ZipRejected(
                        f"Not enough free disk space to extract the zip "
                        f"({needed / 1e6:.0f} MB needed, twice over, for working copies)")

                workdir = Path(tempfile.mkdtemp(prefix=WORKDIR_PREFIX))
                _extract(zf, entries, workdir)
        except PermissionError:
            result.reason = "Zip is open in another program or access is denied"
            return result
        except FileNotFoundError:
            result.reason = "Zip file not found (moved or deleted?)"
            return result
        except NotImplementedError:
            result.reason = ("Zip uses a compression method that can't be read (e.g. Deflate64 or "
                             "zip encryption). Extract it, zip it again, then retry.")
            return result
        except (ZipRejected, zipfile.BadZipFile) as exc:
            result.reason = str(exc) or "Zip can't be read"
            return result
        except OSError as exc:
            result.reason = f"Could not extract the zip: {exc.strerror or exc}"
            return result

        # Protect each file in the working copy.
        total = len(files)
        for i, (e, plan) in enumerate(zip(files, plans), 1):
            shown = Path(e.name)
            if cancel is not None and cancel.is_set():
                res = Result(SKIPPED, shown, reason="Cancelled by user")
            elif not plan.will_encrypt:
                # SKIPPED inside a zip = kept as-is in the new zip, NOT protected.
                res = Result(SKIPPED, shown, reason=plan.note)
            else:
                item = ScanItem(workdir.joinpath(*e.path.parts), True)
                r = processor.process_file(item, password, overwrite=True)
                res = Result(r.status, shown, reason=r.reason)
            logger.result(res.status, f"{src}::{e.name}", None, res.reason)
            result.entries.append(res)
            if on_progress:
                on_progress(i, total, res)

        if cancel is not None and cancel.is_set():
            result.status, result.reason = SKIPPED, "Cancelled by user - no zip was created"
            return result
        n_failed = result.count(FAILED)
        if n_failed:
            result.reason = f"{n_failed} file(s) could not be protected - no zip was created"
            return result
        if result.count(SUCCEEDED) == 0:
            result.status, result.reason = SKIPPED, "Nothing was protected (all files skipped) - no zip was created"
            return result

        # Re-zip into a temp file next to the final location, verify, then move into place.
        dst_dir = src.parent if overwrite else processor.target_dir(src, src.parent, output_dir)
        try:
            dst_dir.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix="~filelocker_", suffix=".tmp", dir=dst_dir)
            os.close(fd)
            tmp_zip = Path(name)
            _write_zip(tmp_zip, entries, workdir)
            try:
                _verify_zip(tmp_zip, entries, workdir)
            except Exception as exc:
                result.reason = f"Verification of the new zip failed: {exc}"
                return result
            if overwrite:
                os.replace(tmp_zip, src)
                out = src
            else:
                out = processor._finalize_new(tmp_zip, src, dst_dir)
            tmp_zip = None
        except PermissionError:
            result.reason = "Could not write the new zip (file open in another program or access denied)"
            return result
        except OSError as exc:
            result.reason = f"Could not write the new zip: {exc.strerror or exc}"
            return result

        result.status, result.output = SUCCEEDED, out
        unchanged = result.count(SKIPPED)
        if unchanged:
            result.reason = f"{unchanged} file(s) in the zip are NOT password-protected"
        return result

    except Exception as exc:  # never crash the app
        result.status = FAILED
        result.reason = processor._scrub(f"Unexpected error: {type(exc).__name__}: {exc}", password)
        return result
    finally:
        if tmp_zip is not None:
            try:
                tmp_zip.unlink(missing_ok=True)
            except OSError:
                pass
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)
        logger.result(result.status, src, result.output, result.reason)
