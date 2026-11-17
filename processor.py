"""Processing pipeline: encrypt -> verify -> move into place, one file at a time.

Kept separate from the GUI so it can be tested without tkinter.

Safety rules:
  * Output is first written to a temporary file in the destination folder.
  * It is re-opened and decrypted with the password (in memory) to verify it.
  * Only after verification passes is it renamed to its final name; otherwise
    the temporary file is deleted and the file is reported as failed.
  * Output naming: "<name>_protected.<ext>" next to the original, or the original
    name when written to a different output folder. Existing files are never
    overwritten; a free "(2)", "(3)", ... name is used instead.
  * Originals are never touched unless overwrite=True, in which case the
    verified temp file atomically replaces the original.
  * The password is never logged or included in any reported message.
"""

from __future__ import annotations

import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import office_crypto
import logger
import pdf_crypto
from scanner import ScanItem

SUCCEEDED = "succeeded"
SKIPPED = "skipped"
FAILED = "failed"

SUFFIX = "_protected"


@dataclass
class Result:
    status: str
    source: Path
    output: Path | None = None
    reason: str = ""


def _scrub(message: str, password: str) -> str:
    """Belt and braces: never let the password leak through an exception message."""
    if password and password in message:
        message = message.replace(password, "***")
    return message


def target_dir(src: Path, source_root: Path | None, output_dir: Path | None) -> Path:
    """Where the output of `src` goes. Mirrors subfolders when an output folder is used."""
    if not output_dir:
        return src.parent
    if source_root and source_root.is_dir():
        try:
            return Path(output_dir) / src.parent.relative_to(source_root)
        except ValueError:
            pass
    return Path(output_dir)


def same_folder(a: Path, b: Path) -> bool:
    """True if both paths point to the same folder (works even if `b` doesn't exist yet)."""
    try:
        if a.exists() and b.exists():
            return os.path.samefile(a, b)
    except OSError:
        pass
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def name_suffix(src: Path, dst_dir: Path) -> str:
    """Naming rule:
      * output goes next to the original  -> "<name>_protected.<ext>"
      * output goes to a different folder -> "<name>.<ext>" (original name kept)
    """
    return SUFFIX if same_folder(src.parent, dst_dir) else ""


def candidate_names(src: Path, dst_dir: Path) -> Iterable[Path]:
    """First choice, then numbered alternatives if that name is already taken:
    same folder:  name_protected.ext, name_protected(2).ext, name_protected(3).ext, ...
    other folder: name.ext,           name(2).ext,           name(3).ext, ...
    """
    stem, ext = src.stem, src.suffix
    suffix = name_suffix(src, dst_dir)
    yield dst_dir / f"{stem}{suffix}{ext}"
    n = 2
    while True:
        yield dst_dir / f"{stem}{suffix}({n}){ext}"
        n += 1


def unique_output_path(src: Path, dst_dir: Path) -> Path:
    for p in candidate_names(src, dst_dir):
        if not p.exists():
            return p
    raise RuntimeError("unreachable")


def planned_output(
    src: Path,
    source_root: Path | None = None,
    output_dir: Path | None = None,
    overwrite: bool = False,
) -> Path:
    """The output path a file would get if it were processed now (for the preview)."""
    if overwrite:
        return src
    return unique_output_path(src, target_dir(src, source_root, output_dir))


def _finalize_new(tmp: Path, src: Path, dst_dir: Path) -> Path:
    """Rename tmp to the first free output name without ever overwriting a file."""
    for _ in range(1000):
        dst = unique_output_path(src, dst_dir)
        try:
            os.rename(tmp, dst)  # on Windows, fails if dst exists -> never clobbers
            return dst
        except FileExistsError:
            continue  # someone created it in between; try the next number
    raise OSError("Could not find a free output file name")


def process_file(
    item: ScanItem,
    password: str,
    output_dir: Path | None = None,
    source_root: Path | None = None,
    overwrite: bool = False,
) -> Result:
    src = item.path
    if not item.supported:
        return Result(SKIPPED, src, reason=item.reason)

    ext = item.ext
    module = pdf_crypto if ext == ".pdf" else office_crypto

    tmp: Path | None = None
    try:
        # 1. Already encrypted?
        if module.is_encrypted(src):
            return Result(SKIPPED, src, reason="Already password-protected/encrypted")

        # 2. Encrypt into a temp file in the destination folder.
        dst_dir = src.parent if overwrite else target_dir(src, source_root, output_dir)
        dst_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="~filelocker_", suffix=".tmp", dir=dst_dir)
        os.close(fd)
        tmp = Path(tmp_name)

        pages = module.encrypt(src, tmp, password)

        # 3. Verify by re-opening and decrypting in memory.
        try:
            if ext == ".pdf":
                pdf_crypto.verify(tmp, password, expected_pages=pages)
            else:
                office_crypto.verify(tmp, password, ext)
        except Exception as exc:
            return Result(FAILED, src, reason=_scrub(f"Verification failed: {exc}", password))

        # 4. Move into place.
        if overwrite:
            os.replace(tmp, src)
            out = src
        else:
            out = _finalize_new(tmp, src, dst_dir)
        tmp = None
        return Result(SUCCEEDED, src, output=out)

    except PermissionError:
        return Result(FAILED, src, reason="File is open in another program or access is denied")
    except FileNotFoundError:
        return Result(FAILED, src, reason="File not found (moved or deleted?)")
    except (office_crypto.InvalidOfficeFile, pdf_crypto.InvalidPdfFile) as exc:
        msg = str(exc)
        status = SKIPPED if "already encrypted" in msg.lower() else FAILED
        return Result(status, src, reason=_scrub(msg, password))
    except OSError as exc:
        return Result(FAILED, src, reason=_scrub(f"I/O error: {exc.strerror or exc}", password))
    except Exception as exc:  # never let one bad file stop the batch
        return Result(FAILED, src, reason=_scrub(f"Unexpected error: {type(exc).__name__}: {exc}", password))
    finally:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


def run_batch(
    items: list[ScanItem],
    password: str,
    output_dir: Path | None = None,
    source_root: Path | None = None,
    overwrite: bool = False,
    on_progress: Callable[[int, int, Result], None] | None = None,
    cancel: threading.Event | None = None,
) -> list[Result]:
    results: list[Result] = []
    total = len(items)
    logger.info(
        f"Run started: {total} item(s), source={logger.path(source_root)}, "
        f"output={'(same as source)' if not output_dir else logger.path(output_dir)}, overwrite={overwrite}"
    )
    for i, item in enumerate(items, 1):
        if cancel is not None and cancel.is_set():
            res = Result(SKIPPED, item.path, reason="Cancelled by user")
        else:
            res = process_file(item, password, output_dir, source_root, overwrite)
        logger.result(res.status, res.source, res.output, res.reason)
        results.append(res)
        if on_progress:
            on_progress(i, total, res)
    counts = {s: sum(r.status == s for r in results) for s in (SUCCEEDED, SKIPPED, FAILED)}
    logger.info(
        f"Run finished: succeeded={counts[SUCCEEDED]} skipped={counts[SKIPPED]} failed={counts[FAILED]}"
    )
    return results
