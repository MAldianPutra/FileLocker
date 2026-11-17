"""Action/result log written to filelocker.log next to the exe (or main.py).

Only file paths, outcomes and reasons are logged. The password is never passed
to this module. A dedicated, non-propagating logger is used so that debug
output from third-party libraries can never end up in the file.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_NAME = "filelocker.log"
_logger: logging.Logger | None = None
_log_path: Path | None = None


def app_dir() -> Path:
    """Folder containing FileLocker.exe (frozen) or main.py (source)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _candidate_dirs():
    yield app_dir()
    # Fallback when the app folder is read-only (e.g. run from a protected share).
    local = os.environ.get("LOCALAPPDATA")
    if local:
        yield Path(local) / "FileLocker"


def get_logger() -> logging.Logger:
    global _logger, _log_path
    if _logger is not None:
        return _logger

    log = logging.getLogger("filelocker")
    log.setLevel(logging.INFO)
    log.propagate = False

    for d in _candidate_dirs():
        try:
            d.mkdir(parents=True, exist_ok=True)
            path = d / LOG_NAME
            handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s"))
            log.addHandler(handler)
            _log_path = path
            break
        except OSError:
            continue
    else:
        log.addHandler(logging.NullHandler())

    _logger = log
    return log


def log_path() -> Path | None:
    get_logger()
    return _log_path


def info(msg: str) -> None:
    get_logger().info(msg)


def warning(msg: str) -> None:
    get_logger().warning(msg)


def error(msg: str) -> None:
    get_logger().error(msg)


# When True, file and folder names are replaced by a short fingerprint in the log, so the
# log reveals what happened but not which (possibly confidential) files were involved.
_redact = False


def set_redact_names(on: bool) -> None:
    global _redact
    _redact = bool(on)


def redacting() -> bool:
    return _redact


def path(p) -> str:
    """Format a path for the log, honouring the redaction setting."""
    if p is None:
        return "-"
    s = str(p)
    if not _redact:
        return s
    ext = os.path.splitext(s.split("::")[-1])[1].lower()
    digest = hashlib.sha256(s.lower().encode("utf-8")).hexdigest()[:10]
    return f"<name hidden {digest}{ext}>"


def _scrub_names(text: str, *paths) -> str:
    """Remove file/folder names of `paths` from free text (used in redaction mode)."""
    for p in paths:
        if not p:
            continue
        for part in str(p).replace("::", "/").replace("\\", "/").split("/"):
            if len(part) >= 3 and part in text:
                text = text.replace(part, "<name hidden>")
    return text


def result(status: str, source, output=None, reason: str = "") -> None:
    parts = [f"{status.upper():9}", f"src={path(source)}"]
    if output:
        parts.append(f"out={path(output)}")
    if reason:
        parts.append(f"reason={_scrub_names(reason, source, output) if _redact else reason}")
    level = logging.ERROR if status.lower() == "failed" else logging.INFO
    get_logger().log(level, " | ".join(parts))
