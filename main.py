"""FileLocker entry point.

Portable, offline tool that password-protects .xlsx, .docx and .pdf files.
"""

import os
import sys

# Make sibling modules importable when launched from another working directory
# (e.g. run_portable.bat with the embeddable Python, which ignores PYTHONPATH).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# FIRST, before anything else is imported: switch off networking for this process.
import netguard  # noqa: E402

netguard.install()


def _enable_dpi_awareness() -> None:
    """Crisp text on high-DPI screens. Harmless if unavailable."""
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def _silence_library_logging() -> None:
    """Third-party libraries (pypdf, msoffcrypto) log to the root logger. Swallow that:
    the windowed exe has no console, and only logger.py's own file log is wanted."""
    import logging

    logging.getLogger().addHandler(logging.NullHandler())
    logging.getLogger().setLevel(logging.CRITICAL)


def _report_startup_error(exc: BaseException) -> None:
    """The windowed exe has no console: put the traceback in the log and show a dialog."""
    import traceback

    details = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    try:
        import logger

        logger.error("Startup failed:\n" + details)
    except Exception:
        pass
    hint = ""
    if "too long" in str(exc).lower():
        hint = ("\n\nThe folder path is too long for Windows. Move the FileLocker folder to a "
                "shorter location, e.g. C:\\Users\\<you>\\Tools\\FileLocker.")
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("FileLocker could not start", f"{type(exc).__name__}: {exc}{hint}")
        root.destroy()
    except Exception:
        pass


def main() -> None:
    _silence_library_logging()
    if len(sys.argv) >= 2 and sys.argv[1] == "--selftest":
        import selftest

        sys.exit(selftest.run(sys.argv[2] if len(sys.argv) >= 3 else None))
    _enable_dpi_awareness()
    try:
        import gui
    except Exception as exc:
        _report_startup_error(exc)
        sys.exit(1)
    gui.run()


if __name__ == "__main__":
    main()
