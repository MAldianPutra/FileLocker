"""Find target files by extension.

The scanner never opens files; it only classifies paths so the GUI can show a
preview. Content checks (already encrypted, corrupt, ...) happen at processing
time in processor.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_EXTENSIONS = {".xlsx", ".docx", ".pdf"}

# Extensions we recognise but deliberately refuse, with the reason shown to the user.
UNSUPPORTED_EXTENSIONS = {
    ".xls": "Unsupported format (.xls) - only .xlsx is supported",
    ".xlsm": "Unsupported format (.xlsm) - only .xlsx is supported",
    ".doc": "Unsupported format (.doc) - only .docx is supported",
}


@dataclass
class ScanItem:
    path: Path
    supported: bool
    reason: str = ""  # why it will be skipped (empty when supported)

    @property
    def ext(self) -> str:
        return self.path.suffix.lower()


def classify(path: Path) -> ScanItem | None:
    """Return a ScanItem for a relevant file, or None if the file is irrelevant."""
    ext = path.suffix.lower()
    name = path.name
    if ext in SUPPORTED_EXTENSIONS or ext in UNSUPPORTED_EXTENSIONS:
        # Zips made on a Mac carry "__MACOSX/._name.pdf" metadata files. They only look
        # like documents, so never try to encrypt them.
        if name.startswith("._") or "__MACOSX" in path.parts:
            return ScanItem(path, False, "macOS metadata file (not a real document)")
    if ext in SUPPORTED_EXTENSIONS:
        if name.startswith("~$"):
            # Office creates "~$name.xlsx" / "~$name.docx" owner/lock files while a file is open.
            return ScanItem(path, False, "Office temporary/lock file")
        return ScanItem(path, True)
    if ext in UNSUPPORTED_EXTENSIONS:
        if name.startswith("~$"):
            return None
        return ScanItem(path, False, UNSUPPORTED_EXTENSIONS[ext])
    return None


def scan(source: str | os.PathLike, include_subfolders: bool = False) -> list[ScanItem]:
    """Scan a single file or a folder and return relevant files, sorted by path."""
    src = Path(source)
    if src.is_file():
        item = classify(src)
        if item is None:
            return [ScanItem(src, False, f"Unsupported file type ({src.suffix or 'no extension'})")]
        return [item]

    if not src.is_dir():
        raise FileNotFoundError(f"Source not found: {src}")

    items: list[ScanItem] = []
    if include_subfolders:
        for root, dirs, files in os.walk(src):
            dirs.sort()
            for f in files:
                item = classify(Path(root) / f)
                if item:
                    items.append(item)
    else:
        for entry in src.iterdir():
            if entry.is_file():
                item = classify(entry)
                if item:
                    items.append(item)

    items.sort(key=lambda i: str(i.path).lower())
    return items
