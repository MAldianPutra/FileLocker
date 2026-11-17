"""tkinter user interface for FileLocker."""

from __future__ import annotations

import os
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

import logger
import netguard
import processor
import version
import zip_processor
from scanner import ScanItem, scan

APP_TITLE = "FileLocker - password-protect Excel (.xlsx), Word (.docx) and PDF files"
PAD = {"padx": 6, "pady": 4}
MIN_RECOMMENDED_PASSWORD = 10
# Main button: one button that is "Encrypt files" when idle and "Stop" while running.
# mode -> (text, background, background while pressed, state)
BUTTON_LOOKS = {
    "ready": ("Encrypt files", "#0b5cad", "#084a8c", "normal"),
    "running": ("Stop", "#c62828", "#9f1f1f", "normal"),
    "stopping": ("Stopping...", "#8a8f98", "#8a8f98", "disabled"),
}
STOP_GUARD_SECONDS = 0.6  # clicks this soon after starting are ignored (double-click protection)
NEW_FOLDER_NAME = "Protected"  # folder suggested by the output "New folder" button


def _is_inside(path: Path, folder: Path) -> bool:
    try:
        path.resolve().relative_to(folder.resolve())
        return True
    except (ValueError, OSError):
        return False


class FileLockerApp(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master, padding=10)
        self.master = master
        self.pack(fill="both", expand=True)

        self.mode = tk.StringVar(value="file")
        self.source = tk.StringVar()
        self.subfolders = tk.BooleanVar(value=False)
        self.output = tk.StringVar()
        self.overwrite = tk.BooleanVar(value=False)
        self.show_pw = tk.BooleanVar(value=False)
        self.hide_names = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Choose a file or folder to begin.")

        self.items: list[ScanItem] = []
        self.zip_plans: list[zip_processor.EntryPlan] = []
        self.preview_error = ""
        self.row_ids: dict[Path, str] = {}
        self.queue: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self._btn_mode = "ready"
        self._running_since = 0.0

        self._planned_job: str | None = None

        self.scale = dpi_scale(master)
        self._configure_styles()
        self._build()
        self.output.trace_add("write", self._on_output_changed)

    # ------------------------------------------------------------------ layout
    def _configure_styles(self) -> None:
        """ttk.Treeview uses a fixed pixel row height that does not follow DPI scaling,
        so on high-DPI screens (125%, 150%, ...) the text gets cut off. Size rows from
        the actual font height instead."""
        style = ttk.Style(self.master)
        body = tkfont.nametofont("TkDefaultFont")
        heading = tkfont.nametofont("TkHeadingFont")
        row_h = int(body.metrics("linespace") * 1.45) + 2
        style.configure("Treeview", rowheight=row_h)
        style.configure("Treeview.Heading", padding=(4, int(heading.metrics("linespace") * 0.25)))

    def _build(self) -> None:
        # Source
        src = ttk.LabelFrame(self, text="1. Source")
        src.pack(fill="x", **PAD)
        ttk.Radiobutton(src, text="Single file", variable=self.mode, value="file",
                        command=self._on_mode).grid(row=0, column=0, sticky="w", **PAD)
        ttk.Radiobutton(src, text="Folder", variable=self.mode, value="folder",
                        command=self._on_mode).grid(row=0, column=1, sticky="w", **PAD)
        ttk.Radiobutton(src, text="Zip file", variable=self.mode, value="zip",
                        command=self._on_mode).grid(row=0, column=2, sticky="w", **PAD)
        self.chk_sub = ttk.Checkbutton(src, text="Include subfolders", variable=self.subfolders,
                                       command=self.refresh_preview, state="disabled")
        self.chk_sub.grid(row=0, column=3, sticky="w", **PAD)
        ttk.Entry(src, textvariable=self.source).grid(row=1, column=0, columnspan=4, sticky="ew", **PAD)
        ttk.Button(src, text="Browse...", command=self._browse_source).grid(row=1, column=4, **PAD)
        src.columnconfigure(3, weight=1)

        # Password
        pw = ttk.LabelFrame(self, text="2. Password")
        pw.pack(fill="x", **PAD)
        ttk.Label(pw, text="Password:").grid(row=0, column=0, sticky="w", **PAD)
        self.pw1 = ttk.Entry(pw, show="•", width=36)
        self.pw1.grid(row=0, column=1, sticky="ew", **PAD)
        ttk.Label(pw, text="Confirm:").grid(row=1, column=0, sticky="w", **PAD)
        self.pw2 = ttk.Entry(pw, show="•", width=36)
        self.pw2.grid(row=1, column=1, sticky="ew", **PAD)
        ttk.Checkbutton(pw, text="Show", variable=self.show_pw,
                        command=self._toggle_pw).grid(row=0, column=2, sticky="w", **PAD)
        ttk.Label(pw, text="A forgotten password cannot be recovered.",
                  foreground="#a33").grid(row=1, column=2, sticky="w", **PAD)
        pw.columnconfigure(1, weight=1)

        # Output
        out = ttk.LabelFrame(self, text="3. Output")
        out.pack(fill="x", **PAD)
        ttk.Label(out, text="Output folder (optional):").grid(row=0, column=0, sticky="w", **PAD)
        self.ent_out = ttk.Entry(out, textvariable=self.output)
        self.ent_out.grid(row=0, column=1, sticky="ew", **PAD)
        self.btn_out = ttk.Button(out, text="Browse...", command=self._browse_output)
        self.btn_out.grid(row=0, column=2, **PAD)
        self.btn_out_new = ttk.Button(out, text="New folder", command=self._new_output_folder)
        self.btn_out_new.grid(row=0, column=3, **PAD)
        ttk.Label(out, text="Empty = save next to the source as <name>_protected.<ext>.  "
                            "Another folder = save there under the original name.\n"
                            f"New folder = use a new \"{NEW_FOLDER_NAME}\" folder next to your files "
                            "(created when the first file is saved).",
                  foreground="#555").grid(row=1, column=0, columnspan=4, sticky="w", **PAD)
        ttk.Checkbutton(out, text="Overwrite original files (not recommended)", variable=self.overwrite,
                        command=self._on_overwrite).grid(row=2, column=0, columnspan=4, sticky="w", **PAD)
        out.columnconfigure(1, weight=1)

        # Preview / results
        prev = ttk.LabelFrame(self, text="4. Files to process")
        prev.pack(fill="both", expand=True, **PAD)
        cols = ("file", "planned", "result")
        # Small requested height: the list still grows to fill the window, but never pushes the
        # buttons/progress/status off the bottom on small or high-DPI screens.
        self.tree = ttk.Treeview(prev, columns=cols, show="headings", height=6)
        self.tree.heading("file", text="File")
        self.tree.heading("planned", text="Planned action")
        self.tree.heading("result", text="Result")
        s = self.scale
        self.tree.column("file", width=int(360 * s), minwidth=int(120 * s), anchor="w")
        self.tree.column("planned", width=int(320 * s), minwidth=int(100 * s), anchor="w")
        self.tree.column("result", width=int(300 * s), minwidth=int(100 * s), anchor="w")
        self.tree.tag_configure(processor.SUCCEEDED, foreground="#1a7f37")
        self.tree.tag_configure(processor.SKIPPED, foreground="#9a6700")
        self.tree.tag_configure(processor.FAILED, foreground="#cf222e")
        ysb = ttk.Scrollbar(prev, orient="vertical", command=self.tree.yview)
        xsb = ttk.Scrollbar(prev, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        prev.rowconfigure(0, weight=1)
        prev.columnconfigure(0, weight=1)

        # Actions
        act = ttk.Frame(self)
        act.pack(fill="x", **PAD)
        # Secondary tools on the left, the one main action on the right (Windows convention).
        self.btn_preview = ttk.Button(act, text="Refresh preview", command=self.refresh_preview)
        self.btn_preview.pack(side="left", **PAD)
        ttk.Checkbutton(act, text="Hide file names in log", variable=self.hide_names,
                        command=lambda: logger.set_redact_names(self.hide_names.get())
                        ).pack(side="left", **PAD)
        ttk.Button(act, text="Open log", command=self._open_log).pack(side="left", **PAD)
        ttk.Button(act, text="About", command=self._about).pack(side="left", **PAD)
        # Main action: a plain tk.Button, because the native Windows ttk theme ignores colours.
        # It toggles Encrypt files -> Stop -> Stopping... (see BUTTON_LOOKS); fixed width so
        # it does not jump around when the text changes.
        bold = tkfont.nametofont("TkDefaultFont").copy()
        bold.configure(weight="bold")
        self.btn_start = tk.Button(
            act, command=self._on_main_button, font=bold, width=14,
            fg="white", activeforeground="white", disabledforeground="#eef1f5",
            relief="flat", bd=0, pady=int(4 * self.scale))
        self.btn_start.pack(side="right", **PAD)
        self._set_button("ready")

        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", **PAD)
        status_lbl = ttk.Label(self, textvariable=self.status, justify="left")
        status_lbl.pack(fill="x", **PAD)
        # Wrap at the label's real width (a fixed pixel width is far too narrow on high-DPI screens).
        status_lbl.bind("<Configure>", lambda e: status_lbl.configure(wraplength=max(200, e.width - 8)))

    # ---------------------------------------------------------------- handlers
    def _on_mode(self) -> None:
        self.chk_sub.configure(state="normal" if self.mode.get() == "folder" else "disabled")
        if self.mode.get() != "folder":
            self.subfolders.set(False)
        self.source.set("")
        self._clear_tree()

    def _toggle_pw(self) -> None:
        ch = "" if self.show_pw.get() else "•"
        self.pw1.configure(show=ch)
        self.pw2.configure(show=ch)

    def _browse_source(self) -> None:
        if self.mode.get() == "zip":
            path = filedialog.askopenfilename(
                title="Choose a zip file", filetypes=[("Zip file", "*.zip"), ("All files", "*.*")])
        elif self.mode.get() == "file":
            path = filedialog.askopenfilename(
                title="Choose a file",
                filetypes=[("Excel / Word / PDF", "*.xlsx *.docx *.pdf"), ("Excel workbook", "*.xlsx"),
                           ("Word document", "*.docx"),
                           ("PDF", "*.pdf"), ("All files", "*.*")])
        else:
            path = filedialog.askdirectory(title="Choose a folder")
        if path:
            self.source.set(os.path.normpath(path))
            self.refresh_preview()

    def _browse_output(self) -> None:
        path = filedialog.askdirectory(title="Choose an output folder")
        if path:
            self.output.set(os.path.normpath(path))

    def _on_overwrite(self) -> None:
        if self.overwrite.get():
            ok = messagebox.askyesno(
                "Overwrite original files?",
                "The original files will be REPLACED by their password-protected versions.\n\n"
                "If you forget the password, the content is lost for good - there is no recovery.\n\n"
                "Keep a backup elsewhere. Are you sure you want to overwrite the originals?",
                icon="warning", default="no", parent=self.master)
            if not ok:
                self.overwrite.set(False)
        state = "disabled" if self.overwrite.get() else "normal"
        for w in (self.ent_out, self.btn_out, self.btn_out_new):
            w.configure(state=state)
        self._update_planned()

    def _about(self) -> None:
        info = version.build_info()
        messagebox.showinfo(
            f"About {version.APP_NAME}",
            f"{version.version_string()}\n\n"
            f"Commit: {info['commit']}\n"
            f"Built: {info['build_date'] or '-'} ({info['builder']})\n\n"
            f"Log file: {logger.log_path()}\n\n"
            "Passwords are never stored or logged.\n"
            "Encryption: Office AES-256 (ECMA-376 Agile) for .xlsx/.docx, AES-256 for PDF.\n\n"
            "Self-test: FileLocker.exe --selftest report.txt\n"
            "License: MIT. Third-party licenses: THIRD_PARTY_LICENSES.txt",
            parent=self.master)

    def _open_log(self) -> None:
        path = logger.log_path()
        if path and path.exists():
            os.startfile(path)  # type: ignore[attr-defined]  # Windows only
        else:
            messagebox.showinfo("Log", f"No log file yet.\nIt will be created at:\n{path}", parent=self.master)

    # ----------------------------------------------------------------- preview
    def _clear_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.items = []
        self.zip_plans = []
        self.preview_error = ""
        self.row_ids = {}

    def _new_output_folder(self) -> None:
        """Point the output folder at a new "Protected" folder next to the chosen files:
        inside the chosen folder, or in the folder that holds the chosen file / zip.
        Nothing is created yet - the folder appears when the first file is saved."""
        root = self._source_root()
        if root is None:
            messagebox.showinfo("New folder", "Choose a file, folder or zip first (step 1).",
                                parent=self.master)
            return
        target = root / NEW_FOLDER_NAME
        n = 2
        while target.exists():
            target = root / f"{NEW_FOLDER_NAME} ({n})"
            n += 1
        self.output.set(str(target))

    def _output_dir(self) -> Path | None:
        out = self.output.get().strip()
        return None if (self.overwrite.get() or not out) else Path(out)

    def _source_root(self) -> Path | None:
        src = self.source.get().strip()
        if not src:
            return None
        p = Path(src)
        return p if p.is_dir() else p.parent

    def _planned_text(self, item: ScanItem) -> str:
        if not item.supported:
            return f"Skip: {item.reason}"
        if self.overwrite.get():
            return "Encrypt (replace original)"
        output_dir = self._output_dir()
        try:
            out = processor.planned_output(item.path, self._source_root(), output_dir)
        except OSError:
            return "Encrypt"
        if processor.same_folder(out.parent, item.path.parent):
            return f"Encrypt -> {out.name}"
        try:
            shown = out.relative_to(output_dir) if output_dir else out
        except ValueError:
            shown = out
        return f"Encrypt -> {shown} (output folder)"

    def _zip_output_text(self) -> str:
        src = Path(self.source.get().strip())
        if self.overwrite.get():
            return f"the original {src.name} will be replaced"
        output_dir = self._output_dir()
        try:
            out = processor.planned_output(src, src.parent, output_dir)
        except OSError:
            return "new zip"
        where = "next to the original" if processor.same_folder(out.parent, src.parent) else "in the output folder"
        return f"new zip: {out.name} ({where})"

    def _zip_status(self) -> str:
        n = len(self.zip_plans)
        enc = sum(p.will_encrypt for p in self.zip_plans)
        return (f"Zip contains {n} file(s): {enc} to encrypt, {n - enc} included unchanged "
                f"(NOT protected). Result -> {self._zip_output_text()}.")

    def _update_planned(self) -> None:
        # The plan is frozen while a run is in progress: recomputing it then would show
        # "(2)" names for files that this very run has just written.
        if self._btn_mode != "ready":
            return
        if self.mode.get() == "zip":
            if self.zip_plans:
                self.status.set(self._zip_status())
            return
        for item in self.items:
            rid = self.row_ids.get(item.path)
            if rid:
                self.tree.set(rid, "planned", self._planned_text(item))

    def _on_output_changed(self, *_args) -> None:
        # Debounce: typing a path fires on every keystroke.
        if self._planned_job is not None:
            self.after_cancel(self._planned_job)
        self._planned_job = self.after(300, self._run_planned_update)

    def _run_planned_update(self) -> None:
        self._planned_job = None
        self._update_planned()

    def refresh_preview(self) -> bool:
        self._clear_tree()
        src = self.source.get().strip()
        if not src:
            self.status.set("Choose a file or folder to begin.")
            return False
        if self.mode.get() == "zip":
            return self._refresh_zip_preview(src)
        try:
            self.master.config(cursor="watch")
            self.master.update_idletasks()
            items = scan(src, include_subfolders=self.subfolders.get())
        except FileNotFoundError:
            self.status.set(f"Source not found: {src}")
            return False
        except OSError as exc:
            self.status.set(f"Could not read source: {exc}")
            return False
        finally:
            self.master.config(cursor="")
        # Never list files that are inside the output folder (e.g. a "Protected" folder made
        # inside the source by the New folder button): they are earlier results, not inputs.
        out_dir = self._output_dir()
        if out_dir is not None:
            items = [i for i in items if not _is_inside(i.path, out_dir)]
        self.items = items
        base = Path(src) if Path(src).is_dir() else None
        for item in items:
            shown = str(item.path.relative_to(base)) if base else str(item.path)
            rid = self.tree.insert("", "end", values=(shown, self._planned_text(item), ""))
            self.row_ids[item.path] = rid
        n_ok = sum(i.supported for i in items)
        self.status.set(f"Found {len(items)} file(s): {n_ok} to encrypt, {len(items) - n_ok} will be skipped.")
        self.progress.configure(value=0, maximum=max(1, len(items)))
        return True

    def _refresh_zip_preview(self, src: str) -> bool:
        try:
            self.master.config(cursor="watch")
            self.master.update_idletasks()
            if not Path(src).is_file():
                raise zip_processor.ZipRejected(f"Zip file not found: {src}")
            plans = zip_processor.preview(src)
        except zip_processor.ZipRejected as exc:
            self.preview_error = str(exc)
            self.status.set(f"Can't use this zip: {exc}")
            return False
        except OSError as exc:
            self.preview_error = f"Could not read the zip: {exc}"
            self.status.set(self.preview_error)
            return False
        finally:
            self.master.config(cursor="")
        self.zip_plans = plans
        for plan in plans:
            planned = "Encrypt" if plan.will_encrypt else f"Keep as-is: {plan.note}"
            rid = self.tree.insert("", "end", values=(plan.name, planned, ""))
            self.row_ids[Path(plan.name)] = rid
        self.status.set(self._zip_status())
        self.progress.configure(value=0, maximum=max(1, len(plans)))
        return True

    # --------------------------------------------------------------------- run
    def _set_button(self, mode: str) -> None:
        """Switch the main button between its three looks: ready / running / stopping."""
        self._btn_mode = mode
        text, bg, active, state = BUTTON_LOOKS[mode]
        self.btn_start.configure(text=text, bg=bg, activebackground=active, state=state,
                                 cursor="hand2" if state == "normal" else "")

    def _set_running(self, running: bool) -> None:
        self.btn_preview.configure(state="disabled" if running else "normal")
        self._running_since = time.monotonic()
        self._set_button("running" if running else "ready")

    def _on_main_button(self) -> None:
        if self._btn_mode == "ready":
            self.start()
        elif self._btn_mode == "running":
            # Ignore the second half of a double-click on "Encrypt files".
            if time.monotonic() - self._running_since >= STOP_GUARD_SECONDS:
                self.cancel()

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        p1, p2 = self.pw1.get(), self.pw2.get()
        if not p1:
            messagebox.showerror("Password", "Please enter a password.", parent=self.master)
            return
        if p1 != p2:
            messagebox.showerror("Password", "The passwords do not match.", parent=self.master)
            return
        if len(p1) < MIN_RECOMMENDED_PASSWORD and not messagebox.askyesno(
                "Short password",
                f"This password has only {len(p1)} characters.\n\n"
                f"Short passwords can be guessed by password-cracking tools. At least "
                f"{MIN_RECOMMENDED_PASSWORD} characters (or a phrase of 3-4 words) is recommended.\n\n"
                "Use this password anyway?",
                icon="warning", default="no", parent=self.master):
            return
        logger.set_redact_names(self.hide_names.get())
        if not self.refresh_preview():
            messagebox.showerror("Source", self.preview_error or "Please choose a valid file, folder or zip.",
                                 parent=self.master)
            return
        if self.mode.get() == "zip":
            self._start_zip(p1)
            return
        if not any(i.supported for i in self.items):
            messagebox.showinfo("Nothing to do", "No .xlsx, .docx or .pdf files to encrypt were found.", parent=self.master)
            return

        out = self.output.get().strip()
        output_dir = None if (self.overwrite.get() or not out) else Path(out)
        if output_dir is not None and output_dir.exists() and not output_dir.is_dir():
            messagebox.showerror("Output", "The output path is not a folder.", parent=self.master)
            return

        overwrite = self.overwrite.get()
        if overwrite and not messagebox.askyesno(
                "Confirm overwrite",
                f"Replace {sum(i.supported for i in self.items)} original file(s) with encrypted versions?",
                icon="warning", default="no", parent=self.master):
            return

        src = Path(self.source.get().strip())
        source_root = src if src.is_dir() else src.parent
        self.cancel_event.clear()
        self._set_running(True)
        self.status.set("Working...")
        items = list(self.items)

        def work(password: str = p1) -> None:
            try:
                results = processor.run_batch(
                    items, password, output_dir=output_dir, source_root=source_root,
                    overwrite=overwrite, cancel=self.cancel_event,
                    on_progress=lambda i, n, r: self.queue.put(("progress", i, n, r)))
                self.queue.put(("done", results))
            except Exception as exc:  # pragma: no cover - safety net
                logger.error(f"Batch crashed: {type(exc).__name__}")
                self.queue.put(("crash", f"{type(exc).__name__}"))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.after(100, self._poll)

    def _start_zip(self, password: str) -> None:
        if not any(p.will_encrypt for p in self.zip_plans):
            messagebox.showinfo("Nothing to do", "The zip has no .xlsx, .docx or .pdf files to encrypt.",
                                parent=self.master)
            return
        output_dir = self._output_dir()
        if output_dir is not None and output_dir.exists() and not output_dir.is_dir():
            messagebox.showerror("Output", "The output path is not a folder.", parent=self.master)
            return
        overwrite = self.overwrite.get()
        src = Path(self.source.get().strip())
        if overwrite and not messagebox.askyesno(
                "Confirm overwrite", f"Replace the original zip ({src.name}) with the protected version?",
                icon="warning", default="no", parent=self.master):
            return
        self.cancel_event.clear()
        self._set_running(True)
        self.status.set("Extracting the zip...")

        def work(password: str = password) -> None:
            try:
                result = zip_processor.process_zip(
                    src, password, output_dir=output_dir, overwrite=overwrite, cancel=self.cancel_event,
                    on_progress=lambda i, n, r: self.queue.put(("progress", i, n, r)))
                self.queue.put(("zipdone", result))
            except Exception as exc:  # pragma: no cover - safety net
                logger.error(f"Zip run crashed: {type(exc).__name__}")
                self.queue.put(("crash", f"{type(exc).__name__}"))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.after(100, self._poll)

    def cancel(self) -> None:
        self.cancel_event.set()
        self._set_button("stopping")
        self.status.set("Stopping after the current file...")

    def _poll(self) -> None:
        try:
            while True:
                msg = self.queue.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, i, n, res = msg
                    self.progress.configure(maximum=n, value=i)
                    self.status.set(f"Processed {i} of {n}: {res.source.name}")
                    rid = self.row_ids.get(res.source)
                    if rid:
                        if self.mode.get() == "zip":
                            text = self._zip_result_text(res)
                        else:
                            text = res.status.capitalize()
                            if res.status == processor.SUCCEEDED and res.output:
                                text += f" -> {res.output.name}"
                            elif res.reason:
                                text += f": {res.reason}"
                        self.tree.set(rid, "result", text)
                        self.tree.item(rid, tags=(res.status,))
                        self.tree.see(rid)
                elif kind == "done":
                    self._finish(msg[1])
                    return
                elif kind == "zipdone":
                    self._finish_zip(msg[1])
                    return
                elif kind == "crash":
                    self._set_running(False)
                    messagebox.showerror("Error", f"Processing stopped unexpectedly ({msg[1]}).",
                                         parent=self.master)
                    return
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _finish(self, results: list[processor.Result]) -> None:
        self._set_running(False)
        # Don't leave the password sitting in the widgets after a run.
        self.pw1.delete(0, "end")
        self.pw2.delete(0, "end")

        groups = {s: [r for r in results if r.status == s]
                  for s in (processor.SUCCEEDED, processor.SKIPPED, processor.FAILED)}
        summary = (f"Done. Succeeded: {len(groups[processor.SUCCEEDED])}   "
                   f"Skipped: {len(groups[processor.SKIPPED])}   "
                   f"Failed: {len(groups[processor.FAILED])}")
        self.status.set(summary + f"   (log: {logger.log_path()})")

        lines = [summary, ""]
        for status, title in ((processor.FAILED, "Failed"), (processor.SKIPPED, "Skipped")):
            if groups[status]:
                lines.append(f"{title}:")
                for r in groups[status][:15]:
                    lines.append(f"  - {r.source.name}: {r.reason}")
                if len(groups[status]) > 15:
                    lines.append(f"  ... and {len(groups[status]) - 15} more (see list / log)")
                lines.append("")
        lines.append("The password has been cleared from the form.")
        icon = "error" if groups[processor.FAILED] else "info"
        messagebox.showinfo("FileLocker - summary", "\n".join(lines), icon=icon, parent=self.master)


    def _zip_result_text(self, res: processor.Result) -> str:
        if res.status == processor.SUCCEEDED:
            return "Protected"
        if res.status == processor.FAILED:
            return f"Failed: {res.reason}"
        planned_note = next((p.note for p in self.zip_plans if Path(p.name) == res.source), "")
        if res.reason and res.reason != planned_note:  # e.g. already encrypted, cancelled
            return f"NOT protected (kept as-is): {res.reason}"
        return "NOT protected (kept as-is)"

    def _finish_zip(self, result: zip_processor.ZipResult) -> None:
        self._set_running(False)
        self.pw1.delete(0, "end")
        self.pw2.delete(0, "end")
        self.progress.configure(value=self.progress.cget("maximum"))

        protected = [r for r in result.entries if r.status == processor.SUCCEEDED]
        unchanged = [r for r in result.entries if r.status == processor.SKIPPED]
        failed = [r for r in result.entries if r.status == processor.FAILED]

        if result.status == processor.SUCCEEDED:
            head = f"Created: {result.output}"
        else:
            head = f"No zip was created. {result.reason}"
        counts = (f"Protected: {len(protected)}   Included unchanged (NOT protected): {len(unchanged)}   "
                  f"Failed: {len(failed)}")
        self.status.set(f"{head}   |   {counts}")

        lines = [head, "", counts, ""]
        for title, group in (("Failed", failed), ("Included unchanged - NOT password-protected", unchanged)):
            if group:
                lines.append(f"{title}:")
                for r in group[:15]:
                    lines.append(f"  - {r.source.as_posix()}: {r.reason}")
                if len(group) > 15:
                    lines.append(f"  ... and {len(group) - 15} more (see list / log)")
                lines.append("")
        lines.append("The temporary extracted copies have been deleted.")
        lines.append("The password has been cleared from the form.")
        if result.status == processor.SUCCEEDED and not unchanged:
            icon = "info"
        elif result.status == processor.SUCCEEDED:
            icon = "warning"
        else:
            icon = "error"
        messagebox.showinfo("FileLocker - zip summary", "\n".join(lines), icon=icon, parent=self.master)


def dpi_scale(widget: tk.Misc) -> float:
    """1.0 at 100% Windows display scaling, 1.25 at 125%, 1.5 at 150%, ..."""
    try:
        return max(1.0, widget.winfo_fpixels("1i") / 96.0)
    except tk.TclError:
        return 1.0


def run() -> None:
    root = tk.Tk()
    root.title(f"{APP_TITLE}  -  v{version.__version__}")
    s = dpi_scale(root)
    # Fit the window to the screen even on small, high-DPI laptop displays.
    w = min(int(1000 * s), int(root.winfo_screenwidth() * 0.9))
    h = min(int(720 * s), int(root.winfo_screenheight() * 0.85))
    root.geometry(f"{w}x{h}")
    root.minsize(min(int(760 * s), w), min(int(560 * s), h))
    try:
        ttk.Style().theme_use("vista")
    except tk.TclError:
        pass
    app = FileLockerApp(root)

    def on_close() -> None:
        if app.worker and app.worker.is_alive():
            if not messagebox.askyesno("Quit", "Files are still being processed. Quit anyway?", parent=root):
                return
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    zip_processor.cleanup_stale_workdirs()
    logger.info(f"{version.version_string()} started (network guard active: {netguard.is_installed()})")
    root.mainloop()
