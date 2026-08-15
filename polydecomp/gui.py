from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from threading import Thread
from tkinter import filedialog, messagebox, ttk

from .engine import AnalysisError, analyze_file
from .i18n import tr
from .model import AnalysisReport


class PolyDecompApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.language = tk.StringVar(value="en")
        self.status = tk.StringVar()
        self.report: AnalysisReport | None = None

        self.root.geometry("980x680")
        self.root.minsize(760, 520)

        toolbar = ttk.Frame(root, padding=10)
        toolbar.pack(fill="x")
        self.open_button = ttk.Button(toolbar, command=self.open_file)
        self.open_button.pack(side="left")
        self.export_button = ttk.Button(toolbar, command=self.export_json)
        self.export_button.pack(side="left", padx=(8, 0))
        ttk.Label(toolbar, text="EN / 日本語").pack(side="right", padx=(8, 0))
        language_box = ttk.Combobox(toolbar, textvariable=self.language, values=("en", "ja"), width=5, state="readonly")
        language_box.pack(side="right")
        language_box.bind("<<ComboboxSelected>>", lambda _event: self.refresh_labels())

        self.summary = ttk.Treeview(root, columns=("value",), show="tree headings", height=7)
        self.summary.heading("#0", text="Field")
        self.summary.heading("value", text="Value")
        self.summary.column("#0", width=160, stretch=False)
        self.summary.pack(fill="x", padx=10)

        body = ttk.Panedwindow(root, orient="vertical")
        body.pack(fill="both", expand=True, padx=10, pady=10)
        findings_frame = ttk.Labelframe(body, text="Findings", padding=6)
        warnings_frame = ttk.Labelframe(body, text="Warnings", padding=6)
        body.add(findings_frame, weight=4)
        body.add(warnings_frame, weight=1)

        self.findings_frame = findings_frame
        self.warnings_frame = warnings_frame
        self.findings = ttk.Treeview(findings_frame, columns=("kind", "offset", "value"), show="headings")
        self.findings.heading("kind", text="Kind")
        self.findings.heading("offset", text="Offset")
        self.findings.heading("value", text="Value")
        self.findings.column("kind", width=120, stretch=False)
        self.findings.column("offset", width=100, stretch=False)
        self.findings.column("value", width=650)
        self.findings.pack(fill="both", expand=True)

        self.warning_text = tk.Text(warnings_frame, height=5, wrap="word", state="disabled")
        self.warning_text.pack(fill="both", expand=True)
        ttk.Label(root, textvariable=self.status, anchor="w", padding=(10, 0, 10, 10)).pack(fill="x")
        self.refresh_labels()

    def refresh_labels(self) -> None:
        lang = self.language.get()
        self.root.title(tr(lang, "title"))
        self.open_button.configure(text=tr(lang, "open"))
        self.export_button.configure(text=tr(lang, "export"))
        self.findings_frame.configure(text=tr(lang, "findings"))
        self.warnings_frame.configure(text=tr(lang, "warnings"))
        if self.report is None:
            self.status.set(tr(lang, "ready"))
        else:
            self.status.set(tr(lang, "done"))
            self._render_summary()

    def open_file(self) -> None:
        selected = filedialog.askopenfilename()
        if not selected:
            return
        self.open_button.configure(state="disabled")
        self.status.set(str(selected))
        Thread(target=self._analyze_worker, args=(Path(selected),), daemon=True).start()

    def _analyze_worker(self, path: Path) -> None:
        try:
            report = analyze_file(path)
        except (AnalysisError, OSError, ValueError) as exc:
            self.root.after(0, self._analysis_failed, str(exc))
            return
        self.root.after(0, self._analysis_done, report)

    def _analysis_failed(self, message: str) -> None:
        self.open_button.configure(state="normal")
        messagebox.showerror(tr(self.language.get(), "error"), message)
        self.status.set(message)

    def _analysis_done(self, report: AnalysisReport) -> None:
        self.report = report
        self.open_button.configure(state="normal")
        self.status.set(tr(self.language.get(), "done"))
        self._render_summary()
        for item in self.findings.get_children():
            self.findings.delete(item)
        for finding in report.findings:
            offset = "" if finding.offset is None else hex(finding.offset)
            self.findings.insert("", "end", values=(finding.kind, offset, finding.value))
        self.warning_text.configure(state="normal")
        self.warning_text.delete("1.0", "end")
        self.warning_text.insert("1.0", "\n".join(report.warnings) if report.warnings else "-")
        self.warning_text.configure(state="disabled")

    def _render_summary(self) -> None:
        if self.report is None:
            return
        for item in self.summary.get_children():
            self.summary.delete(item)
        lang = self.language.get()
        rows = (
            (tr(lang, "path"), self.report.path),
            (tr(lang, "format"), self.report.format),
            (tr(lang, "size"), f"{self.report.size:,} bytes"),
            (tr(lang, "sha256"), self.report.sha256),
            (tr(lang, "architecture"), self.report.architecture or "-"),
            ("Metadata", json.dumps(self.report.metadata, ensure_ascii=False, sort_keys=True)),
        )
        for name, value in rows:
            self.summary.insert("", "end", text=name, values=(value,))

    def export_json(self) -> None:
        if self.report is None:
            messagebox.showinfo(tr(self.language.get(), "title"), tr(self.language.get(), "no_report"))
            return
        selected = filedialog.asksaveasfilename(defaultextension=".json", filetypes=(("JSON", "*.json"), ("All files", "*.*")))
        if not selected:
            return
        Path(selected).write_text(json.dumps(self.report.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    root = tk.Tk()
    PolyDecompApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
