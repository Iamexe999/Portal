"""
Portablizer GUI — Tkinter-based drag-and-drop interface.

Run with: python gui.py
"""

import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path

# Patch sys.path so we can import from parent
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.pipeline import PortablizerPipeline


# ─── Theme ────────────────────────────────────────────────────────────────────
BG        = "#1a1a2e"
PANEL     = "#16213e"
ACCENT    = "#0f3460"
HIGHLIGHT = "#e94560"
TEXT      = "#eaeaea"
DIM_TEXT  = "#888899"
SUCCESS   = "#4caf50"
WARNING   = "#ff9800"
FONT_MAIN = ("Segoe UI", 10)
FONT_HEAD = ("Segoe UI", 13, "bold")
FONT_MONO = ("Consolas", 9)


class PortablizerGUI:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Portablizer — Make any .exe portable")
        self.root.geometry("780x640")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self.root.minsize(640, 500)

        self._input_var    = tk.StringVar()
        self._output_var   = tk.StringVar()
        self._method_var   = tk.StringVar(value="auto")
        self._silent_var   = tk.BooleanVar(value=True)
        self._patch_var    = tk.BooleanVar(value=True)
        self._report_var   = tk.BooleanVar(value=False)
        self._keep_var     = tk.BooleanVar(value=False)
        self._running      = False

        self._build_ui()
        self._setup_drop()

    # ── UI Construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        header = tk.Frame(self.root, bg=ACCENT, pady=12)
        header.pack(fill=tk.X)
        tk.Label(header, text="⚙  PORTABLIZER",
                 font=("Segoe UI", 16, "bold"),
                 bg=ACCENT, fg=TEXT).pack(side=tk.LEFT, padx=20)
        tk.Label(header, text="Convert any .exe to run without admin privileges",
                 font=FONT_MAIN, bg=ACCENT, fg=DIM_TEXT).pack(side=tk.LEFT, padx=4)

        # ── Drop zone ──
        drop_frame = tk.Frame(self.root, bg=BG, pady=8)
        drop_frame.pack(fill=tk.X, padx=20, pady=(12, 4))

        self._drop_label = tk.Label(
            drop_frame,
            text="📂  Drag & drop an .exe here  —  or click Browse",
            font=("Segoe UI", 11),
            bg=PANEL, fg=DIM_TEXT,
            relief=tk.FLAT, bd=0, pady=28,
            cursor="hand2",
        )
        self._drop_label.pack(fill=tk.X, ipadx=10)
        self._drop_label.bind("<Button-1>", lambda e: self._browse_input())
        self._drop_label.bind("<Enter>",
            lambda e: self._drop_label.config(fg=TEXT, bg=ACCENT))
        self._drop_label.bind("<Leave>",
            lambda e: self._drop_label.config(fg=DIM_TEXT, bg=PANEL))

        # ── Input path ──
        self._build_path_row("Input .exe:", self._input_var, self._browse_input,
                             row_pady=(0, 2))
        self._build_path_row("Output folder:", self._output_var, self._browse_output,
                             row_pady=(0, 8))

        # ── Options row ──
        opts_frame = tk.Frame(self.root, bg=BG)
        opts_frame.pack(fill=tk.X, padx=20)

        # Method
        tk.Label(opts_frame, text="Method:", bg=BG, fg=DIM_TEXT,
                 font=FONT_MAIN).grid(row=0, column=0, sticky=tk.W, padx=(0,6))
        method_combo = ttk.Combobox(
            opts_frame, textvariable=self._method_var,
            values=["auto", "extract", "sandbox"],
            state="readonly", width=10,
            font=FONT_MAIN,
        )
        method_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        method_combo.bind("<<ComboboxSelected>>", self._on_method_change)

        # Checkboxes
        check_cfg = [
            ("Silent install",    self._silent_var),
            ("Patch UAC manifest",self._patch_var),
            ("Generate report",   self._report_var),
            ("Keep temp files",   self._keep_var),
        ]
        for i, (label, var) in enumerate(check_cfg):
            cb = tk.Checkbutton(
                opts_frame, text=label, variable=var,
                bg=BG, fg=TEXT, activebackground=BG, activeforeground=TEXT,
                selectcolor=ACCENT, font=FONT_MAIN,
            )
            cb.grid(row=0, column=2 + i, padx=(0, 16), sticky=tk.W)

        # ── Method hint ──
        self._method_hint = tk.Label(
            self.root,
            text=self._get_method_hint("auto"),
            bg=BG, fg=DIM_TEXT, font=("Segoe UI", 9, "italic"),
            anchor=tk.W,
        )
        self._method_hint.pack(fill=tk.X, padx=20, pady=(4, 0))

        # ── Convert button ──
        btn_frame = tk.Frame(self.root, bg=BG, pady=10)
        btn_frame.pack(fill=tk.X, padx=20)
        self._convert_btn = tk.Button(
            btn_frame,
            text="▶  Convert to Portable",
            font=("Segoe UI", 11, "bold"),
            bg=HIGHLIGHT, fg="white",
            activebackground="#c73652", activeforeground="white",
            relief=tk.FLAT, padx=20, pady=8,
            cursor="hand2",
            command=self._on_convert,
        )
        self._convert_btn.pack(side=tk.LEFT)

        self._cancel_btn = tk.Button(
            btn_frame,
            text="✕  Cancel",
            font=FONT_MAIN,
            bg=ACCENT, fg=DIM_TEXT,
            activebackground=ACCENT, activeforeground=TEXT,
            relief=tk.FLAT, padx=14, pady=8,
            cursor="hand2",
            command=self._on_cancel,
            state=tk.DISABLED,
        )
        self._cancel_btn.pack(side=tk.LEFT, padx=(10, 0))

        # ── Progress bar ──
        self._progress = ttk.Progressbar(
            self.root, mode="indeterminate", length=400
        )
        self._progress.pack(fill=tk.X, padx=20, pady=(0, 6))

        # ── Status label ──
        self._status_var = tk.StringVar(value="Ready. Select an .exe file to begin.")
        self._status_label = tk.Label(
            self.root, textvariable=self._status_var,
            bg=BG, fg=DIM_TEXT, font=FONT_MAIN, anchor=tk.W,
        )
        self._status_label.pack(fill=tk.X, padx=22)

        # ── Log output ──
        log_frame = tk.Frame(self.root, bg=BG)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(8, 12))
        tk.Label(log_frame, text="Log", bg=BG, fg=DIM_TEXT,
                 font=("Segoe UI", 9)).pack(anchor=tk.W)
        self._log = scrolledtext.ScrolledText(
            log_frame,
            bg="#0d1117", fg=TEXT,
            font=FONT_MONO,
            relief=tk.FLAT, bd=0,
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self._log.pack(fill=tk.BOTH, expand=True)
        # Configure log tags
        self._log.tag_config("step",    foreground="#58a6ff", font=(FONT_MONO[0], FONT_MONO[1], "bold"))
        self._log.tag_config("success", foreground=SUCCESS)
        self._log.tag_config("warn",    foreground=WARNING)
        self._log.tag_config("error",   foreground=HIGHLIGHT)
        self._log.tag_config("dim",     foreground=DIM_TEXT)

    def _build_path_row(self, label: str, var: tk.StringVar, browse_cmd, row_pady=(0,0)):
        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill=tk.X, padx=20, pady=row_pady)
        tk.Label(frame, text=label, bg=BG, fg=DIM_TEXT,
                 font=FONT_MAIN, width=14, anchor=tk.W).pack(side=tk.LEFT)
        entry = tk.Entry(
            frame, textvariable=var,
            bg=PANEL, fg=TEXT, insertbackground=TEXT,
            relief=tk.FLAT, font=FONT_MONO, bd=4,
        )
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 6))
        tk.Button(
            frame, text="Browse…",
            bg=ACCENT, fg=TEXT,
            activebackground=HIGHLIGHT, activeforeground="white",
            relief=tk.FLAT, font=FONT_MAIN, padx=10,
            cursor="hand2", command=browse_cmd,
        ).pack(side=tk.LEFT)

    # ── Drag & Drop ────────────────────────────────────────────────────────────

    def _setup_drop(self):
        try:
            self.root.tk.call("package", "require", "tkdnd")
            self._drop_label.drop_target_register("DND_Files")
            self._drop_label.dnd_bind("<<Drop>>", self._on_drop)
        except Exception:
            pass  # tkdnd not available, that's fine

    def _on_drop(self, event):
        path = event.data.strip("{}")
        if path.lower().endswith(".exe"):
            self._set_input(path)

    # ── Event handlers ─────────────────────────────────────────────────────────

    def _browse_input(self):
        path = filedialog.askopenfilename(
            title="Select installer .exe",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
        )
        if path:
            self._set_input(path)

    def _browse_output(self):
        path = filedialog.askdirectory(title="Select output folder")
        if path:
            self._output_var.set(path)

    def _set_input(self, path: str):
        self._input_var.set(path)
        if not self._output_var.get():
            stem = Path(path).stem
            default_out = str(Path(path).parent / f"{stem}_portable")
            self._output_var.set(default_out)
        self._drop_label.config(
            text=f"✔  {Path(path).name}",
            fg=SUCCESS,
        )
        self._log_clear()
        self._status("Ready to convert. Click 'Convert to Portable'.")

    def _on_method_change(self, _event=None):
        self._method_hint.config(text=self._get_method_hint(self._method_var.get()))

    def _get_method_hint(self, method: str) -> str:
        hints = {
            "auto":    "auto: Detects the best method automatically (recommended)",
            "extract": "extract: Static extraction - fastest, works for Inno/NSIS/MSI/ZIP",
            "sandbox": "sandbox: Runtime capture - universal, requires running the installer",
        }
        return hints.get(method, "")

    def _on_convert(self):
        input_path = self._input_var.get().strip()
        if not input_path:
            messagebox.showwarning("No input", "Please select an .exe file first.")
            return
        if not Path(input_path).exists():
            messagebox.showerror("File not found", f"File not found:\n{input_path}")
            return

        output_path = self._output_var.get().strip()
        if not output_path:
            output_path = str(Path(input_path).parent / f"{Path(input_path).stem}_portable")
            self._output_var.set(output_path)

        self._log_clear()
        self._set_running(True)
        self._progress.start(10)
        self._status("Converting...")

        config = Config(
            input_path=Path(input_path),
            output_path=Path(output_path),
            method=self._method_var.get(),
            silent=self._silent_var.get(),
            patch_manifest=self._patch_var.get(),
            generate_report=self._report_var.get(),
            keep_temp=self._keep_var.get(),
            verbose=True,
        )

        self._thread = threading.Thread(
            target=self._run_pipeline, args=(config,), daemon=True
        )
        self._thread.start()

    def _on_cancel(self):
        self._status("Cancelling... (current step will finish)")
        self._set_running(False)

    def _run_pipeline(self, config: Config):
        ui_adapter = GUILogAdapter(self)
        pipeline = PortablizerPipeline(config, ui_adapter)
        result = pipeline.run()
        self.root.after(0, self._on_complete, result, config)

    def _on_complete(self, result, config: Config):
        self._progress.stop()
        self._set_running(False)

        if result.success:
            self._status(f"Done! Portable app at: {result.output_path}", "success")
            self._log_write(f"\n✔ Portable app created: {result.output_path}\n", "success")
            self._log_write(f"   Files: {result.file_count}\n", "dim")
            if result.warnings:
                self._log_write(f"\nWarnings:\n", "warn")
                for w in result.warnings:
                    self._log_write(f"  • {w}\n", "warn")
            if result.limitations:
                self._log_write(f"\nLimitations:\n", "warn")
                for lim in result.limitations:
                    self._log_write(f"  ⚠ {lim}\n", "warn")
            messagebox.showinfo(
                "Conversion Complete",
                f"Portable app created successfully!\n\n"
                f"Location: {result.output_path}\n"
                f"Files: {result.file_count}"
            )
        else:
            self._status(f"Failed: {result.error}", "error")
            self._log_write(f"\n✘ Conversion failed: {result.error}\n", "error")
            if result.traceback:
                self._log_write(result.traceback, "dim")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _set_running(self, running: bool):
        self._running = running
        state_convert = tk.DISABLED if running else tk.NORMAL
        state_cancel  = tk.NORMAL if running else tk.DISABLED
        self._convert_btn.config(state=state_convert)
        self._cancel_btn.config(state=state_cancel)

    def _status(self, msg: str, tag: str = ""):
        self._status_var.set(msg)
        colors = {"success": SUCCESS, "error": HIGHLIGHT, "warn": WARNING}
        self._status_label.config(fg=colors.get(tag, DIM_TEXT))

    def _log_write(self, text: str, tag: str = ""):
        self._log.config(state=tk.NORMAL)
        if tag:
            self._log.insert(tk.END, text, tag)
        else:
            self._log.insert(tk.END, text)
        self._log.see(tk.END)
        self._log.config(state=tk.DISABLED)

    def _log_clear(self):
        self._log.config(state=tk.NORMAL)
        self._log.delete("1.0", tk.END)
        self._log.config(state=tk.DISABLED)


# ─── GUI Log Adapter ──────────────────────────────────────────────────────────

class GUILogAdapter:
    """Adapts the GUI's log widget to the same interface as ConsoleUI."""

    def __init__(self, gui: PortablizerGUI):
        self._gui = gui

    def step(self, message: str):
        self._gui.root.after(0, self._gui._log_write, f"\n[>>] {message}...\n", "step")
        self._gui.root.after(0, self._gui._status, message)

    def info(self, message: str):
        self._gui.root.after(0, self._gui._log_write, f"     {message}\n")

    def success(self, message: str):
        self._gui.root.after(0, self._gui._log_write, f"{message}\n", "success")

    def warn(self, message: str):
        self._gui.root.after(0, self._gui._log_write, f"  {message}\n", "warn")

    def error(self, message: str):
        self._gui.root.after(0, self._gui._log_write, f"{message}\n", "error")

    def print_banner(self):
        pass  # No banner in GUI mode


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    # Try to set a modern theme
    style = ttk.Style(root)
    for theme in ("clam", "alt", "default"):
        if theme in style.theme_names():
            style.theme_use(theme)
            break
    style.configure("TCombobox", fieldbackground=PANEL, background=PANEL,
                    foreground=TEXT, selectbackground=ACCENT)
    style.configure("Horizontal.TProgressbar", troughcolor=PANEL,
                    background=HIGHLIGHT, thickness=4)

    app = PortablizerGUI(root)
    # Center window
    root.update_idletasks()
    x = (root.winfo_screenwidth()  - root.winfo_width())  // 2
    y = (root.winfo_screenheight() - root.winfo_height()) // 2
    root.geometry(f"+{x}+{y}")
    root.mainloop()


if __name__ == "__main__":
    main()
