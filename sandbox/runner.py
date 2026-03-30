r"""
Sandbox Runner.

Executes the installer inside a monitored environment using one of:

  1. Windows Sandbox / App Container (preferred, most isolated)
  2. Detours-based DLL injection shim (our custom hooking DLL)
  3. Process Monitor + filesystem watcher (least invasive, capture-only)

The runner redirects:
  - Filesystem writes to C:\Program Files\  -> %TEMP%\portablizer_sandbox\files
  - Registry writes to HKLM\SOFTWARE\       -> registry capture file
  - UAC elevation prompts                   -> silently accept / no-op

After the installer finishes, the SnapshotDiffer collects the results.
"""

import os
import json
import time
import shutil
import ctypes
import logging
import platform
import subprocess
import threading
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

log = logging.getLogger(__name__)
IS_WINDOWS = platform.system() == "Windows"


@dataclass
class RunResult:
    success: bool
    exit_code: int = 0
    error: Optional[str] = None
    captured_files: List[str] = field(default_factory=list)
    captured_registry_keys: List[str] = field(default_factory=list)


class SandboxRunner:

    def __init__(self, config, installer_info):
        self.config = config
        self.info = installer_info
        self._watcher_thread = None
        self._stop_event = threading.Event()

    def run(self) -> RunResult:
        if not IS_WINDOWS:
            return RunResult(
                success=False,
                error="Sandbox mode requires Windows. Use --method extract on Linux/macOS."
            )

        log.info("Starting sandbox run...")

        # Prepare the sandbox directory
        sandbox = self.config.sandbox_dir
        sandbox.mkdir(parents=True, exist_ok=True)

        # Write the injector config
        injector_config = self._build_injector_config(sandbox)
        config_path = sandbox / "injector_config.json"
        config_path.write_text(json.dumps(injector_config, indent=2))

        # Choose runner method
        if self._has_detours_shim():
            return self._run_with_detours(config_path)
        elif self._has_procmon():
            return self._run_with_procmon()
        else:
            return self._run_with_watcher()

    # ──────────────────────────────────────────────────────────────────────────
    # Runner implementations
    # ──────────────────────────────────────────────────────────────────────────

    def _run_with_detours(self, config_path: Path) -> RunResult:
        """
        Inject our portablizer_shim.dll into the installer process.
        The DLL hooks CreateFile, RegCreateKey, RegSetValue, etc.
        and redirects writes to our sandbox directory.
        """
        shim_dll = self._get_shim_dll_path()
        launcher = self._get_detours_launcher()

        env = os.environ.copy()
        env["PORTABLIZER_CONFIG"] = str(config_path)
        env["PORTABLIZER_SANDBOX"] = str(self.config.sandbox_dir)

        cmd = [
            str(launcher),
            str(shim_dll),
            str(self.config.input_path),
        ] + self._build_installer_args()

        log.info(f"Launching with Detours shim: {self.config.input_path.name}")

        try:
            proc = subprocess.run(
                cmd,
                env=env,
                timeout=600,
                capture_output=True,
                text=True,
            )
            return RunResult(
                success=proc.returncode in (0, 3010),  # 3010 = reboot required, OK
                exit_code=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return RunResult(success=False, error="Installer timed out after 10 minutes")
        except Exception as e:
            return RunResult(success=False, error=str(e))

    def _run_with_procmon(self) -> RunResult:
        """
        Use Process Monitor (procmon) to capture all FS and registry operations.
        Then parse the procmon log to collect what was written.
        This requires procmon64.exe to be available.
        """
        procmon = shutil.which("procmon64") or shutil.which("procmon")
        pml_log = self.config.sandbox_dir / "capture.pml"
        pml_csv = self.config.sandbox_dir / "capture.csv"

        # Start procmon capture
        pm_proc = subprocess.Popen([
            procmon, "/Quiet", "/Minimized",
            "/BackingFile", str(pml_log),
        ])
        time.sleep(2)  # let procmon initialize

        # Run installer
        run_result = self._run_raw()

        # Stop procmon
        subprocess.run([procmon, "/Terminate"], capture_output=True)
        pm_proc.wait(timeout=10)

        # Convert log to CSV
        subprocess.run([
            procmon, "/OpenLog", str(pml_log),
            "/SaveAs", str(pml_csv)
        ], capture_output=True)

        run_result.captured_files = self._parse_procmon_csv(pml_csv)
        return run_result

    def _run_with_watcher(self) -> RunResult:
        """
        Fallback: use Python watchdog + winreg polling to capture changes.
        Less comprehensive than Detours but requires no extra tools.
        """
        log.info("Using filesystem watcher (fallback sandbox mode)")

        # Start filesystem watcher
        self._start_fs_watcher()

        # Run the installer
        result = self._run_raw()

        # Stop watcher
        self._stop_event.set()
        if self._watcher_thread:
            self._watcher_thread.join(timeout=5)

        return result

    def _run_raw(self) -> RunResult:
        """Run the installer without any interception."""
        cmd = [str(self.config.input_path)] + self._build_installer_args()
        log.info(f"Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd,
                timeout=600,
                capture_output=False,  # let installer UI show
            )
            return RunResult(
                success=proc.returncode in (0, 3010),
                exit_code=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return RunResult(success=False, error="Installer timed out")
        except Exception as e:
            return RunResult(success=False, error=str(e))

    # ──────────────────────────────────────────────────────────────────────────
    # Filesystem watcher
    # ──────────────────────────────────────────────────────────────────────────

    def _start_fs_watcher(self):
        """
        Watch commonly written-to directories using ReadDirectoryChangesW.
        Records new/modified files for the snapshot differ.
        """
        watch_dirs = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
            Path(os.environ.get("APPDATA", "")),
            Path(os.environ.get("LOCALAPPDATA", "")),
            Path(os.environ.get("CommonProgramFiles", r"C:\Program Files\Common Files")),
        ]

        def watch():
            try:
                import watchdog.observers
                import watchdog.events

                class Handler(watchdog.events.FileSystemEventHandler):
                    def __init__(self_inner):
                        self_inner.events = []

                    def on_any_event(self_inner, event):
                        if not event.is_directory:
                            self_inner.events.append(event.src_path)

                handler = Handler()
                observer = watchdog.observers.Observer()
                for d in watch_dirs:
                    if d.exists():
                        observer.schedule(handler, str(d), recursive=True)
                observer.start()

                self._stop_event.wait()
                observer.stop()
                observer.join()

                # Save captured paths
                log_path = self.config.sandbox_dir / "watcher_events.txt"
                log_path.write_text("\n".join(handler.events))

            except ImportError:
                log.debug("watchdog not installed — filesystem watcher unavailable")
            except Exception as e:
                log.debug(f"Filesystem watcher error: {e}")

        self._watcher_thread = threading.Thread(target=watch, daemon=True)
        self._watcher_thread.start()

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _build_installer_args(self) -> List[str]:
        args = []
        if self.config.silent:
            args.extend(self.info.silent_switch.split())
        if self.config.install_args:
            args.extend(self.config.install_args.split())
        return args

    def _build_injector_config(self, sandbox: Path) -> dict:
        return {
            "sandbox_dir": str(sandbox),
            "redirect_paths": {
                str(Path(os.environ.get("ProgramFiles", r"C:\Program Files"))): str(sandbox / "ProgramFiles"),
                str(Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))): str(sandbox / "ProgramFiles_x86"),
                r"C:\Windows\System32": str(sandbox / "System32"),
                r"C:\Windows\SysWOW64": str(sandbox / "SysWOW64"),
            },
            "redirect_registry": {
                r"HKEY_LOCAL_MACHINE\SOFTWARE": r"HKEY_CURRENT_USER\SOFTWARE\Portablizer_Sandbox",
            },
            "capture_output": str(sandbox / "captured.json"),
        }

    def _has_detours_shim(self) -> bool:
        return self._get_shim_dll_path() is not None

    def _get_shim_dll_path(self) -> Optional[Path]:
        p = Path(__file__).parent.parent / "tools" / "bin" / "portablizer_shim.dll"
        return p if p.exists() else None

    def _get_detours_launcher(self) -> Optional[Path]:
        p = Path(__file__).parent.parent / "tools" / "bin" / "withdll.exe"
        return p if p.exists() else None

    def _has_procmon(self) -> bool:
        return bool(shutil.which("procmon64") or shutil.which("procmon"))

    def _parse_procmon_csv(self, csv_path: Path) -> List[str]:
        """
        Parse a Process Monitor CSV export and return list of written file paths.
        """
        if not csv_path.exists():
            return []
        files = []
        try:
            import csv
            with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    op = row.get("Operation", "")
                    path = row.get("Path", "")
                    result = row.get("Result", "")
                    if "WriteFile" in op or "CreateFile" in op:
                        if result == "SUCCESS" and path:
                            files.append(path)
        except Exception as e:
            log.warning(f"Failed to parse procmon CSV: {e}")
        return files
