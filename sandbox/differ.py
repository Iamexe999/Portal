"""
Snapshot Differ.

Takes a before/after snapshot of the filesystem and registry,
then computes the delta (new files, changed files, new registry keys).

Used in sandbox mode to capture everything the installer wrote.
"""

import os
import json
import time
import hashlib
import logging
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Set, List, Optional, Tuple

log = logging.getLogger(__name__)
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import winreg


# Directories to snapshot for file changes
WATCH_DIRS = [
    os.environ.get("ProgramFiles", r"C:\Program Files"),
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    os.environ.get("APPDATA", ""),
    os.environ.get("LOCALAPPDATA", ""),
    os.environ.get("CommonProgramFiles", r"C:\Program Files\Common Files"),
    os.environ.get("CommonProgramFiles(x86)", r"C:\Program Files (x86)\Common Files"),
    os.environ.get("SystemRoot", r"C:\Windows"),
]

# Registry hives to snapshot
WATCH_REGISTRY_HIVES = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE", "HKLM\\SOFTWARE") if IS_WINDOWS else None,
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE", "HKCU\\SOFTWARE") if IS_WINDOWS else None,
]
WATCH_REGISTRY_HIVES = [h for h in WATCH_REGISTRY_HIVES if h is not None]


@dataclass
class FileSnapshot:
    """Lightweight snapshot: path → (size, mtime) mapping."""
    entries: Dict[str, Tuple[int, float]] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class RegistrySnapshot:
    """Registry key → list of value names."""
    keys: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class SnapshotDiff:
    new_files: List[str] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)
    new_registry_keys: List[str] = field(default_factory=list)

    @property
    def file_count(self) -> int:
        return len(self.new_files) + len(self.changed_files)

    @property
    def registry_key_count(self) -> int:
        return len(self.new_registry_keys)


class SnapshotDiffer:

    def __init__(self, config):
        self.config = config

    def snapshot(self) -> Tuple[FileSnapshot, RegistrySnapshot]:
        fs_snap = self._snapshot_filesystem()
        reg_snap = self._snapshot_registry() if IS_WINDOWS else RegistrySnapshot()
        return fs_snap, reg_snap

    def diff(self,
             before: Tuple[FileSnapshot, RegistrySnapshot],
             after: Tuple[FileSnapshot, RegistrySnapshot]) -> SnapshotDiff:
        fs_before, reg_before = before
        fs_after, reg_after = after

        result = SnapshotDiff()

        # File diff
        for path, (size, mtime) in fs_after.entries.items():
            if path not in fs_before.entries:
                result.new_files.append(path)
            else:
                prev_size, prev_mtime = fs_before.entries[path]
                if size != prev_size or mtime > prev_mtime + 0.1:
                    result.changed_files.append(path)

        # Registry diff
        before_keys = set(reg_before.keys.keys())
        after_keys = set(reg_after.keys.keys())
        result.new_registry_keys = list(after_keys - before_keys)

        log.info(f"Snapshot diff: {len(result.new_files)} new files, "
                 f"{len(result.changed_files)} changed, "
                 f"{len(result.new_registry_keys)} new registry keys")
        return result

    def collect(self, diff: SnapshotDiff, output_dir: Path) -> Path:
        """
        Copy all new/changed files to output_dir, preserving their relative
        paths (stripped of the drive letter / ProgramFiles prefix).
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        programfiles = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        programfiles_x86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))

        # Find the install root (most files cluster under a single subdirectory)
        install_root = self._detect_install_root(diff.new_files, programfiles, programfiles_x86)
        log.info(f"Detected install root: {install_root}")

        copied = 0
        for src_str in diff.new_files + diff.changed_files:
            src = Path(src_str)
            if not src.exists():
                continue
            # Compute relative path
            try:
                if install_root and src.is_relative_to(install_root):
                    rel = src.relative_to(install_root)
                else:
                    # Fallback: strip drive letter
                    rel = Path(*src.parts[1:])
                dst = output_dir / rel
            except Exception:
                dst = output_dir / src.name

            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(src, dst)
                copied += 1
            except Exception as e:
                log.warning(f"Could not copy {src}: {e}")

        # Save registry diff for later processing
        if diff.new_registry_keys:
            reg_dump = output_dir.parent / "registry_diff.json"
            reg_dump.write_text(json.dumps({
                "new_keys": diff.new_registry_keys,
            }, indent=2))

        log.info(f"Collected {copied} files to {output_dir}")
        return output_dir

    # ──────────────────────────────────────────────────────────────────────────

    def _snapshot_filesystem(self) -> FileSnapshot:
        snap = FileSnapshot(timestamp=time.time())
        for d_str in WATCH_DIRS:
            if not d_str:
                continue
            d = Path(d_str)
            if not d.exists():
                continue
            try:
                for f in d.rglob("*"):
                    if f.is_file():
                        try:
                            stat = f.stat()
                            snap.entries[str(f)] = (stat.st_size, stat.st_mtime)
                        except (PermissionError, OSError):
                            pass
            except (PermissionError, OSError):
                pass
        log.debug(f"Filesystem snapshot: {len(snap.entries)} files")
        return snap

    def _snapshot_registry(self) -> RegistrySnapshot:
        snap = RegistrySnapshot()
        if not IS_WINDOWS:
            return snap
        for hive, subkey, prefix in WATCH_REGISTRY_HIVES:
            try:
                self._walk_registry(hive, subkey, prefix, snap)
            except Exception as e:
                log.debug(f"Registry snapshot error at {prefix}: {e}")
        log.debug(f"Registry snapshot: {len(snap.keys)} keys")
        return snap

    def _walk_registry(self, hive, subkey: str, prefix: str, snap: RegistrySnapshot):
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                # Enumerate values
                value_names = []
                i = 0
                while True:
                    try:
                        name, _, _ = winreg.EnumValue(k, i)
                        value_names.append(name)
                        i += 1
                    except OSError:
                        break
                snap.keys[prefix] = value_names

                # Recurse into subkeys
                i = 0
                while True:
                    try:
                        child_name = winreg.EnumKey(k, i)
                        child_subkey = f"{subkey}\\{child_name}"
                        child_prefix = f"{prefix}\\{child_name}"
                        self._walk_registry(hive, child_subkey, child_prefix, snap)
                        i += 1
                    except OSError:
                        break
        except PermissionError:
            pass

    def _detect_install_root(self,
                              new_files: List[str],
                              *program_dirs: Path) -> Optional[Path]:
        """
        Find the most common ancestor directory among new_files
        that falls under a Program Files directory.
        """
        counts: Dict[str, int] = {}
        for f in new_files:
            p = Path(f)
            for prog_dir in program_dirs:
                try:
                    if p.is_relative_to(prog_dir):
                        # Get the immediate child of ProgramFiles (the app folder)
                        parts = p.relative_to(prog_dir).parts
                        if parts:
                            app_root = prog_dir / parts[0]
                            counts[str(app_root)] = counts.get(str(app_root), 0) + 1
                        break
                except Exception:
                    pass

        if not counts:
            return None
        best = max(counts, key=lambda k: counts[k])
        return Path(best) if counts[best] > 2 else None
