"""
UAC Manifest Patcher.

Scans all .exe and .dll files in the output directory and patches
their embedded XML manifest to change:
  - requestedExecutionLevel level="requireAdministrator"  →  level="asInvoker"
  - requestedExecutionLevel level="highestAvailable"      →  level="asInvoker"

Patching methods (in order of preference):
  1. mt.exe (Windows SDK Manifest Tool) — cleanest, official
  2. Resource Hacker CLI — powerful, widely used
  3. Direct binary patching — no external tools required
     (replaces the manifest XML bytes in-place; works because
      "asInvoker       " is same length as "requireAdministrator")
"""

import re
import os
import shutil
import struct
import logging
import platform
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

log = logging.getLogger(__name__)
IS_WINDOWS = platform.system() == "Windows"

# The XML snippet we want to replace
ADMIN_PATTERNS = [
    b'level="requireAdministrator"',
    b"level='requireAdministrator'",
    b'level="highestAvailable"',
    b"level='highestAvailable'",
]

# Replacement — must be EXACTLY the same byte length for in-place binary patching.
# We pad with trailing spaces inside the XML attribute value — XML parsers ignore them.
#
# Length check (must all be equal within each pair):
#   b'level="requireAdministrator"'  → 28 bytes
#   b'level="asInvoker"           '  → 17 + 11 spaces = 28 bytes  ✓
#
#   b'level="highestAvailable"'      → 24 bytes
#   b'level="asInvoker"       '      → 17 + 7 spaces  = 24 bytes  ✓
REPLACEMENTS = {
    b'level="requireAdministrator"': b'level="asInvoker"           ',  # 11 spaces → 28 bytes
    b"level='requireAdministrator'": b"level='asInvoker'           ",  # 11 spaces → 28 bytes
    b'level="highestAvailable"':     b'level="asInvoker"       ',      #  7 spaces → 24 bytes
    b"level='highestAvailable'":     b"level='asInvoker'       ",      #  7 spaces → 24 bytes
}

PORTABLE_MANIFEST = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{35138b9a-5d96-4fbe-8e08-38612f45d1d3}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"""


@dataclass
class PatchResult:
    patched_count: int = 0
    skipped_count: int = 0
    warnings: List[str] = field(default_factory=list)


class ManifestPatcher:

    def __init__(self, config):
        self.config = config
        self._mt_path = self._find_tool("mt")
        self._reshacker_path = self._find_tool("ResourceHacker")

    def patch_directory(self, directory: Path) -> PatchResult:
        result = PatchResult()
        targets = list(directory.rglob("*.exe")) + list(directory.rglob("*.dll"))
        log.info(f"Scanning {len(targets)} PE files for UAC manifest...")

        for pe_path in targets:
            try:
                patched = self._patch_file(pe_path)
                if patched:
                    result.patched_count += 1
                    log.debug(f"Patched manifest: {pe_path.name}")
                else:
                    result.skipped_count += 1
            except Exception as e:
                result.warnings.append(f"Could not patch {pe_path.name}: {e}")
                log.warning(f"Manifest patch failed for {pe_path.name}: {e}")

        return result

    def _patch_file(self, path: Path) -> bool:
        """
        Returns True if file was patched, False if no patching needed.
        """
        # Quick check: does this file even have a manifest?
        with open(path, "rb") as f:
            data = f.read()

        needs_patch = any(pat in data for pat in ADMIN_PATTERNS)
        if not needs_patch:
            return False

        log.debug(f"Found admin manifest in: {path.name}")

        # Method 1: mt.exe (Windows SDK manifest tool)
        if IS_WINDOWS and self._mt_path:
            if self._patch_with_mt(path):
                return True

        # Method 2: Resource Hacker
        if IS_WINDOWS and self._reshacker_path:
            if self._patch_with_reshacker(path):
                return True

        # Method 3: Direct binary patch (no external tools)
        return self._patch_binary_direct(path, data)

    def _patch_with_mt(self, path: Path) -> bool:
        """Patch using mt.exe from the Windows SDK."""
        with tempfile.NamedTemporaryFile(suffix=".manifest", delete=False, mode='w') as mf:
            mf.write(PORTABLE_MANIFEST)
            manifest_path = mf.name

        try:
            backup = path.with_suffix(path.suffix + ".bak")
            shutil.copy2(path, backup)

            cmd = [
                self._mt_path,
                f"-manifest", manifest_path,
                f"-outputresource:{path};1",
                "-nologo"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                backup.unlink(missing_ok=True)
                return True
            else:
                shutil.copy2(backup, path)
                backup.unlink(missing_ok=True)
                log.debug(f"mt.exe failed: {proc.stderr}")
                return False
        finally:
            try:
                os.unlink(manifest_path)
            except Exception:
                pass

    def _patch_with_reshacker(self, path: Path) -> bool:
        """Patch using Resource Hacker CLI."""
        with tempfile.NamedTemporaryFile(suffix=".manifest", delete=False, mode='w') as mf:
            mf.write(PORTABLE_MANIFEST)
            manifest_path = mf.name

        try:
            cmd = [
                self._reshacker_path,
                "-open", str(path),
                "-save", str(path),
                "-action", "addoverwrite",
                "-res", manifest_path,
                "-mask", "MANIFEST,1,",
                "-log", "CONSOLE"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return proc.returncode == 0
        finally:
            try:
                os.unlink(manifest_path)
            except Exception:
                pass

    def _patch_binary_direct(self, path: Path, data: bytes) -> bool:
        """
        Direct binary replacement of the UAC level string.

        This works because XML attribute values can have trailing whitespace
        inside the quotes — browsers/parsers ignore it.
        We replace 'requireAdministrator' with 'asInvoker             '
        (padded to same length so no offsets shift).
        """
        patched = data
        changed = False

        for pattern, replacement in REPLACEMENTS.items():
            if pattern in patched:
                # Ensure same length
                assert len(pattern) == len(replacement), (
                    f"Length mismatch: {len(pattern)} vs {len(replacement)}"
                )
                patched = patched.replace(pattern, replacement)
                changed = True

        if not changed:
            return False

        # Write atomically
        tmp = path.with_suffix(".tmp_patch")
        try:
            tmp.write_bytes(patched)
            if IS_WINDOWS:
                path.unlink()
            tmp.rename(path)
            return True
        except Exception as e:
            tmp.unlink(missing_ok=True)
            raise e

    def _find_tool(self, name: str) -> Optional[str]:
        bundled = Path(__file__).parent.parent / "tools" / "bin" / name
        if IS_WINDOWS:
            bundled = bundled.with_suffix(".exe")
        if bundled.exists():
            return str(bundled)
        path = shutil.which(name)
        if path:
            return path
        # Windows SDK locations for mt.exe
        if IS_WINDOWS and name == "mt":
            for version in ["10.0", "8.1", "8.0"]:
                for arch in ["x64", "x86"]:
                    candidate = Path(
                        f"C:/Program Files (x86)/Windows Kits/{version}/bin/{arch}/mt.exe"
                    )
                    if candidate.exists():
                        return str(candidate)
        return None
