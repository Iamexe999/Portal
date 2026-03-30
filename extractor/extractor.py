"""
Static installer extractor.

Supports:
  - Inno Setup    → innounp (bundled) or inoextract
  - NSIS          → 7-Zip or nsis7z
  - MSI           → msiexec /a (admin-less unpack) or lessmsi
  - 7-Zip SFX     → 7-Zip
  - WinRAR SFX    → 7-Zip (can read RAR)
  - ZIP SFX       → Python zipfile
  - Squirrel      → 7-Zip + NuGet repack
"""

import os
import sys
import shutil
import logging
import zipfile
import subprocess
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"


@dataclass
class ExtractResult:
    success: bool
    output_dir: Optional[Path] = None
    file_count: int = 0
    error: Optional[str] = None


class InstallerExtractor:

    def __init__(self, config, installer_info):
        self.config = config
        self.info = installer_info
        self.output_dir = config.extracted_dir

    def extract(self) -> ExtractResult:
        t = self.info.installer_type
        log.info(f"Extracting {t} installer: {self.config.input_path}")

        dispatchers = {
            "inno_setup":         self._extract_inno,
            "nsis":               self._extract_nsis,
            "msi":                self._extract_msi,
            "7zip_sfx":           self._extract_7zip,
            "winrar_sfx":         self._extract_7zip,   # 7-zip reads RAR too
            "zip_sfx":            self._extract_zip,
            "installshield":      self._extract_7zip,   # often works
            "squirrel":           self._extract_squirrel,
            "wise":               self._extract_7zip,
            "advanced_installer": self._extract_7zip,
        }

        fn = dispatchers.get(t, self._extract_7zip)
        try:
            result = fn()
            if result.success:
                result.file_count = self._count_files(self.output_dir)
                self._flatten_single_subdir()
            return result
        except Exception as e:
            log.error(f"Extraction exception: {e}")
            return ExtractResult(success=False, error=str(e))

    # ──────────────────────────────────────────────────────────────────────────
    # Per-format extractors
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_inno(self) -> ExtractResult:
        """
        Use innounp (preferred) or fallback to 7-Zip.
        innounp is a free Inno Setup unpacker:
            https://sourceforge.net/projects/innounp/
        """
        innounp = self._find_tool("innounp")
        if innounp:
            cmd = [innounp, "-x", "-d", str(self.output_dir),
                   str(self.config.input_path), "*"]
            return self._run_cmd(cmd, "innounp")

        # Fallback: innoextract (cross-platform, open source)
        innoextract = self._find_tool("innoextract")
        if innoextract:
            cmd = [innoextract, "--extract", "--output-dir",
                   str(self.output_dir), str(self.config.input_path)]
            return self._run_cmd(cmd, "innoextract")

        log.warning("innounp/innoextract not found — falling back to 7-Zip")
        return self._extract_7zip()

    def _extract_nsis(self) -> ExtractResult:
        """
        NSIS archives can be extracted with 7-Zip (with nsis7z plugin).
        7-Zip natively supports NSIS since version 9.x.
        """
        return self._extract_7zip()

    def _extract_msi(self) -> ExtractResult:
        """
        MSI extraction options:
          1. lessmsi  - best results, preserves directory structure
          2. msiexec /a - admin-free 'advertised install' (creates .msi copy in output)
          3. 7-Zip    - works but loses MSI-specific metadata
        """
        lessmsi = self._find_tool("lessmsi")
        if lessmsi:
            cmd = [lessmsi, "x", str(self.config.input_path),
                   str(self.output_dir) + "\\"]
            return self._run_cmd(cmd, "lessmsi")

        if IS_WINDOWS:
            # msiexec /a does an 'administrative install' — no admin needed
            msi_out = self.output_dir / "msi_admin_install"
            msi_out.mkdir(parents=True, exist_ok=True)
            cmd = [
                "msiexec", "/a", str(self.config.input_path),
                "/qn",
                f"TARGETDIR={msi_out}"
            ]
            result = self._run_cmd(cmd, "msiexec /a")
            if result.success:
                return result

        log.warning("lessmsi not found — falling back to 7-Zip (limited MSI support)")
        return self._extract_7zip()

    def _extract_7zip(self) -> ExtractResult:
        """Generic 7-Zip extraction. Works for most SFX, NSIS, ZIP, RAR."""
        sevenzip = self._find_7zip()
        if not sevenzip:
            return ExtractResult(
                success=False,
                error="7-Zip not found. Install 7-Zip or add 7z.exe to PATH."
            )
        cmd = [sevenzip, "x", str(self.config.input_path),
               f"-o{self.output_dir}", "-y", "-bb0"]
        return self._run_cmd(cmd, "7-Zip")

    def _extract_zip(self) -> ExtractResult:
        """Use Python's built-in zipfile for ZIP SFX archives."""
        try:
            # ZIP SFX: find the PK header offset
            with open(self.config.input_path, "rb") as f:
                data = f.read()

            zip_offset = data.find(b"PK\x03\x04")
            if zip_offset == -1:
                return ExtractResult(success=False, error="No ZIP signature found in SFX")

            import io
            zip_data = data[zip_offset:]
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                zf.extractall(self.output_dir)
            return ExtractResult(success=True, output_dir=self.output_dir)

        except Exception as e:
            return ExtractResult(success=False, error=str(e))

    def _extract_squirrel(self) -> ExtractResult:
        """
        Squirrel installers (Electron apps) contain a NuGet package.
        Extract with 7-Zip, then unpack the .nupkg (which is a ZIP).
        """
        result = self._extract_7zip()
        if not result.success:
            return result

        # Find and unpack any .nupkg files
        for nupkg in self.output_dir.rglob("*.nupkg"):
            nupkg_out = nupkg.parent / nupkg.stem
            nupkg_out.mkdir(exist_ok=True)
            try:
                with zipfile.ZipFile(nupkg) as zf:
                    zf.extractall(nupkg_out)
                log.debug(f"Unpacked NuGet package: {nupkg.name}")
            except Exception as e:
                log.warning(f"Failed to unpack {nupkg.name}: {e}")

        return ExtractResult(success=True, output_dir=self.output_dir)

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _run_cmd(self, cmd, tool_name: str) -> ExtractResult:
        log.debug(f"Running: {' '.join(str(c) for c in cmd)}")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if proc.returncode not in (0, 1):   # some tools return 1 on warnings
                log.warning(f"{tool_name} exited {proc.returncode}: {proc.stderr[:500]}")
                return ExtractResult(
                    success=False,
                    error=f"{tool_name} failed (exit {proc.returncode}): {proc.stderr[:300]}"
                )
            return ExtractResult(success=True, output_dir=self.output_dir)
        except FileNotFoundError:
            return ExtractResult(success=False, error=f"{tool_name} not found in PATH")
        except subprocess.TimeoutExpired:
            return ExtractResult(success=False, error=f"{tool_name} timed out after 5 min")

    def _find_tool(self, name: str) -> Optional[str]:
        # Check bundled tools first
        bundled = Path(__file__).parent.parent / "tools" / "bin" / name
        if IS_WINDOWS:
            bundled = bundled.with_suffix(".exe")
        if bundled.exists():
            return str(bundled)
        return shutil.which(name)

    def _find_7zip(self) -> Optional[str]:
        # Check bundled
        for name in ["7z", "7za", "7zip"]:
            path = self._find_tool(name)
            if path:
                return path
        # Windows default install location
        if IS_WINDOWS:
            candidates = [
                r"C:\Program Files\7-Zip\7z.exe",
                r"C:\Program Files (x86)\7-Zip\7z.exe",
            ]
            for c in candidates:
                if Path(c).exists():
                    return c
        return None

    def _count_files(self, directory: Path) -> int:
        return sum(1 for _ in directory.rglob("*") if _.is_file())

    def _flatten_single_subdir(self):
        """
        If extraction produced a single subdirectory, move contents up one level.
        e.g., extracted/ → extracted/AppName/ → move AppName/* to extracted/
        """
        children = list(self.output_dir.iterdir())
        if len(children) == 1 and children[0].is_dir():
            single = children[0]
            tmp = self.output_dir.parent / "_flatten_tmp"
            single.rename(tmp)
            self.output_dir.rmdir()
            tmp.rename(self.output_dir)
            log.debug(f"Flattened single subdirectory: {single.name}")
