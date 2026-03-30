"""
Registry Redirect Builder.

Many apps write to HKEY_LOCAL_MACHINE (HKLM) during install.
For portability, we need these reads/writes to go to HKEY_CURRENT_USER (HKCU).

This module:
  1. Scans extracted files for .reg files and embedded registry data
  2. Rewrites HKLM paths to HKCU equivalents
  3. Generates a registry redirect configuration used by the launcher
  4. Generates a .reg file to pre-populate HKCU on first run
"""

import re
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Tuple, Optional

log = logging.getLogger(__name__)

# HKLM → HKCU path mappings
HKLM_TO_HKCU_MAP = {
    r"HKEY_LOCAL_MACHINE\SOFTWARE":             r"HKEY_CURRENT_USER\SOFTWARE",
    r"HKLM\SOFTWARE":                           r"HKCU\SOFTWARE",
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services": None,  # services — skip
    r"HKEY_LOCAL_MACHINE\SYSTEM":               None,               # system — skip (requires admin)
    r"HKEY_LOCAL_MACHINE\HARDWARE":             None,               # hardware — skip
}

# COM registration redirects
COM_HKLM_CLSID = r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID"
COM_HKCU_CLSID = r"HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID"


@dataclass
class RegistryRedirectResult:
    has_redirects: bool = False
    key_count: int = 0
    skipped_count: int = 0
    reg_file_path: Optional[Path] = None
    redirect_map: Dict[str, str] = field(default_factory=dict)


class RegistryRedirectBuilder:

    def __init__(self, config):
        self.config = config

    def build(self, app_root: Path) -> RegistryRedirectResult:
        result = RegistryRedirectResult()
        all_entries = []

        # 1. Parse any .reg files in the extracted directory
        reg_files = list(app_root.rglob("*.reg"))
        for reg_file in reg_files:
            entries = self._parse_reg_file(reg_file)
            all_entries.extend(entries)
            log.debug(f"Parsed {len(entries)} entries from {reg_file.name}")

        # 2. Scan for registry hints in text-based scripts (.bat, .cmd, .ini, .cfg, .xml)
        script_entries = self._scan_scripts_for_registry(app_root)
        all_entries.extend(script_entries)

        if not all_entries:
            return result

        # 3. Redirect HKLM → HKCU
        redirected = []
        skipped = []
        redirect_map = {}

        for key, values in all_entries:
            new_key = self._redirect_key(key)
            if new_key is None:
                skipped.append(key)
                continue
            redirected.append((new_key, values))
            if key != new_key:
                redirect_map[key] = new_key

        result.key_count = len(redirected)
        result.skipped_count = len(skipped)
        result.redirect_map = redirect_map
        result.has_redirects = bool(redirected)

        if skipped:
            log.debug(f"Skipped {len(skipped)} registry keys (require admin/system access)")

        # 4. Write the merged .reg file to the output app root
        if redirected:
            reg_out = self.config.output_path / "registry_import.reg"
            self._write_reg_file(reg_out, redirected)
            result.reg_file_path = reg_out
            log.info(f"Wrote registry redirect file: {reg_out.name} ({len(redirected)} keys)")

        # 5. Write redirect map as JSON (used by launcher)
        if redirect_map:
            map_out = self.config.output_path / "_portablizer" / "registry_redirects.json"
            map_out.parent.mkdir(parents=True, exist_ok=True)
            map_out.write_text(json.dumps(redirect_map, indent=2))

        return result

    # ──────────────────────────────────────────────────────────────────────────

    def _redirect_key(self, key: str) -> Optional[str]:
        """
        Returns the redirected key, or None if this key should be skipped.
        """
        key_upper = key.upper()
        for hklm_prefix, hkcu_prefix in HKLM_TO_HKCU_MAP.items():
            if key_upper.startswith(hklm_prefix.upper()):
                if hkcu_prefix is None:
                    return None  # Skip — cannot redirect system/hardware/services
                tail = key[len(hklm_prefix):]
                return hkcu_prefix + tail
        # Already HKCU — keep as-is
        if key_upper.startswith("HKEY_CURRENT_USER") or key_upper.startswith("HKCU"):
            return key
        # Unknown root — skip
        return None

    def _parse_reg_file(self, path: Path) -> List[Tuple[str, dict]]:
        """
        Parse a Windows .reg file and return list of (key_path, {value_name: value}).
        Handles both REGEDIT4 (ANSI) and Windows Registry Editor Version 5 (UTF-16).
        """
        entries = []
        try:
            # Try UTF-16 first (modern .reg format), then fall back to UTF-8/latin-1
            try:
                text = path.read_text(encoding="utf-16")
            except (UnicodeDecodeError, UnicodeError):
                try:
                    text = path.read_text(encoding="utf-8")
                except Exception:
                    text = path.read_text(encoding="latin-1")

            current_key = None
            current_values = {}

            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue

                # Key header: [HKEY_LOCAL_MACHINE\Software\...]
                key_match = re.match(r"^\[(.+)\]$", line)
                if key_match:
                    if current_key:
                        entries.append((current_key, current_values))
                    current_key = key_match.group(1)
                    current_values = {}
                    continue

                # Value line: "Name"=... or @=...
                if current_key and "=" in line:
                    name, _, val = line.partition("=")
                    name = name.strip().strip('"')
                    current_values[name] = val.strip()

            if current_key:
                entries.append((current_key, current_values))

        except Exception as e:
            log.warning(f"Failed to parse reg file {path.name}: {e}")

        return entries

    def _scan_scripts_for_registry(self, app_root: Path) -> List[Tuple[str, dict]]:
        """
        Scan .bat, .cmd, .ps1, .inf, .ini files for registry references.
        """
        entries = []
        patterns = [
            r'(HKEY_LOCAL_MACHINE\\[^\s"\']+)',
            r'(HKLM:\\[^\s"\']+)',
            r'(HKCU:\\[^\s"\']+)',
        ]
        compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

        script_exts = {".bat", ".cmd", ".ps1", ".inf", ".ini"}
        for f in app_root.rglob("*"):
            if f.suffix.lower() not in script_exts:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
                for pat in compiled:
                    for match in pat.findall(text):
                        # Normalize path separators
                        key = match.replace("/", "\\").rstrip("\\")
                        entries.append((key, {}))
            except Exception:
                pass

        return entries

    def _write_reg_file(self, path: Path, entries: List[Tuple[str, dict]]):
        lines = ["Windows Registry Editor Version 5.00", ""]
        for key, values in entries:
            lines.append(f"[{key}]")
            for name, val in values.items():
                if name == "@":
                    lines.append(f"@={val}")
                else:
                    lines.append(f'"{name}"={val}')
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-16")
