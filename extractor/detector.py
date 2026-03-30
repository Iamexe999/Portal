"""
Installer format detector.

Identifies the installer technology used by inspecting:
  - File magic bytes / binary signatures
  - PE resources (version info, manifest, string tables)
  - Known byte patterns for Inno Setup, NSIS, MSI, etc.
"""

import re
import struct
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

log = logging.getLogger(__name__)


@dataclass
class InstallerInfo:
    installer_type: str           # inno_setup | nsis | msi | nullsoft | wise | zip_sfx | 7zip_sfx | winrar_sfx | unknown
    confidence: str               # high | medium | low
    version: Optional[str] = None
    silent_switch: str = "/S"
    has_drivers: bool = False
    has_services: bool = False
    app_name: Optional[str] = None
    publisher: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def __str__(self):
        return f"{self.installer_type} (confidence={self.confidence})"


# ──────────────────────────────────────────────────────────────────────────────
# Byte signatures
# ──────────────────────────────────────────────────────────────────────────────

SIGNATURES = {
    # Inno Setup — look for "Inno Setup Setup Data" in the binary
    "inno_setup": [
        b"Inno Setup Setup Data",
        b"InnoSetupVersion",
    ],
    # NSIS — Nullsoft Scriptable Install System
    "nsis": [
        b"Nullsoft Install System",
        b"NullsoftInst",
        b"\xef\xbe\xad\xde",          # NSIS magic dword at offset 0x1c
    ],
    # MSI OLE compound document header
    "msi": [
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",  # OLE2 magic
    ],
    # 7-Zip SFX
    "7zip_sfx": [
        b"7-Zip Self-Extracting",
        b"7zS",
    ],
    # WinRAR SFX
    "winrar_sfx": [
        b"Rar!\x1a\x07",
        b"WinRAR",
    ],
    # ZIP SFX
    "zip_sfx": [
        b"PK\x03\x04",
    ],
    # InstallShield
    "installshield": [
        b"InstallShield",
        b"InstShield",
    ],
    # Wise installer
    "wise": [
        b"Wise Installation Wizard",
        b"WiseInst",
    ],
    # Advanced Installer
    "advanced_installer": [
        b"Advanced Installer",
    ],
    # Squirrel (Electron apps like Slack, Discord, VS Code)
    "squirrel": [
        b"Squirrel",
        b"SquirrelSetup",
    ],
}

# Silent install switches per installer type
SILENT_SWITCHES = {
    "inno_setup":         "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
    "nsis":               "/S",
    "msi":                "/quiet /qn /norestart",
    "installshield":      "/s /v\"/qn\"",
    "wise":               "/s",
    "advanced_installer": "/exenoui /qn",
    "squirrel":           "--silent",
    "7zip_sfx":           "-y",
    "winrar_sfx":         "-s",
    "zip_sfx":            "-y",
    "unknown":            "/S /silent /quiet",
}

# Known driver-related strings that indicate kernel driver installation
DRIVER_INDICATORS = [
    b"CreateService",
    b"SERVICE_KERNEL_DRIVER",
    b".sys\x00",
    b"NtLoadDriver",
    b"ZwLoadDriver",
    b"DriverEntry",
]

SERVICE_INDICATORS = [
    b"CreateServiceA",
    b"CreateServiceW",
    b"StartService",
    b"SERVICE_WIN32_OWN_PROCESS",
    b"SERVICE_AUTO_START",
]


class InstallerDetector:

    def __init__(self, config):
        self.config = config
        self.path = config.input_path

    def detect(self) -> InstallerInfo:
        try:
            data = self._read_binary()
        except Exception as e:
            log.warning(f"Could not read binary for detection: {e}")
            return InstallerInfo(installer_type="unknown", confidence="low")

        installer_type, confidence = self._detect_type(data)
        version = self._extract_version_hint(data, installer_type)
        has_drivers = self._check_driver_indicators(data)
        has_services = self._check_service_indicators(data)
        app_name, publisher = self._extract_pe_metadata()

        info = InstallerInfo(
            installer_type=installer_type,
            confidence=confidence,
            version=version,
            silent_switch=SILENT_SWITCHES.get(installer_type, "/S"),
            has_drivers=has_drivers,
            has_services=has_services,
            app_name=app_name,
            publisher=publisher,
        )
        log.debug(f"Detection result: {info}")
        return info

    # ──────────────────────────────────────────────────────────────────────────
    def _read_binary(self, max_bytes: int = 2 * 1024 * 1024) -> bytes:
        """Read up to max_bytes from the exe for signature scanning."""
        with open(self.path, "rb") as f:
            return f.read(max_bytes)

    def _detect_type(self, data: bytes):
        hits = {}
        for name, patterns in SIGNATURES.items():
            count = sum(1 for p in patterns if p in data)
            if count:
                hits[name] = count

        if not hits:
            return "unknown", "low"

        # MSI is an OLE container — often wrapped in an EXE bootstrapper.
        # If the file is literally just an OLE doc, it's a pure MSI.
        if data[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
            if b"Inno Setup" not in data and b"Nullsoft" not in data:
                return "msi", "high"

        # Score: give more weight to specific/unique patterns
        best = max(hits, key=lambda k: hits[k] * self._type_specificity(k))
        confidence = "high" if hits[best] >= 2 else "medium"
        return best, confidence

    def _type_specificity(self, t: str) -> int:
        """Higher = more reliable identifier."""
        scores = {
            "inno_setup": 10,
            "nsis": 9,
            "squirrel": 9,
            "installshield": 8,
            "wise": 8,
            "advanced_installer": 8,
            "7zip_sfx": 7,
            "winrar_sfx": 7,
            "msi": 6,
            "zip_sfx": 3,   # generic
            "unknown": 1,
        }
        return scores.get(t, 5)

    def _extract_version_hint(self, data: bytes, installer_type: str) -> Optional[str]:
        """Try to extract a version string from the binary."""
        # Look for common Inno Setup version pattern
        if installer_type == "inno_setup":
            m = re.search(rb"Inno Setup Setup Data \((\d+\.\d+\.\d+)\)", data)
            if m:
                return m.group(1).decode("ascii", errors="ignore")

        # NSIS version
        if installer_type == "nsis":
            m = re.search(rb"Nullsoft Install System v(\d+\.\d+)", data)
            if m:
                return m.group(1).decode("ascii", errors="ignore")

        return None

    def _check_driver_indicators(self, data: bytes) -> bool:
        return any(ind in data for ind in DRIVER_INDICATORS)

    def _check_service_indicators(self, data: bytes) -> bool:
        return any(ind in data for ind in SERVICE_INDICATORS)

    def _extract_pe_metadata(self):
        """
        Extract app name and publisher from PE version info.
        Uses `sigcheck` if available, otherwise falls back to raw PE parsing.
        """
        app_name = None
        publisher = None
        try:
            app_name, publisher = self._parse_pe_version_info()
        except Exception as e:
            log.debug(f"PE metadata extraction failed: {e}")
        return app_name, publisher

    def _parse_pe_version_info(self):
        """
        Parse VS_VERSIONINFO resource from a PE file.
        Returns (product_name, company_name) tuple.
        """
        with open(self.path, "rb") as f:
            data = f.read()

        # Scan for StringFileInfo block containing version strings
        # Look for UTF-16LE encoded keys like "ProductName\0"
        def find_utf16_string(key: str) -> Optional[str]:
            needle = (key + "\x00").encode("utf-16-le")
            idx = data.find(needle)
            if idx == -1:
                return None
            # Value follows after the key + alignment padding
            start = idx + len(needle)
            # Skip padding bytes
            while start < len(data) - 1 and data[start] == 0 and data[start+1] == 0:
                start += 2
            # Read until double null
            result = bytearray()
            i = start
            while i < len(data) - 1:
                c1, c2 = data[i], data[i+1]
                if c1 == 0 and c2 == 0:
                    break
                result.extend([c1, c2])
                i += 2
                if len(result) > 256:
                    break
            try:
                return result.decode("utf-16-le").strip().strip("\x00")
            except Exception:
                return None

        product_name = find_utf16_string("ProductName")
        company_name = find_utf16_string("CompanyName")
        return product_name, company_name
