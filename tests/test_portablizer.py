"""
Test suite for Portablizer.

Run with: pytest tests/ -v
"""

import io
import os
import sys
import json
import struct
import tempfile
import platform
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import Config
from core.result import PipelineResult
from extractor.detector import InstallerDetector, InstallerInfo, SIGNATURES
from patcher.manifest import ManifestPatcher, ADMIN_PATTERNS, REPLACEMENTS
from patcher.registry import RegistryRedirectBuilder
from packager.packager import PortablePackager
from packager.reporter import ReportGenerator


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def make_config(tmp_path: Path) -> Config:
    input_exe = tmp_path / "test_setup.exe"
    input_exe.write_bytes(b"MZ" + b"\x00" * 100)
    return Config(
        input_path=input_exe,
        output_path=tmp_path / "output",
        method="extract",
        silent=True,
        keep_temp=False,
        patch_manifest=True,
        verbose=False,
    )


def make_inno_exe(tmp_path: Path) -> Path:
    """Create a fake Inno Setup .exe with the right signature."""
    p = tmp_path / "inno_setup.exe"
    p.write_bytes(b"MZ" + b"\x00" * 50 + b"Inno Setup Setup Data (5.6.1)" + b"\x00" * 100)
    return p


def make_nsis_exe(tmp_path: Path) -> Path:
    p = tmp_path / "nsis_setup.exe"
    p.write_bytes(b"MZ" + b"\x00" * 50 + b"Nullsoft Install System v3.08" + b"\x00" * 100)
    return p


def make_pe_with_admin_manifest(tmp_path: Path) -> Path:
    """Create a minimal PE-like binary containing an admin manifest."""
    p = tmp_path / "admin_app.exe"
    manifest_fragment = b'<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>'
    p.write_bytes(b"MZ" + b"\x00" * 100 + manifest_fragment + b"\x00" * 50)
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Detector tests
# ─────────────────────────────────────────────────────────────────────────────

class TestInstallerDetector(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_config(self, exe_path: Path) -> Config:
        return Config(input_path=exe_path, output_path=self.tmp_path / "out")

    def test_detect_inno_setup(self):
        exe = make_inno_exe(self.tmp_path)
        config = self._make_config(exe)
        detector = InstallerDetector(config)
        info = detector.detect()
        self.assertEqual(info.installer_type, "inno_setup")
        self.assertIn(info.confidence, ("high", "medium"))

    def test_detect_nsis(self):
        exe = make_nsis_exe(self.tmp_path)
        config = self._make_config(exe)
        detector = InstallerDetector(config)
        info = detector.detect()
        self.assertEqual(info.installer_type, "nsis")

    def test_detect_unknown(self):
        exe = self.tmp_path / "unknown.exe"
        exe.write_bytes(b"MZ" + b"\x00" * 200)
        config = self._make_config(exe)
        detector = InstallerDetector(config)
        info = detector.detect()
        self.assertEqual(info.installer_type, "unknown")
        self.assertEqual(info.confidence, "low")

    def test_detect_driver_indicator(self):
        exe = self.tmp_path / "driver_setup.exe"
        exe.write_bytes(b"MZ" + b"Nullsoft Install System v3" + b"SERVICE_KERNEL_DRIVER" + b"\x00" * 50)
        config = self._make_config(exe)
        detector = InstallerDetector(config)
        info = detector.detect()
        self.assertTrue(info.has_drivers)

    def test_detect_service_indicator(self):
        exe = self.tmp_path / "service_setup.exe"
        exe.write_bytes(b"MZ" + b"Nullsoft Install System v3" + b"CreateServiceA" + b"\x00" * 50)
        config = self._make_config(exe)
        detector = InstallerDetector(config)
        info = detector.detect()
        self.assertTrue(info.has_services)

    def test_silent_switch_defaults(self):
        exe = make_inno_exe(self.tmp_path)
        config = self._make_config(exe)
        detector = InstallerDetector(config)
        info = detector.detect()
        self.assertIn("VERYSILENT", info.silent_switch.upper())

    def test_version_extraction_inno(self):
        exe = self.tmp_path / "inno_version.exe"
        exe.write_bytes(b"Inno Setup Setup Data (5.6.1)" + b"\x00" * 50)
        config = self._make_config(exe)
        detector = InstallerDetector(config)
        info = detector.detect()
        self.assertEqual(info.version, "5.6.1")


# ─────────────────────────────────────────────────────────────────────────────
# Manifest patcher tests
# ─────────────────────────────────────────────────────────────────────────────

class TestManifestPatcher(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_config(self):
        return Config(
            input_path=self.tmp_path / "dummy.exe",
            output_path=self.tmp_path / "out"
        )

    def test_binary_patch_require_admin(self):
        exe = make_pe_with_admin_manifest(self.tmp_path)
        original_size = exe.stat().st_size
        config = self._make_config()
        patcher = ManifestPatcher(config)
        patched = patcher._patch_binary_direct(exe, exe.read_bytes())
        self.assertTrue(patched)
        new_data = exe.read_bytes()
        self.assertNotIn(b'level="requireAdministrator"', new_data)
        self.assertIn(b'level="asInvoker"', new_data)
        # File size must be unchanged (binary patch, no offset shift)
        self.assertEqual(exe.stat().st_size, original_size)

    def test_binary_patch_highest_available(self):
        exe = self.tmp_path / "ha_app.exe"
        fragment = b'<requestedExecutionLevel level="highestAvailable" uiAccess="false"/>'
        exe.write_bytes(b"MZ" + b"\x00" * 50 + fragment + b"\x00" * 50)
        original_size = exe.stat().st_size
        config = self._make_config()
        patcher = ManifestPatcher(config)
        patched = patcher._patch_binary_direct(exe, exe.read_bytes())
        self.assertTrue(patched)
        new_data = exe.read_bytes()
        self.assertNotIn(b'level="highestAvailable"', new_data)
        self.assertIn(b'level="asInvoker"', new_data)
        self.assertEqual(exe.stat().st_size, original_size)

    def test_no_patch_needed(self):
        exe = self.tmp_path / "normal.exe"
        exe.write_bytes(b"MZ" + b"no manifest here" + b"\x00" * 50)
        config = self._make_config()
        patcher = ManifestPatcher(config)
        patched = patcher._patch_binary_direct(exe, exe.read_bytes())
        self.assertFalse(patched)

    def test_replacement_lengths_are_equal(self):
        """Critical: replacements must be same length as patterns for in-place patching."""
        for pattern, replacement in REPLACEMENTS.items():
            self.assertEqual(
                len(pattern), len(replacement),
                f"Length mismatch for pattern: {pattern!r}\n"
                f"  Pattern:     {len(pattern)} bytes\n"
                f"  Replacement: {len(replacement)} bytes"
            )

    def test_patch_directory(self):
        app_dir = self.tmp_path / "app"
        app_dir.mkdir()
        # Create two .exe files
        for i in range(3):
            f = app_dir / f"app{i}.exe"
            fragment = b'level="requireAdministrator"' if i < 2 else b"no manifest"
            f.write_bytes(b"MZ" + b"\x00" * 30 + fragment + b"\x00" * 30)
        config = self._make_config()
        patcher = ManifestPatcher(config)
        result = patcher.patch_directory(app_dir)
        self.assertEqual(result.patched_count, 2)


# ─────────────────────────────────────────────────────────────────────────────
# Registry redirect tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRegistryRedirectBuilder(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_config(self):
        return Config(
            input_path=self.tmp_path / "dummy.exe",
            output_path=self.tmp_path / "out"
        )

    def test_redirect_hklm_software(self):
        config = self._make_config()
        builder = RegistryRedirectBuilder(config)
        result = builder._redirect_key(r"HKEY_LOCAL_MACHINE\SOFTWARE\MyApp")
        self.assertIsNotNone(result)
        self.assertIn("HKEY_CURRENT_USER", result)
        self.assertIn("SOFTWARE", result)
        self.assertIn("MyApp", result)

    def test_skip_hklm_system(self):
        config = self._make_config()
        builder = RegistryRedirectBuilder(config)
        result = builder._redirect_key(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MyService")
        self.assertIsNone(result)

    def test_keep_hkcu(self):
        config = self._make_config()
        builder = RegistryRedirectBuilder(config)
        original = r"HKEY_CURRENT_USER\SOFTWARE\MyApp"
        result = builder._redirect_key(original)
        self.assertEqual(result, original)

    def test_parse_reg_file(self):
        config = self._make_config()
        reg_file = self.tmp_path / "test.reg"
        content = (
            "Windows Registry Editor Version 5.00\n\n"
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\TestApp]\n"
            '"InstallDir"="C:\\\\TestApp"\n'
            '"Version"="1.0"\n\n'
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\TestApp\\Settings]\n"
            '"Theme"="dark"\n'
        )
        reg_file.write_text(content, encoding="utf-8")
        builder = RegistryRedirectBuilder(config)
        entries = builder._parse_reg_file(reg_file)
        self.assertEqual(len(entries), 2)
        keys = [e[0] for e in entries]
        self.assertIn(r"HKEY_LOCAL_MACHINE\SOFTWARE\TestApp", keys)


# ─────────────────────────────────────────────────────────────────────────────
# Packager tests
# ─────────────────────────────────────────────────────────────────────────────

class TestPortablePackager(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_app_dir(self) -> Path:
        app_dir = self.tmp_path / "app_source"
        app_dir.mkdir()
        (app_dir / "MyApp.exe").write_bytes(b"MZ" + b"\x00" * 100)
        (app_dir / "MyApp.dll").write_bytes(b"MZ" + b"\x00" * 50)
        (app_dir / "uninstall.exe").write_bytes(b"MZ" + b"\x00" * 30)
        data_dir = app_dir / "data"
        data_dir.mkdir()
        (data_dir / "config.ini").write_text("[Settings]\nfoo=bar\n")
        return app_dir

    def _make_info(self):
        return InstallerInfo(
            installer_type="nsis",
            confidence="high",
            app_name="MyApp",
            publisher="TestCorp",
            silent_switch="/S",
        )

    def test_package_creates_output_structure(self):
        app_dir = self._make_app_dir()
        config = Config(
            input_path=self.tmp_path / "setup.exe",
            output_path=self.tmp_path / "portable",
        )
        config.output_path.mkdir(parents=True)
        info = self._make_info()
        packager = PortablePackager(config, info)
        result = packager.package(app_dir)

        self.assertTrue(result.success)
        self.assertTrue((config.output_path / "app").exists())
        self.assertTrue((config.output_path / "_portablizer").exists())
        self.assertTrue((config.output_path / "_portablizer" / "launcher.bat").exists())
        self.assertTrue((config.output_path / "_portablizer" / "launcher.ps1").exists())
        self.assertTrue((config.output_path / "README.txt").exists())

    def test_package_file_count(self):
        app_dir = self._make_app_dir()
        config = Config(
            input_path=self.tmp_path / "setup.exe",
            output_path=self.tmp_path / "portable",
        )
        config.output_path.mkdir(parents=True)
        info = self._make_info()
        packager = PortablePackager(config, info)
        result = packager.package(app_dir)
        # app_dir has 4 files (MyApp.exe, MyApp.dll, uninstall.exe, data/config.ini)
        self.assertEqual(result.file_count, 4)

    def test_find_main_exe(self):
        app_dir = self._make_app_dir()
        config = Config(
            input_path=self.tmp_path / "setup.exe",
            output_path=self.tmp_path / "portable",
        )
        config.output_path.mkdir(parents=True)
        info = self._make_info()
        packager = PortablePackager(config, info)
        # Copy to output/app first as the packager expects
        app_dest = config.output_path / "app"
        import shutil
        shutil.copytree(app_dir, app_dest)
        main = packager._find_main_exe(app_dest)
        self.assertIsNotNone(main)
        self.assertEqual(main.stem.lower(), "myapp")

    def test_suspect_driver_detection(self):
        app_dir = self._make_app_dir()
        (app_dir / "driver.sys").write_bytes(b"\x00" * 100)
        config = Config(
            input_path=self.tmp_path / "setup.exe",
            output_path=self.tmp_path / "portable",
        )
        config.output_path.mkdir(parents=True)
        info = self._make_info()
        packager = PortablePackager(config, info)
        suspects = packager._scan_for_suspects(app_dir)
        self.assertTrue(any(s.suffix == ".sys" for s in suspects))

    def test_readme_generated(self):
        app_dir = self._make_app_dir()
        config = Config(
            input_path=self.tmp_path / "setup.exe",
            output_path=self.tmp_path / "portable",
        )
        config.output_path.mkdir(parents=True)
        info = self._make_info()
        packager = PortablePackager(config, info)
        result = packager.package(app_dir)
        readme = config.output_path / "README.txt"
        self.assertTrue(readme.exists())
        content = readme.read_text()
        self.assertIn("MyApp", content)
        self.assertIn("Portable", content)


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline integration test (mocked extraction)
# ─────────────────────────────────────────────────────────────────────────────

class TestPipelineIntegration(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_extract_pipeline(self):
        """
        Test the full extract pipeline with a mocked extractor.
        Verifies that the pipeline produces a complete output structure.
        """
        from core.pipeline import PortablizerPipeline

        # Create a fake NSIS installer
        input_exe = self.tmp_path / "FakeApp_Setup.exe"
        input_exe.write_bytes(
            b"MZ" + b"\x00" * 30 +
            b"Nullsoft Install System v3.08" +
            b"\x00" * 200
        )

        config = Config(
            input_path=input_exe,
            output_path=self.tmp_path / "output",
            method="extract",
            keep_temp=True,
            patch_manifest=True,
        )

        # Mock the extractor to return a fake app directory
        def fake_extract(self_ext):
            from extractor.extractor import ExtractResult
            app_dir = config.extracted_dir
            app_dir.mkdir(parents=True, exist_ok=True)
            (app_dir / "FakeApp.exe").write_bytes(b"MZ" + b"\x00" * 100)
            (app_dir / "FakeApp.dll").write_bytes(b"MZ" + b"\x00" * 50)
            return ExtractResult(success=True, output_dir=app_dir, file_count=2)

        with patch("extractor.extractor.InstallerExtractor.extract", fake_extract):
            pipeline = PortablizerPipeline(config)
            result = pipeline.run()

        self.assertTrue(result.success, f"Pipeline failed: {result.error}\n{result.traceback}")
        self.assertTrue((config.output_path / "app").exists())
        self.assertTrue((config.output_path / "_portablizer" / "launcher.bat").exists())
        self.assertGreater(result.file_count, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
