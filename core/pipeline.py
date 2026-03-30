"""
Main pipeline: orchestrates detection → extraction/sandbox → patch → package.
"""

import logging
import traceback
import tempfile
import shutil
from pathlib import Path

from core.config import Config
from core.result import PipelineResult
from extractor.detector import InstallerDetector
from extractor.extractor import InstallerExtractor
from patcher.manifest import ManifestPatcher
from patcher.registry import RegistryRedirectBuilder
from sandbox.runner import SandboxRunner
from sandbox.differ import SnapshotDiffer
from packager.packager import PortablePackager
from packager.reporter import ReportGenerator

log = logging.getLogger(__name__)


class PortablizerPipeline:

    def __init__(self, config: Config, ui=None):
        self.config = config
        self.ui = ui
        self.result = PipelineResult(success=False)

    def _step(self, name: str):
        if self.ui:
            self.ui.step(name)

    def run(self) -> PipelineResult:
        config = self.config

        try:
            # 1. Create temp workspace
            config.temp_dir = Path(tempfile.mkdtemp(prefix="portablizer_"))
            config.sandbox_dir = config.temp_dir / "sandbox"
            config.extracted_dir = config.temp_dir / "extracted"
            config.sandbox_dir.mkdir(parents=True)
            config.extracted_dir.mkdir(parents=True)
            log.debug(f"Temp dir: {config.temp_dir}")

            # 2. Detect installer format
            self._step("Detecting installer format")
            detector = InstallerDetector(config)
            installer_info = detector.detect()
            self.result.installer_type = installer_info.installer_type
            log.info(f"Detected installer: {installer_info}")
            if self.ui:
                self.ui.info(f"  Installer type: {installer_info.installer_type}")
                self.ui.info(f"  Confidence: {installer_info.confidence}")
                if installer_info.version:
                    self.ui.info(f"  Version hint: {installer_info.version}")

            # Check for hard blockers (drivers, services)
            if installer_info.has_drivers:
                self.result.limitations.append(
                    "Installer installs kernel drivers — driver functionality will NOT work without admin."
                )
            if installer_info.has_services:
                self.result.limitations.append(
                    "Installer registers Windows services — services will NOT start without admin."
                )

            # 3. Determine method
            method = config.method
            if method == "auto":
                method = self._choose_method(installer_info)
                if self.ui:
                    self.ui.info(f"  Auto-selected method: {method}")
            self.result.method_used = method

            # 4a. Extract method
            if method == "extract":
                self._step("Extracting installer contents")
                extractor = InstallerExtractor(config, installer_info)
                extract_result = extractor.extract()
                if not extract_result.success:
                    raise RuntimeError(f"Extraction failed: {extract_result.error}")
                if self.ui:
                    self.ui.info(f"  Extracted {extract_result.file_count} files")
                app_root = extract_result.output_dir

            # 4b. Sandbox method
            elif method == "sandbox":
                self._step("Taking pre-install snapshot")
                differ = SnapshotDiffer(config)
                pre_snap = differ.snapshot()

                self._step("Running installer in sandbox")
                runner = SandboxRunner(config, installer_info)
                run_result = runner.run()
                if not run_result.success:
                    raise RuntimeError(f"Sandbox run failed: {run_result.error}")

                self._step("Capturing installed files (diffing snapshot)")
                post_snap = differ.snapshot()
                diff = differ.diff(pre_snap, post_snap)
                app_root = differ.collect(diff, config.extracted_dir)
                if self.ui:
                    self.ui.info(f"  Captured {diff.file_count} new/changed files")
                    self.ui.info(f"  Captured {diff.registry_key_count} registry keys")

            else:
                raise ValueError(f"Unknown method: {method}")

            # 5. Patch UAC manifests
            if config.patch_manifest:
                self._step("Patching UAC manifests")
                patcher = ManifestPatcher(config)
                patch_result = patcher.patch_directory(app_root)
                if self.ui:
                    self.ui.info(f"  Patched {patch_result.patched_count} executables")
                self.result.warnings.extend(patch_result.warnings)

            # 6. Build registry redirect layer
            self._step("Building registry redirect layer")
            reg_builder = RegistryRedirectBuilder(config)
            reg_result = reg_builder.build(app_root)
            if reg_result.has_redirects:
                if self.ui:
                    self.ui.info(f"  Registry redirect: {reg_result.key_count} keys → user hive")

            # 7. Package everything into portable output
            self._step("Packaging portable application")
            config.output_path.mkdir(parents=True, exist_ok=True)
            packager = PortablePackager(config, installer_info)
            pack_result = packager.package(app_root)
            self.result.file_count = pack_result.file_count
            self.result.warnings.extend(pack_result.warnings)
            self.result.limitations.extend(pack_result.limitations)

            # 8. Optional report
            if config.generate_report:
                self._step("Generating report")
                reporter = ReportGenerator(config)
                self.result.report_path = reporter.generate(
                    installer_info, pack_result, self.result
                )

            # 9. Cleanup
            if not config.keep_temp:
                shutil.rmtree(config.temp_dir, ignore_errors=True)

            self.result.success = True
            self.result.output_path = config.output_path
            return self.result

        except Exception as e:
            log.error(f"Pipeline failed: {e}")
            self.result.success = False
            self.result.error = str(e)
            self.result.traceback = traceback.format_exc()
            if not config.keep_temp and config.temp_dir and config.temp_dir.exists():
                shutil.rmtree(config.temp_dir, ignore_errors=True)
            return self.result

    def _choose_method(self, installer_info) -> str:
        """
        Auto-select the best conversion method based on installer type.
        Static extraction is preferred when the format is known.
        Fall back to sandbox for unknown or complex formats.
        """
        extractable_types = {
            "inno_setup", "nsis", "msi", "zip_sfx", "7zip_sfx", "winrar_sfx"
        }
        if installer_info.installer_type in extractable_types:
            return "extract"
        return "sandbox"
