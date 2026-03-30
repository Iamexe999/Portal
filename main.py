#!/usr/bin/env python3
"""
Portablizer - Convert any .exe installer into a portable, no-admin-required application.
"""

import sys
import argparse
import logging
from pathlib import Path

from core.pipeline import PortablizerPipeline
from core.config import Config
from ui.console import ConsoleUI

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    )

def parse_args():
    parser = argparse.ArgumentParser(
        prog="portablizer",
        description="Convert .exe installers into portable apps that require no admin privileges.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  portablizer app.exe
  portablizer app.exe --output ./MyPortableApp
  portablizer app.exe --method extract
  portablizer app.exe --method sandbox --keep-temp
  portablizer app.exe --silent
        """
    )
    parser.add_argument("input", help="Path to the .exe installer")
    parser.add_argument(
        "--output", "-o",
        help="Output directory for the portable app (default: <input_name>_portable/)"
    )
    parser.add_argument(
        "--method", "-m",
        choices=["auto", "extract", "sandbox"],
        default="auto",
        help="Conversion method: auto (detect best), extract (static), sandbox (runtime capture). Default: auto"
    )
    parser.add_argument(
        "--silent", "-s",
        action="store_true",
        help="Run installer silently (no GUI prompts)"
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep temporary files after conversion (useful for debugging)"
    )
    parser.add_argument(
        "--patch-manifest",
        action="store_true",
        default=True,
        help="Patch UAC manifest in output executables (default: true)"
    )
    parser.add_argument(
        "--no-patch-manifest",
        dest="patch_manifest",
        action="store_false",
        help="Skip UAC manifest patching"
    )
    parser.add_argument(
        "--install-args",
        help="Extra arguments to pass to the installer (for sandbox mode)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate a detailed conversion report"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)

    ui = ConsoleUI()
    ui.print_banner()

    # Validate input
    input_path = Path(args.input)
    if not input_path.exists():
        ui.error(f"Input file not found: {input_path}")
        sys.exit(1)
    if not input_path.suffix.lower() == ".exe":
        ui.warn(f"Input does not have .exe extension. Proceeding anyway...")

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.parent / f"{input_path.stem}_portable"

    # Build config
    config = Config(
        input_path=input_path,
        output_path=output_path,
        method=args.method,
        silent=args.silent,
        keep_temp=args.keep_temp,
        patch_manifest=args.patch_manifest,
        install_args=args.install_args or "",
        verbose=args.verbose,
        generate_report=args.report,
    )

    ui.info(f"Input:   {input_path.resolve()}")
    ui.info(f"Output:  {output_path.resolve()}")
    ui.info(f"Method:  {args.method}")

    # Run pipeline
    pipeline = PortablizerPipeline(config, ui)
    result = pipeline.run()

    if result.success:
        ui.success(f"\nPortable app created at: {result.output_path}")
        ui.info(f"Files extracted: {result.file_count}")
        if result.warnings:
            ui.warn(f"\nWarnings ({len(result.warnings)}):")
            for w in result.warnings:
                ui.warn(f"  • {w}")
        if result.limitations:
            ui.warn(f"\nLimitations (features that may not work without admin):")
            for lim in result.limitations:
                ui.warn(f"  ⚠ {lim}")
        if args.report:
            ui.info(f"\nReport saved to: {result.report_path}")
    else:
        ui.error(f"\nConversion failed: {result.error}")
        if args.verbose and result.traceback:
            ui.error(result.traceback)
        sys.exit(1)


if __name__ == "__main__":
    main()
