"""
Configuration for a portablizer run.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    input_path: Path
    output_path: Path
    method: str = "auto"            # auto | extract | sandbox
    silent: bool = True
    keep_temp: bool = False
    patch_manifest: bool = True
    install_args: str = ""
    verbose: bool = False
    generate_report: bool = False

    # Internal paths (set during pipeline init)
    temp_dir: Optional[Path] = None
    sandbox_dir: Optional[Path] = None
    extracted_dir: Optional[Path] = None

    def __post_init__(self):
        self.input_path = Path(self.input_path)
        self.output_path = Path(self.output_path)
