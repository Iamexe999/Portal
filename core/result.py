"""
Result object returned by the pipeline.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class PipelineResult:
    success: bool
    output_path: Optional[Path] = None
    file_count: int = 0
    warnings: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    report_path: Optional[Path] = None
    error: Optional[str] = None
    traceback: Optional[str] = None
    installer_type: Optional[str] = None
    method_used: Optional[str] = None
