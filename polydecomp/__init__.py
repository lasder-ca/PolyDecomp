"""PolyDecomp static analysis package."""

from .engine import analyze_file
from .model import AnalysisReport, Finding

__all__ = ["AnalysisReport", "Finding", "analyze_file"]
__version__ = "0.1.0"
