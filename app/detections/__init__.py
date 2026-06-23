"""Detection modules."""

from app.detections.engine import run_detections
from app.detections.rules import DetectionResult

__all__ = ["DetectionResult", "run_detections"]
