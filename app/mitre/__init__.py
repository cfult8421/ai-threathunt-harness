"""MITRE ATT&CK mapping modules."""

from app.mitre.mappings import get_techniques_for_detection
from app.mitre.models import DetectionToTechnique, Technique

__all__ = ["DetectionToTechnique", "Technique", "get_techniques_for_detection"]
