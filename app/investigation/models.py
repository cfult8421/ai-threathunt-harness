from pydantic import BaseModel, ConfigDict, Field

from app.detections import DetectionResult
from app.mitre import Technique
from app.normalization import NormalizedEvent


class InvestigationPackage(BaseModel):
    model_config = ConfigDict(frozen=True)

    event: NormalizedEvent
    detections: list[DetectionResult]
    mitre_techniques: list[Technique]
    summary: str
    evidence: dict[str, str | None]
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
