from pydantic import BaseModel, ConfigDict


class Technique(BaseModel):
    model_config = ConfigDict(frozen=True)

    technique_id: str
    name: str


class DetectionToTechnique(BaseModel):
    model_config = ConfigDict(frozen=True)

    detection_key: str
    techniques: tuple[Technique, ...]
