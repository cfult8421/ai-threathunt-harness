from pydantic import BaseModel, ConfigDict


class ScoreResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    total_score: int
    max_score: int
    score_percent: float
    components: dict[str, int]
    notes: list[str]
