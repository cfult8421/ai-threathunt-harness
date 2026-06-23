from typing import Any

from app.investigation import InvestigationPackage
from app.scoring.models import ScoreResult


MAX_SCORE = 100


def score_investigation(
    package: InvestigationPackage,
    validated_llm_output: dict[str, Any],
) -> ScoreResult:
    components: dict[str, int] = {
        "detections": 0,
        "mitre_techniques": 0,
        "evidence_references": 0,
        "recommended_actions": 0,
        "confidence": 0,
        "likely_attack": 0,
    }
    notes: list[str] = []

    if package.detections:
        components["detections"] = 25
    else:
        notes.append("No detections were present.")

    if package.mitre_techniques:
        components["mitre_techniques"] = 20
    else:
        notes.append("No MITRE techniques were mapped.")

    if validated_llm_output.get("evidence_references"):
        components["evidence_references"] = 20
    else:
        notes.append("LLM output did not include evidence references.")

    if validated_llm_output.get("recommended_actions"):
        components["recommended_actions"] = 15
    else:
        notes.append("LLM output did not include recommended actions.")

    confidence = validated_llm_output.get("confidence")
    if isinstance(confidence, int | float) and not isinstance(confidence, bool) and 0.5 <= confidence <= 1.0:
        components["confidence"] = 10
    else:
        notes.append("LLM confidence was below 0.5 or invalid.")

    if str(validated_llm_output.get("likely_attack", "")).strip():
        components["likely_attack"] = 10
    else:
        notes.append("LLM output did not include a likely attack.")

    total_score = sum(components.values())
    return ScoreResult(
        total_score=total_score,
        max_score=MAX_SCORE,
        score_percent=round((total_score / MAX_SCORE) * 100, 2),
        components=components,
        notes=notes,
    )
