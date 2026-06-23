from app.detections.rules import RULES, DetectionResult
from app.normalization import NormalizedEvent


def run_detections(event: NormalizedEvent) -> list[DetectionResult]:
    results: list[DetectionResult] = []
    for rule in RULES:
        result = rule(event)
        if result is not None:
            results.append(result)
    return results
