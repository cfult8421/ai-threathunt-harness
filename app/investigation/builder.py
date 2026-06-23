from app.detections import DetectionResult
from app.investigation.models import InvestigationPackage
from app.mitre import Technique
from app.normalization import NormalizedEvent


SEVERITY_RANK: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def build_investigation_package(
    event: NormalizedEvent,
    detections: list[DetectionResult],
    mitre_techniques: list[Technique],
) -> InvestigationPackage:
    severity = _aggregate_severity(detections)
    confidence = _aggregate_confidence(detections)

    return InvestigationPackage(
        event=event,
        detections=detections,
        mitre_techniques=mitre_techniques,
        summary=_build_summary(event, detections, mitre_techniques, severity),
        evidence=_build_evidence(event),
        severity=severity,
        confidence=confidence,
    )


def _build_summary(
    event: NormalizedEvent,
    detections: list[DetectionResult],
    mitre_techniques: list[Technique],
    severity: str,
) -> str:
    detection_names = ", ".join(detection.rule_name for detection in detections) or "no detections"
    technique_ids = ", ".join(technique.technique_id for technique in mitre_techniques) or "no mapped techniques"
    return (
        f"{severity.title()} investigation package for {event.process_name} on {event.host}: "
        f"{detection_names}. MITRE ATT&CK: {technique_ids}."
    )


def _build_evidence(event: NormalizedEvent) -> dict[str, str | None]:
    return {
        "host": event.host,
        "user": event.user,
        "process_name": event.process_name,
        "parent_process": event.parent_process,
        "command_line": event.command_line,
    }


def _aggregate_severity(detections: list[DetectionResult]) -> str:
    if not detections:
        return "informational"

    return max(detections, key=lambda detection: SEVERITY_RANK.get(detection.severity.lower(), 0)).severity


def _aggregate_confidence(detections: list[DetectionResult]) -> float:
    if not detections:
        return 0.0

    return max(detection.confidence for detection in detections)
