from datetime import datetime, timezone

from app.detections import DetectionResult
from app.investigation import InvestigationPackage, build_investigation_package
from app.mitre import Technique
from app.normalization import NormalizedEvent


def _event() -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 6, 23, 4, 15, 30, tzinfo=timezone.utc),
        host="workstation-01",
        user="ACME\\alice",
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
        hash_sha256=None,
        event_type="process_creation",
        source="sysmon",
    )


def _detection(rule_name: str, severity: str, confidence: float) -> DetectionResult:
    return DetectionResult(
        rule_id=f"TH-TEST-{severity.upper()}",
        rule_name=rule_name,
        severity=severity,
        confidence=confidence,
        description="Test detection.",
        host="workstation-01",
        user="ACME\\alice",
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
        source="sysmon",
    )


def test_builds_investigation_package_with_event_detections_and_mitre_techniques() -> None:
    event = _event()
    detections = [_detection("Encoded PowerShell command", "high", 0.9)]
    techniques = [
        Technique(technique_id="T1059.001", name="PowerShell"),
        Technique(technique_id="T1027", name="Obfuscated Files or Information"),
    ]

    package = build_investigation_package(event, detections, techniques)

    assert isinstance(package, InvestigationPackage)
    assert package.event == event
    assert package.detections == detections
    assert package.mitre_techniques == techniques


def test_summary_is_deterministic_and_includes_detection_and_technique_context() -> None:
    event = _event()
    detections = [_detection("Encoded PowerShell command", "high", 0.9)]
    techniques = [Technique(technique_id="T1059.001", name="PowerShell")]

    first_package = build_investigation_package(event, detections, techniques)
    second_package = build_investigation_package(event, detections, techniques)

    assert first_package.summary == second_package.summary
    assert "Encoded PowerShell command" in first_package.summary
    assert "T1059.001" in first_package.summary
    assert event.host in first_package.summary


def test_evidence_includes_key_event_fields() -> None:
    package = build_investigation_package(_event(), [], [])

    assert package.evidence == {
        "host": "workstation-01",
        "user": "ACME\\alice",
        "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_process": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
    }


def test_severity_uses_highest_detection_severity() -> None:
    detections = [
        _detection("Certutil download behavior", "medium", 0.8),
        _detection("Office spawning PowerShell", "high", 0.85),
    ]

    package = build_investigation_package(_event(), detections, [])

    assert package.severity == "high"


def test_confidence_uses_highest_detection_confidence() -> None:
    detections = [
        _detection("Certutil download behavior", "medium", 0.8),
        _detection("Office spawning PowerShell", "high", 0.85),
    ]

    package = build_investigation_package(_event(), detections, [])

    assert package.confidence == 0.85


def test_empty_detections_default_to_informational_zero_confidence_package() -> None:
    package = build_investigation_package(_event(), [], [])

    assert package.severity == "informational"
    assert package.confidence == 0.0
    assert "no detections" in package.summary
    assert "no mapped techniques" in package.summary
