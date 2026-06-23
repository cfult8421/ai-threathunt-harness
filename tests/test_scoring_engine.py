from datetime import datetime, timezone

from app.detections import DetectionResult
from app.investigation import build_investigation_package
from app.mitre import Technique
from app.normalization import NormalizedEvent
from app.scoring import ScoreResult, score_investigation


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


def _detection() -> DetectionResult:
    return DetectionResult(
        rule_id="TH-PS-001",
        rule_name="Encoded PowerShell command",
        severity="high",
        confidence=0.9,
        description="PowerShell was launched with an encoded command argument.",
        host="workstation-01",
        user="ACME\\alice",
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
        source="sysmon",
    )


def _technique() -> Technique:
    return Technique(technique_id="T1059.001", name="PowerShell")


def _llm_output(**overrides):
    output = {
        "assessment": "Suspicious encoded PowerShell execution.",
        "likely_attack": "PowerShell execution with obfuscation.",
        "mitre_summary": "Maps to T1059.001.",
        "recommended_actions": ["Review command line", "Contain host if unauthorized"],
        "confidence": 0.9,
        "evidence_references": ["evidence.command_line"],
    }
    output.update(overrides)
    return output


def _package(*, detections=None, techniques=None):
    if detections is None:
        detections = [_detection()]
    if techniques is None:
        techniques = [_technique()]
    return build_investigation_package(_event(), detections, techniques)


def test_perfect_score() -> None:
    result = score_investigation(_package(), _llm_output())

    assert isinstance(result, ScoreResult)
    assert result.total_score == 100
    assert result.max_score == 100
    assert result.score_percent == 100.0
    assert result.components == {
        "detections": 25,
        "mitre_techniques": 20,
        "evidence_references": 20,
        "recommended_actions": 15,
        "confidence": 10,
        "likely_attack": 10,
    }
    assert result.notes == []


def test_no_detections_loses_detection_points() -> None:
    result = score_investigation(_package(detections=[]), _llm_output())

    assert result.total_score == 75
    assert result.components["detections"] == 0
    assert "No detections were present." in result.notes


def test_missing_mitre_techniques_loses_mitre_points() -> None:
    result = score_investigation(_package(techniques=[]), _llm_output())

    assert result.total_score == 80
    assert result.components["mitre_techniques"] == 0
    assert "No MITRE techniques were mapped." in result.notes


def test_empty_evidence_references_loses_evidence_points() -> None:
    result = score_investigation(_package(), _llm_output(evidence_references=[]))

    assert result.total_score == 80
    assert result.components["evidence_references"] == 0
    assert "LLM output did not include evidence references." in result.notes


def test_low_confidence_loses_confidence_points() -> None:
    result = score_investigation(_package(), _llm_output(confidence=0.49))

    assert result.total_score == 90
    assert result.components["confidence"] == 0
    assert "LLM confidence was below 0.5 or invalid." in result.notes


def test_empty_likely_attack_loses_likely_attack_points() -> None:
    result = score_investigation(_package(), _llm_output(likely_attack=" "))

    assert result.total_score == 90
    assert result.components["likely_attack"] == 0
    assert "LLM output did not include a likely attack." in result.notes
