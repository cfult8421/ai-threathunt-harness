import json
from datetime import datetime, timezone

from app.detections import DetectionResult
from app.investigation import build_investigation_package
from app.llm import build_prompt_package
from app.mitre import Technique
from app.normalization import NormalizedEvent


def _investigation_package():
    event = NormalizedEvent(
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
    detections = [
        DetectionResult(
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
    ]
    techniques = [
        Technique(technique_id="T1059.001", name="PowerShell"),
        Technique(technique_id="T1027", name="Obfuscated Files or Information"),
    ]
    return build_investigation_package(event, detections, techniques)


def test_build_prompt_package_has_system_prompt_user_prompt_and_expected_schema() -> None:
    prompt_package = build_prompt_package(_investigation_package())

    assert set(prompt_package) == {"system_prompt", "user_prompt", "expected_schema"}
    assert "cybersecurity analyst" in prompt_package["system_prompt"]
    assert "external API" not in prompt_package


def test_user_prompt_includes_investigation_package_as_structured_json() -> None:
    prompt_package = build_prompt_package(_investigation_package())
    json_text = prompt_package["user_prompt"].split("structured JSON:\n", 1)[1]

    package_json = json.loads(json_text)

    assert package_json["event"]["host"] == "workstation-01"
    assert package_json["detections"][0]["rule_name"] == "Encoded PowerShell command"
    assert package_json["mitre_techniques"][0]["technique_id"] == "T1059.001"


def test_prompt_includes_real_evidence_and_does_not_omit_command_line() -> None:
    prompt_package = build_prompt_package(_investigation_package())
    user_prompt = prompt_package["user_prompt"]

    assert "workstation-01" in user_prompt
    assert "ACME\\\\alice" in user_prompt
    assert "powershell.exe -EncodedCommand SQBFAFgA" in user_prompt
    assert '"command_line": "powershell.exe -EncodedCommand SQBFAFgA"' in user_prompt


def test_expected_schema_requires_all_analysis_fields() -> None:
    expected_schema = build_prompt_package(_investigation_package())["expected_schema"]

    assert expected_schema["required"] == [
        "assessment",
        "likely_attack",
        "mitre_summary",
        "recommended_actions",
        "confidence",
        "evidence_references",
    ]
    assert expected_schema["additionalProperties"] is False
