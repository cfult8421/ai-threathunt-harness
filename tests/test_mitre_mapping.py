from app.detections import DetectionResult
from app.mitre import DetectionToTechnique, Technique, get_techniques_for_detection
from app.mitre.mappings import DETECTION_TO_TECHNIQUES


def _detection(rule_id: str) -> DetectionResult:
    return DetectionResult(
        rule_id=rule_id,
        rule_name="Test detection",
        severity="medium",
        description="Test detection result.",
        host="workstation-01",
        user="ACME\\alice",
        process_name="C:\\Windows\\System32\\cmd.exe",
        parent_process="C:\\Windows\\explorer.exe",
        command_line="cmd.exe",
        source="sysmon",
    )


def test_defines_detection_to_technique_mapping_model() -> None:
    mapping = DETECTION_TO_TECHNIQUES["encoded_powershell"]

    assert isinstance(mapping, DetectionToTechnique)
    assert mapping.detection_key == "encoded_powershell"
    assert all(isinstance(technique, Technique) for technique in mapping.techniques)


def test_maps_encoded_powershell_to_attack_techniques() -> None:
    techniques = get_techniques_for_detection(_detection("TH-PS-001"))

    assert [(technique.technique_id, technique.name) for technique in techniques] == [
        ("T1059.001", "PowerShell"),
        ("T1027", "Obfuscated Files or Information"),
    ]


def test_maps_office_spawns_powershell_to_attack_techniques() -> None:
    techniques = get_techniques_for_detection(_detection("TH-OFFICE-001"))

    assert [(technique.technique_id, technique.name) for technique in techniques] == [
        ("T1204", "User Execution"),
        ("T1059.001", "PowerShell"),
    ]


def test_maps_certutil_download_to_attack_technique() -> None:
    techniques = get_techniques_for_detection(_detection("TH-CERTUTIL-001"))

    assert [(technique.technique_id, technique.name) for technique in techniques] == [
        ("T1105", "Ingress Tool Transfer"),
    ]


def test_maps_suspicious_rundll32_to_attack_technique() -> None:
    techniques = get_techniques_for_detection(_detection("TH-RUNDLL32-001"))

    assert [(technique.technique_id, technique.name) for technique in techniques] == [
        ("T1218.011", "Rundll32"),
    ]


def test_unknown_detection_returns_no_techniques() -> None:
    assert get_techniques_for_detection(_detection("TH-UNKNOWN-001")) == []
