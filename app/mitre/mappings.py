from app.detections import DetectionResult
from app.mitre.models import DetectionToTechnique, Technique


DETECTION_KEY_BY_RULE_ID: dict[str, str] = {
    "TH-PS-001": "encoded_powershell",
    "TH-OFFICE-001": "office_spawns_powershell",
    "TH-CERTUTIL-001": "certutil_download",
    "TH-RUNDLL32-001": "suspicious_rundll32",
}


DETECTION_TO_TECHNIQUES: dict[str, DetectionToTechnique] = {
    "encoded_powershell": DetectionToTechnique(
        detection_key="encoded_powershell",
        techniques=(
            Technique(technique_id="T1059.001", name="PowerShell"),
            Technique(technique_id="T1027", name="Obfuscated Files or Information"),
        ),
    ),
    "office_spawns_powershell": DetectionToTechnique(
        detection_key="office_spawns_powershell",
        techniques=(
            Technique(technique_id="T1204", name="User Execution"),
            Technique(technique_id="T1059.001", name="PowerShell"),
        ),
    ),
    "certutil_download": DetectionToTechnique(
        detection_key="certutil_download",
        techniques=(
            Technique(technique_id="T1105", name="Ingress Tool Transfer"),
        ),
    ),
    "suspicious_rundll32": DetectionToTechnique(
        detection_key="suspicious_rundll32",
        techniques=(
            Technique(technique_id="T1218.011", name="Rundll32"),
        ),
    ),
}


def get_techniques_for_detection(detection: DetectionResult) -> list[Technique]:
    detection_key = DETECTION_KEY_BY_RULE_ID.get(detection.rule_id)
    if detection_key is None:
        return []

    mapping = DETECTION_TO_TECHNIQUES[detection_key]
    return list(mapping.techniques)
