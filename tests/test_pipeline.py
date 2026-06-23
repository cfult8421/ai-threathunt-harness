import pytest

from app.pipeline import run_harness_pipeline


def _raw_sysmon_event() -> dict:
    return {
        "EventID": 1,
        "UtcTime": "2026-06-23T04:15:30Z",
        "Computer": "workstation-01",
        "User": "ACME\\alice",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
        "Hashes": "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }


def _simulated_llm_output() -> dict:
    return {
        "assessment": "Suspicious encoded PowerShell launched from Office.",
        "likely_attack": "Office macro or document-triggered PowerShell execution.",
        "mitre_summary": "Maps to PowerShell execution and user execution.",
        "recommended_actions": ["Review the parent Office document", "Contain workstation-01"],
        "confidence": 0.9,
        "evidence_references": ["evidence.command_line", "detections[0].rule_name"],
    }


def test_pipeline_completes_successfully() -> None:
    report = run_harness_pipeline(_raw_sysmon_event(), _simulated_llm_output())

    assert report.startswith("# Investigation Report")


def test_pipeline_report_includes_expected_context() -> None:
    report = run_harness_pipeline(_raw_sysmon_event(), _simulated_llm_output())

    assert "workstation-01" in report
    assert "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" in report
    assert "Encoded PowerShell command" in report
    assert "T1059.001" in report
    assert "Review the parent Office document" in report
    assert "Score percent:" in report


def test_invalid_llm_output_raises_clear_error() -> None:
    invalid_output = _simulated_llm_output()
    del invalid_output["assessment"]

    with pytest.raises(ValueError, match="Invalid LLM output: Missing required field: assessment"):
        run_harness_pipeline(_raw_sysmon_event(), invalid_output)
