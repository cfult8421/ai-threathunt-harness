import json
from types import SimpleNamespace

from scripts.run_harness import main


class FakeResponses:
    def create(self, **kwargs):
        return SimpleNamespace(
            output_text=json.dumps(
                {
                    "assessment": "Suspicious encoded PowerShell launched from Office.",
                    "likely_attack": "Office macro or document-triggered PowerShell execution.",
                    "mitre_summary": "Maps to PowerShell execution and user execution.",
                    "recommended_actions": ["Review the parent Office document"],
                    "confidence": 0.9,
                    "evidence_references": ["evidence.command_line"],
                }
            )
        )


class FakeOpenAIClient:
    def __init__(self):
        self.responses = FakeResponses()


def test_run_harness_cli_writes_report_and_prints_success(tmp_path, capsys) -> None:
    event_path = tmp_path / "event.json"
    llm_output_path = tmp_path / "llm_output.json"
    report_path = tmp_path / "report.md"

    event_path.write_text(
        json.dumps(
            {
                "EventID": 1,
                "UtcTime": "2026-06-23T04:15:30Z",
                "Computer": "workstation-01",
                "User": "ACME\\alice",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                "Hashes": "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }
        ),
        encoding="utf-8",
    )
    llm_output_path.write_text(
        json.dumps(
            {
                "assessment": "Suspicious encoded PowerShell launched from Office.",
                "likely_attack": "Office macro or document-triggered PowerShell execution.",
                "mitre_summary": "Maps to PowerShell execution and user execution.",
                "recommended_actions": ["Review the parent Office document"],
                "confidence": 0.9,
                "evidence_references": ["evidence.command_line"],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--event",
            str(event_path),
            "--llm-output",
            str(llm_output_path),
            "--out",
            str(report_path),
        ]
    )

    assert exit_code == 0
    assert report_path.exists()
    assert "Encoded PowerShell command" in report_path.read_text(encoding="utf-8")
    assert f"Report written to {report_path}" in capsys.readouterr().out


def test_run_harness_cli_supports_openai_execution_with_fake_client(tmp_path, capsys) -> None:
    event_path = tmp_path / "event.json"
    report_path = tmp_path / "report.md"
    event_path.write_text(
        json.dumps(
            {
                "EventID": 1,
                "UtcTime": "2026-06-23T04:15:30Z",
                "Computer": "workstation-01",
                "User": "ACME\\alice",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                "Hashes": "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--event",
            str(event_path),
            "--out",
            str(report_path),
            "--use-openai",
        ],
        openai_client=FakeOpenAIClient(),
    )

    report = report_path.read_text(encoding="utf-8")
    assert exit_code == 0
    assert "Encoded PowerShell command" in report
    assert "Review the parent Office document" in report
    assert "Score percent:" in report
    assert f"Report written to {report_path}" in capsys.readouterr().out


def test_run_harness_cli_requires_llm_output_without_openai(tmp_path) -> None:
    event_path = tmp_path / "event.json"
    report_path = tmp_path / "report.md"
    event_path.write_text(json.dumps({"EventID": 1}), encoding="utf-8")

    try:
        main(["--event", str(event_path), "--out", str(report_path)])
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError("Expected missing --llm-output to raise SystemExit.")
