from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from app.normalization import NormalizedEvent


class DetectionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_name: str
    severity: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    description: str
    host: str
    user: str | None = None
    process_name: str
    parent_process: str | None = None
    command_line: str | None = None
    source: str


DetectionRule = Callable[[NormalizedEvent], DetectionResult | None]


def detect_encoded_powershell_command(event: NormalizedEvent) -> DetectionResult | None:
    command_line = _lower(event.command_line)
    process_name = _basename(event.process_name)
    if "powershell" not in process_name:
        return None

    encoded_flags = ("-enc", "-encodedcommand", "/enc", "/encodedcommand")
    if not any(flag in command_line for flag in encoded_flags):
        return None

    return _result(
        event,
        rule_id="TH-PS-001",
        rule_name="Encoded PowerShell command",
        severity="high",
        confidence=0.9,
        description="PowerShell was launched with an encoded command argument.",
    )


def detect_office_spawning_powershell(event: NormalizedEvent) -> DetectionResult | None:
    process_name = _basename(event.process_name)
    parent_process = _basename(event.parent_process)
    office_processes = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}

    if "powershell" not in process_name or parent_process not in office_processes:
        return None

    return _result(
        event,
        rule_id="TH-OFFICE-001",
        rule_name="Office spawning PowerShell",
        severity="high",
        confidence=0.85,
        description="A Microsoft Office process spawned PowerShell.",
    )


def detect_certutil_download_behavior(event: NormalizedEvent) -> DetectionResult | None:
    process_name = _basename(event.process_name)
    command_line = _lower(event.command_line)
    if process_name != "certutil.exe":
        return None

    has_url = "http://" in command_line or "https://" in command_line
    download_flags = ("-urlcache", "-split", "-f", "-verifyctl")
    if not has_url or not any(flag in command_line for flag in download_flags):
        return None

    return _result(
        event,
        rule_id="TH-CERTUTIL-001",
        rule_name="Certutil download behavior",
        severity="medium",
        confidence=0.8,
        description="Certutil was used with URL/download-style command-line arguments.",
    )


def detect_rundll32_suspicious_execution(event: NormalizedEvent) -> DetectionResult | None:
    process_name = _basename(event.process_name)
    command_line = _lower(event.command_line)
    if process_name != "rundll32.exe":
        return None

    suspicious_markers = (
        "javascript:",
        "http://",
        "https://",
        "shell32.dll,shellexec_rundll",
        "mshtml,runhtmlapplication",
        "url.dll,fileprotocolhandler",
        "appdata",
        "\\temp\\",
    )
    if not any(marker in command_line for marker in suspicious_markers):
        return None

    return _result(
        event,
        rule_id="TH-RUNDLL32-001",
        rule_name="Rundll32 suspicious execution",
        severity="medium",
        confidence=0.75,
        description="Rundll32 was launched with suspicious script, URL, or user-writable path indicators.",
    )


RULES: tuple[DetectionRule, ...] = (
    detect_encoded_powershell_command,
    detect_office_spawning_powershell,
    detect_certutil_download_behavior,
    detect_rundll32_suspicious_execution,
)


def _result(
    event: NormalizedEvent,
    *,
    rule_id: str,
    rule_name: str,
    severity: str,
    confidence: float,
    description: str,
) -> DetectionResult:
    return DetectionResult(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        confidence=confidence,
        description=description,
        host=event.host,
        user=event.user,
        process_name=event.process_name,
        parent_process=event.parent_process,
        command_line=event.command_line,
        source=event.source,
    )


def _lower(value: str | None) -> str:
    return value.lower() if value else ""


def _basename(value: str | None) -> str:
    if not value:
        return ""
    normalized = value.replace("/", "\\")
    return normalized.rsplit("\\", 1)[-1].lower()
