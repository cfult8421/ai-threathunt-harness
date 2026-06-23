from datetime import timezone

import pytest

from app.normalization import NormalizedEvent, normalize_sysmon_event_id_1


def test_normalizes_sysmon_event_id_1_process_creation() -> None:
    raw_event = {
        "EventID": 1,
        "UtcTime": "2026-06-23 04:15:30.123",
        "Computer": "workstation-01",
        "User": "ACME\\alice",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass",
        "Hashes": (
            "MD5=11111111111111111111111111111111,"
            "SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
    }

    event = normalize_sysmon_event_id_1(raw_event)

    assert isinstance(event, NormalizedEvent)
    assert event.timestamp.tzinfo == timezone.utc
    assert event.host == "workstation-01"
    assert event.user == "ACME\\alice"
    assert event.process_name == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert event.parent_process == "C:\\Windows\\explorer.exe"
    assert event.command_line == "powershell.exe -NoProfile -ExecutionPolicy Bypass"
    assert event.hash_sha256 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert event.event_type == "process_creation"
    assert event.source == "sysmon"


def test_accepts_direct_sha256_field() -> None:
    raw_event = {
        "EventID": "1",
        "UtcTime": "2026-06-23T04:15:30Z",
        "Computer": "server-02",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "SHA256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }

    event = normalize_sysmon_event_id_1(raw_event)

    assert event.hash_sha256 == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert event.user is None
    assert event.parent_process is None
    assert event.command_line is None


def test_rejects_non_event_id_1() -> None:
    raw_event = {
        "EventID": 3,
        "UtcTime": "2026-06-23T04:15:30Z",
        "Computer": "workstation-01",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }

    with pytest.raises(ValueError, match="Expected Sysmon Event ID 1"):
        normalize_sysmon_event_id_1(raw_event)


def test_requires_core_fields() -> None:
    raw_event = {
        "EventID": 1,
        "UtcTime": "2026-06-23T04:15:30Z",
        "Computer": "workstation-01",
    }

    with pytest.raises(ValueError, match="Missing required field"):
        normalize_sysmon_event_id_1(raw_event)
