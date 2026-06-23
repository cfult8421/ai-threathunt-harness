from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.normalization.models import NormalizedEvent


SYSMON_PROCESS_CREATE_EVENT_ID = 1
SYSMON_PROCESS_CREATE_EVENT_TYPE = "process_creation"
SYSMON_SOURCE = "sysmon"


def normalize_sysmon_event_id_1(raw_event: dict[str, Any]) -> NormalizedEvent:
    """Normalize a raw Sysmon Event ID 1 process creation event."""
    event_id = _first_present(raw_event, "EventID", "EventId", "event_id")
    if _coerce_event_id(event_id) != SYSMON_PROCESS_CREATE_EVENT_ID:
        raise ValueError("Expected Sysmon Event ID 1 process creation event.")

    timestamp = _parse_timestamp(
        _first_present(raw_event, "UtcTime", "TimeCreated", "timestamp", "Timestamp")
    )

    return NormalizedEvent(
        timestamp=timestamp,
        host=_required_str(raw_event, "Computer", "host", "Hostname"),
        user=_optional_str(raw_event, "User", "user"),
        process_name=_required_str(raw_event, "Image", "process_name", "ProcessName"),
        parent_process=_optional_str(raw_event, "ParentImage", "parent_process"),
        command_line=_optional_str(raw_event, "CommandLine", "command_line"),
        hash_sha256=_extract_sha256(_first_present(raw_event, "Hashes", "hashes", "SHA256", "hash_sha256")),
        event_type=SYSMON_PROCESS_CREATE_EVENT_TYPE,
        source=SYSMON_SOURCE,
    )


def _first_present(raw_event: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw_event:
            return raw_event[key]
    return None


def _required_str(raw_event: dict[str, Any], *keys: str) -> str:
    value = _first_present(raw_event, *keys)
    if value is None or str(value).strip() == "":
        joined_keys = ", ".join(keys)
        raise ValueError(f"Missing required field: {joined_keys}")
    return str(value)


def _optional_str(raw_event: dict[str, Any], *keys: str) -> str | None:
    value = _first_present(raw_event, *keys)
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _coerce_event_id(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_timestamp(value: Any) -> datetime:
    if value is None:
        raise ValueError("Missing required field: timestamp")

    if isinstance(value, datetime):
        return value

    text = str(value).strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)

    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _extract_sha256(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    for part in text.split(","):
        key_value = part.strip().split("=", 1)
        if len(key_value) == 2 and key_value[0].strip().upper() == "SHA256":
            sha256 = key_value[1].strip()
            return sha256 or None

    if len(text) == 64 and all(character in "0123456789abcdefABCDEF" for character in text):
        return text

    return None
