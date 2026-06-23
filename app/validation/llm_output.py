from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class ValidationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    valid: bool
    errors: list[str]
    sanitized_output: dict[str, Any] | None = None


def validate_llm_output(raw_output: dict[str, Any], expected_schema: dict[str, Any]) -> ValidationResult:
    errors: list[str] = []
    required_fields = expected_schema.get("required", [])
    allowed_fields = set(expected_schema.get("properties", {}))

    for field in required_fields:
        if field not in raw_output:
            errors.append(f"Missing required field: {field}")

    if expected_schema.get("additionalProperties") is False:
        for field in raw_output:
            if field not in allowed_fields:
                errors.append(f"Unexpected field: {field}")

    confidence = raw_output.get("confidence")
    if "confidence" in raw_output and not _valid_confidence(confidence):
        errors.append("confidence must be between 0.0 and 1.0")

    if "recommended_actions" in raw_output and not isinstance(raw_output["recommended_actions"], list):
        errors.append("recommended_actions must be a list")

    if "evidence_references" in raw_output and not isinstance(raw_output["evidence_references"], list):
        errors.append("evidence_references must be a list")

    if errors:
        return ValidationResult(valid=False, errors=errors, sanitized_output=None)

    return ValidationResult(
        valid=True,
        errors=[],
        sanitized_output={field: raw_output[field] for field in required_fields},
    )


def _valid_confidence(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return 0.0 <= float(value) <= 1.0
