from app.llm.prompt_builder import EXPECTED_SCHEMA
from app.validation import ValidationResult, validate_llm_output


def _valid_output() -> dict:
    return {
        "assessment": "Suspicious encoded PowerShell execution.",
        "likely_attack": "Script execution using obfuscated PowerShell.",
        "mitre_summary": "Maps to T1059.001 and T1027.",
        "recommended_actions": ["Review command line", "Isolate host if unauthorized"],
        "confidence": 0.9,
        "evidence_references": ["evidence.command_line", "detections[0].rule_name"],
    }


def test_valid_output_returns_sanitized_output() -> None:
    result = validate_llm_output(_valid_output(), EXPECTED_SCHEMA)

    assert isinstance(result, ValidationResult)
    assert result.valid is True
    assert result.errors == []
    assert result.sanitized_output == _valid_output()


def test_missing_required_field_is_invalid() -> None:
    output = _valid_output()
    del output["assessment"]

    result = validate_llm_output(output, EXPECTED_SCHEMA)

    assert result.valid is False
    assert "Missing required field: assessment" in result.errors
    assert result.sanitized_output is None


def test_invalid_confidence_is_invalid() -> None:
    output = _valid_output()
    output["confidence"] = 1.2

    result = validate_llm_output(output, EXPECTED_SCHEMA)

    assert result.valid is False
    assert "confidence must be between 0.0 and 1.0" in result.errors


def test_wrong_recommended_actions_list_type_is_invalid() -> None:
    output = _valid_output()
    output["recommended_actions"] = "Review command line"

    result = validate_llm_output(output, EXPECTED_SCHEMA)

    assert result.valid is False
    assert "recommended_actions must be a list" in result.errors


def test_wrong_evidence_references_list_type_is_invalid() -> None:
    output = _valid_output()
    output["evidence_references"] = "evidence.command_line"

    result = validate_llm_output(output, EXPECTED_SCHEMA)

    assert result.valid is False
    assert "evidence_references must be a list" in result.errors


def test_unexpected_extra_field_is_invalid() -> None:
    output = _valid_output()
    output["extra_field"] = "not allowed"

    result = validate_llm_output(output, EXPECTED_SCHEMA)

    assert result.valid is False
    assert "Unexpected field: extra_field" in result.errors
    assert result.sanitized_output is None
