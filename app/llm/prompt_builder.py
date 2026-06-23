from __future__ import annotations

import json
from typing import Any

from app.investigation import InvestigationPackage


EXPECTED_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "assessment",
        "likely_attack",
        "mitre_summary",
        "recommended_actions",
        "confidence",
        "evidence_references",
    ],
    "properties": {
        "assessment": {"type": "string"},
        "likely_attack": {"type": "string"},
        "mitre_summary": {"type": "string"},
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
        },
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
        },
        "evidence_references": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "additionalProperties": False,
}


SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Review the provided investigation package, "
    "ground your response only in the supplied evidence, and return the requested JSON schema."
)


def build_prompt_package(package: InvestigationPackage) -> dict[str, Any]:
    package_json = json.dumps(package.model_dump(mode="json"), indent=2, sort_keys=True)
    return {
        "system_prompt": SYSTEM_PROMPT,
        "user_prompt": f"Analyze this investigation package as structured JSON:\n{package_json}",
        "expected_schema": EXPECTED_SCHEMA,
    }
