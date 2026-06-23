from __future__ import annotations

import json
import os
from typing import Any

from app.validation import validate_llm_output


DEFAULT_MODEL = "gpt-5.5"
API_KEY_ENV_VAR = "OPENAI_API_KEY"
MODEL_ENV_VAR = "OPENAI_MODEL"


def call_openai_model(
    prompt_package: dict[str, Any],
    *,
    model: str | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    """Call OpenAI with a prompt package and return validated structured JSON."""
    openai_client = client if client is not None else _build_openai_client()
    selected_model = model or os.environ.get(MODEL_ENV_VAR, DEFAULT_MODEL)
    expected_schema = prompt_package["expected_schema"]

    response = openai_client.responses.create(
        model=selected_model,
        input=[
            {"role": "system", "content": prompt_package["system_prompt"]},
            {"role": "user", "content": prompt_package["user_prompt"]},
        ],
        text={
            "format": {
                "type": "json_schema",
                "name": "threat_hunt_assessment",
                "schema": expected_schema,
                "strict": True,
            }
        },
    )

    raw_output = _extract_json_output(response)
    validation_result = validate_llm_output(raw_output, expected_schema)
    if not validation_result.valid or validation_result.sanitized_output is None:
        errors = "; ".join(validation_result.errors)
        raise ValueError(f"Invalid OpenAI output: {errors}")

    return validation_result.sanitized_output


def _build_openai_client() -> Any:
    api_key = os.environ.get(API_KEY_ENV_VAR)
    if not api_key:
        raise RuntimeError(f"{API_KEY_ENV_VAR} environment variable is required to call OpenAI.")

    try:
        from openai import OpenAI
    except ImportError as error:
        raise RuntimeError("The openai package is required to call OpenAI.") from error

    return OpenAI(api_key=api_key)


def _extract_json_output(response: Any) -> dict[str, Any]:
    output_text = getattr(response, "output_text", None)
    if output_text is None and isinstance(response, dict):
        output_text = response.get("output_text")

    if output_text is None:
        raise ValueError("OpenAI response did not include output_text.")

    parsed = json.loads(output_text)
    if not isinstance(parsed, dict):
        raise ValueError("OpenAI response output_text must contain a JSON object.")
    return parsed
