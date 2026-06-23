import json
from types import SimpleNamespace

import pytest

from app.llm.client import call_openai_model
from app.llm.prompt_builder import EXPECTED_SCHEMA


class FakeResponses:
    def __init__(self, output: dict):
        self.output = output
        self.request = None

    def create(self, **kwargs):
        self.request = kwargs
        return SimpleNamespace(output_text=json.dumps(self.output))


class FakeOpenAIClient:
    def __init__(self, output: dict):
        self.responses = FakeResponses(output)


def _prompt_package() -> dict:
    return {
        "system_prompt": "You are a cybersecurity analyst.",
        "user_prompt": "Analyze this investigation package.",
        "expected_schema": EXPECTED_SCHEMA,
    }


def _valid_output() -> dict:
    return {
        "assessment": "Suspicious encoded PowerShell execution.",
        "likely_attack": "PowerShell execution with obfuscation.",
        "mitre_summary": "Maps to T1059.001.",
        "recommended_actions": ["Review command line"],
        "confidence": 0.9,
        "evidence_references": ["evidence.command_line"],
    }


def test_call_openai_model_returns_validated_structured_output() -> None:
    fake_client = FakeOpenAIClient(_valid_output())

    output = call_openai_model(_prompt_package(), model="test-model", client=fake_client)

    assert output == _valid_output()
    assert fake_client.responses.request["model"] == "test-model"
    assert fake_client.responses.request["text"]["format"]["type"] == "json_schema"
    assert fake_client.responses.request["text"]["format"]["schema"] == EXPECTED_SCHEMA


def test_call_openai_model_rejects_invalid_structured_output() -> None:
    invalid_output = _valid_output()
    del invalid_output["assessment"]
    fake_client = FakeOpenAIClient(invalid_output)

    with pytest.raises(ValueError, match="Invalid OpenAI output: Missing required field: assessment"):
        call_openai_model(_prompt_package(), model="test-model", client=fake_client)


def test_call_openai_model_requires_api_key_without_injected_client(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY environment variable is required"):
        call_openai_model(_prompt_package(), model="test-model")
