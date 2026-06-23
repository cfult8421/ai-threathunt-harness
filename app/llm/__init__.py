"""LLM prompt helpers and optional OpenAI integration.

The default harness pipeline still uses simulated LLM output.
"""

from app.llm.client import call_openai_model
from app.llm.prompt_builder import build_prompt_package

__all__ = ["build_prompt_package", "call_openai_model"]
