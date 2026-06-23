from __future__ import annotations

from typing import Any

from app.detections import run_detections
from app.investigation import build_investigation_package
from app.llm import build_prompt_package
from app.mitre import Technique, get_techniques_for_detection
from app.normalization import normalize_sysmon_event_id_1
from app.reporting import generate_markdown_report
from app.scoring import score_investigation
from app.validation import validate_llm_output


def run_harness_pipeline(
    raw_sysmon_event: dict[str, Any],
    simulated_llm_output: dict[str, Any],
) -> str:
    event = normalize_sysmon_event_id_1(raw_sysmon_event)
    detections = run_detections(event)
    mitre_techniques = _map_mitre_techniques(detections)
    investigation_package = build_investigation_package(event, detections, mitre_techniques)
    prompt_package = build_prompt_package(investigation_package)
    validation_result = validate_llm_output(
        simulated_llm_output,
        prompt_package["expected_schema"],
    )

    if not validation_result.valid or validation_result.sanitized_output is None:
        errors = "; ".join(validation_result.errors)
        raise ValueError(f"Invalid LLM output: {errors}")

    score = score_investigation(investigation_package, validation_result.sanitized_output)
    return generate_markdown_report(
        investigation_package,
        validation_result.sanitized_output,
        score,
    )


def _map_mitre_techniques(detections) -> list[Technique]:
    techniques: list[Technique] = []
    seen_ids: set[str] = set()

    for detection in detections:
        for technique in get_techniques_for_detection(detection):
            if technique.technique_id not in seen_ids:
                techniques.append(technique)
                seen_ids.add(technique.technique_id)

    return techniques
