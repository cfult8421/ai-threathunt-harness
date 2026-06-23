from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from app.detections import run_detections
from app.investigation import build_investigation_package
from app.llm import build_prompt_package, call_openai_model
from app.mitre import Technique, get_techniques_for_detection
from app.normalization import normalize_sysmon_event_id_1
from app.pipeline import run_harness_pipeline
from app.reporting import generate_markdown_report
from app.scoring import score_investigation


def main(argv: list[str] | None = None, *, openai_client: Any | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local AI threat hunt harness.")
    parser.add_argument("--event", required=True, help="Path to raw Sysmon Event ID 1 JSON file.")
    parser.add_argument("--llm-output", help="Path to simulated LLM output JSON file.")
    parser.add_argument("--out", required=True, help="Path to write the Markdown report.")
    parser.add_argument("--use-openai", action="store_true", help="Call OpenAI instead of using simulated output.")
    args = parser.parse_args(argv)

    event_path = Path(args.event)
    report_path = Path(args.out)

    raw_event = _read_json_object(event_path)
    if args.use_openai:
        report = _run_openai_pipeline(raw_event, openai_client=openai_client)
    else:
        if args.llm_output is None:
            parser.error("--llm-output is required unless --use-openai is set.")
        simulated_llm_output = _read_json_object(Path(args.llm_output))
        report = run_harness_pipeline(raw_event, simulated_llm_output)

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    print(f"Report written to {report_path}")
    return 0


def _read_json_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


def _run_openai_pipeline(raw_event: dict[str, Any], *, openai_client: Any | None = None) -> str:
    event = normalize_sysmon_event_id_1(raw_event)
    detections = run_detections(event)
    mitre_techniques = _map_mitre_techniques(detections)
    investigation_package = build_investigation_package(event, detections, mitre_techniques)
    prompt_package = build_prompt_package(investigation_package)
    validated_openai_output = call_openai_model(prompt_package, client=openai_client)
    score = score_investigation(investigation_package, validated_openai_output)
    return generate_markdown_report(investigation_package, validated_openai_output, score)


def _map_mitre_techniques(detections) -> list[Technique]:
    techniques: list[Technique] = []
    seen_ids: set[str] = set()

    for detection in detections:
        for technique in get_techniques_for_detection(detection):
            if technique.technique_id not in seen_ids:
                techniques.append(technique)
                seen_ids.add(technique.technique_id)

    return techniques


if __name__ == "__main__":
    raise SystemExit(main())
