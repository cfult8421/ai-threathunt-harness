# Local AI Threat Hunt Harness

A local-first Python harness for threat hunting experiments. The project is scaffolded for ingestion, normalization, detections, retrieval, LLM integration, validation, scoring, and reporting.

Only the first implemented module is included for now: a Sysmon Event ID 1 process creation normalizer.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Tests

```powershell
pytest
```

## Current Scope

- Normalizes raw Sysmon Event ID 1 JSON process creation events.
- Returns a Pydantic `NormalizedEvent` model.
- No LLM functionality is implemented yet.
