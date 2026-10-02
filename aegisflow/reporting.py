"""Export the canonical record and full analyst/action timeline."""

import json

from aegisflow.models import Incident
from aegisflow.storage import Store


def report_json(incident: Incident, store: Store) -> str:
    return json.dumps(
        {
            "incident": incident.model_dump(mode="json"),
            "timeline": store.timeline(incident.id),
            "simulated_effects": store.effects(incident.id),
        },
        indent=2,
        ensure_ascii=False,
    )


def report_markdown(incident: Incident, store: Store) -> str:
    lines = [
        f"# AegisFlow — {incident.id}",
        "",
        "**SIMULATION — no real systems were modified.**",
        "",
        f"Status: {incident.status} | Severity: {incident.severity} | Heuristic score: {incident.risk_score}/100",
        f"Mode: {incident.mode} | Created: {incident.created_at}",
        "",
        "## Assessment",
        incident.assessment.summary,
        incident.assessment.uncertainty,
        "",
        "## Evidence",
    ]
    lines += [f"- {e.id} · {e.event_id} · {e.source} · {e.observed_at}: {e.detail}" for e in incident.evidence]
    lines += ["", "## Fixed response plan"]
    lines += [f"- {a.kind}: {a.target} (evidence: {', '.join(a.evidence_ids)})" for a in incident.actions] or [
        "- No containment proposed."
    ]
    lines += ["", "## Analyst guidance", incident.guidance.explanation]
    lines += [f"- {check}" for check in incident.guidance.analyst_checks]
    lines += ["", "## Audit timeline"]
    lines += [
        f"- {row['timestamp']} · {row['event']} · {json.dumps(row['details'], ensure_ascii=False)}"
        for row in store.timeline(incident.id)
    ]
    lines += [
        "",
        "## Metadata",
        "```json",
        json.dumps(incident.metadata, indent=2),
        "```",
        "",
        "## API usage",
        "```json",
        json.dumps(incident.usage, indent=2),
        "```",
    ]
    if incident.warning:
        lines += ["", "## Provider notice", incident.warning]
    return "\n".join(lines) + "\n"
