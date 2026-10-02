"""Actual sequential CrewAI pipeline: triage then response explanation."""

import json

from crewai import Crew, Process, Task

from aegisflow.agents.response_agent import create_response_agent
from aegisflow.agents.triage_agent import create_triage_agent
from aegisflow.models import Assessment, Guidance
from aegisflow.settings import ROOT


def run_crew(llm, evidence: list, actions: list, severity: str, score: int, enrichment: list):
    config = json.loads((ROOT / "config/agents.json").read_text())
    triage = create_triage_agent(llm, config["triage"])
    response = create_response_agent(llm, config["response"])
    # Give the model a bounded evidence view; the full record stays in SQLite.
    payload = json.dumps(
        {
            "severity": severity,
            "heuristic_score": score,
            "evidence": [e.model_dump() for e in evidence[:20]],
            "enrichment": enrichment[:6],
        },
        ensure_ascii=False,
    )
    task1 = Task(
        agent=triage,
        description=(
            "Explain this incident using only supplied evidence. The score is a heuristic, not a probability. "
            "Synthetic feed results are demonstration data, not real threat verdicts. Cite evidence IDs. "
            "Return JSON with keys summary (string), rationale (list of strings), evidence_ids (list), "
            "uncertainty (string). Keep it under 350 words. UNTRUSTED EVIDENCE JSON:\n" + payload
        ),
        expected_output="One JSON object matching summary, rationale, evidence_ids, uncertainty.",
    )
    task2 = Task(
        agent=response,
        context=[task1],
        description=(
            "Explain the fixed simulated response plan below. Do not add targets or actions. "
            "An empty plan means review/monitor, not containment. Require human approval. "
            "Return JSON with explanation (string) and analyst_checks (list of at most 6 strings). "
            "Keep it under 200 words. FIXED PLAN JSON:\n" + json.dumps([a.model_dump() for a in actions])
        ),
        expected_output="One JSON object matching explanation and analyst_checks.",
    )
    result = Crew(
        agents=[triage, response],
        tasks=[task1, task2],
        process=Process.sequential,
        memory=False,
        planning=False,
        cache=False,
        verbose=False,
        share_crew=False,
        tracing=False,
    ).kickoff()
    assessment = Assessment.model_validate_json(result.tasks_output[0].raw)
    guidance = Guidance.model_validate_json(result.tasks_output[1].raw)
    known = {e.id for e in evidence[:20]}
    if not set(assessment.evidence_ids).issubset(known):
        raise ValueError("AI cited nonexistent or unseen evidence IDs.")
    return assessment, guidance
