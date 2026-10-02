"""One investigation entry point shared by the dashboard and CLI."""

from datetime import datetime, timezone

from aegisflow.detection import canonical_hash, investigate
from aegisflow.models import Assessment, Bundle, Guidance, Incident
from aegisflow.playbooks import build_actions, phishing_playbook
from aegisflow.settings import Settings
from aegisflow.storage import Store
from aegisflow.tools.enrichment import enrich
from aegisflow.tools.indicators import event_hosts


def investigate_incident(
    bundle: Bundle, store: Store, settings: Settings, use_ai: bool = False, use_search: bool = False, llm=None
) -> Incident:
    input_hash = canonical_hash(bundle.model_dump(mode="json"))
    fingerprint = canonical_hash(
        {
            "input": input_hash,
            "ai": use_ai,
            "search": use_search,
            "model": settings.model if use_ai else "none",
            "policy_version": "1.0",
        }
    )
    incident_id = "AF-" + fingerprint[:20]
    cached = store.get(incident_id)
    if cached:
        return cached
    alert = next(e for e in bundle.events if e.id == bundle.alert_event_id)
    enrichment = enrich(event_hosts(alert), settings.serper_key, use_search)
    findings = investigate(bundle, enrichment)
    actions = build_actions(findings)
    assessment = Assessment(
        summary=f"{findings['severity'].title()} heuristic risk: {len(findings['accounts'])} correlated account(s).",
        rationale=findings["reasons"] or ["No strong phishing signals were found in the supplied evidence."],
        evidence_ids=[e.id for e in findings["evidence"][:30]],
        uncertainty="This is a synthetic/local heuristic, not a calibrated probability. Unknown reputation is inconclusive; logs may be incomplete.",
    )
    guidance = Guidance(
        explanation=(
            f"Review {len(actions)} proposed simulated containment actions. "
            "A human decision is required before any effect is recorded."
            if actions
            else "No containment actions meet the configured policy. Review the evidence and dismiss if appropriate."
        ),
        analyst_checks=[
            "Verify the source and completeness of the supplied logs.",
            "Confirm every target and evidence reference before approving.",
            "Distinguish synthetic demo reputation from live intelligence.",
        ],
    )
    usage = {
        "llm_calls": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "model": "none",
        "serper_requests": sum(r["source"].startswith("Serper") for r in enrichment),
    }
    mode, warning = "offline", ""
    if use_ai:
        if not settings.groq_key and llm is None:
            warning = "No Groq key configured. Deterministic investigation completed without AI."
            mode = "offline-fallback"
        else:
            from aegisflow.crew import run_crew
            from aegisflow.llm import GroqLLM

            llm = llm or GroqLLM(settings.groq_key, settings.model, settings.max_calls, settings.max_tokens)
            try:
                assessment, guidance = run_crew(
                    llm, findings["evidence"], actions, findings["severity"], findings["score"], enrichment
                )
                mode = "groq"
            except Exception:
                # Deliberately avoid displaying provider errors that might contain sensitive payloads.
                mode = "offline-fallback"
                warning = "AI unavailable, rate-limited, over budget, or returned invalid JSON. Local findings and the fixed response plan remain available. No automatic retry."
            finally:
                usage.update(llm.usage())
    book = phishing_playbook()
    incident = Incident(
        id=incident_id,
        title=bundle.title,
        input_sha256=input_hash,
        created_at=datetime.now(timezone.utc).isoformat(),
        mode=mode,
        severity=findings["severity"],
        risk_score=findings["score"],
        evidence=findings["evidence"],
        affected_accounts=findings["accounts"],
        enrichment=enrichment,
        assessment=assessment,
        guidance=guidance,
        actions=actions,
        usage=usage,
        warning=warning,
        metadata={
            "schema_version": "1.0",
            "app_version": "1.0.0",
            "playbook_id": book["id"],
            "mitre_attack": book["mitre_attack"],
            "simulation": True,
            "risk_method": "bounded transparent heuristic; not a probability",
            "input_event_count": len(bundle.events),
            "correlated_event_count": len(findings["related"]),
            "ai_advisory_only": True,
            "search_opt_in": use_search,
            "ai_evidence_view_limit": 20,
            "ai_enrichment_view_limit": 6,
        },
    )
    return store.save(incident)
