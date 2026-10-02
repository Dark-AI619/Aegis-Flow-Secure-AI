"""Run with: streamlit run app.py"""

from dataclasses import replace

import streamlit as st
from pydantic import ValidationError

from aegisflow.models import Bundle
from aegisflow.reporting import report_json, report_markdown
from aegisflow.service import investigate_incident
from aegisflow.settings import ROOT, Settings
from aegisflow.storage import Store, plan_digest

st.set_page_config(page_title="AegisFlow AI", page_icon="🛡️", layout="wide")
st.title("🛡️ AegisFlow AI")
st.caption("Investigate → correlate → explain → review → simulate containment")
st.info(
    "Hackathon simulation. Approval records local effects; no real emails, accounts, firewalls, or sessions are modified."
)

settings = Settings()
with st.sidebar:
    st.header("Investigation settings")
    use_ai = st.toggle("Use Groq + CrewAI", value=False)
    groq_key = st.text_input(
        "Groq API key", type="password", help="Optional when configured in .env or Streamlit secrets."
    )
    choices = ["llama-3.1-8b-instant", "llama-3.3-70b-versatile", "openai/gpt-oss-20b", "Custom model"]
    chosen = st.selectbox(
        "Groq model", choices, index=choices.index(settings.model) if settings.model in choices else 3
    )
    model = st.text_input("Exact model ID", value=settings.model) if chosen == "Custom model" else chosen
    use_search = st.toggle(
        "Public-domain search with Serper",
        value=False,
        help="Opt in: sends up to two public hostnames to Serper. No email bodies or accounts are sent. Demo/local domains are skipped.",
    )
    serper_key = st.text_input("Serper API key (optional)", type="password") if use_search else ""
    st.caption("Serper provides search context. It cannot replace Groq as the AI provider.")
    st.caption(
        f"AI cap: {settings.max_calls} requests per incident, {settings.max_tokens} output tokens/request. Cached cases do not call the model again."
    )
    st.caption("Offline mode works without any keys.")
    # Secrets are read only when present; never exported or persisted.
    try:
        secret_groq = st.secrets.get("GROQ_API_KEY", "")
        secret_serper = st.secrets.get("SERPER_API_KEY", "")
    except (FileNotFoundError, st.errors.StreamlitSecretNotFoundError):
        secret_groq = secret_serper = ""
    settings = replace(
        settings,
        groq_key=groq_key or settings.groq_key or secret_groq,
        serper_key=serper_key or settings.serper_key or secret_serper,
        model=model.strip(),
    )

store = Store(settings.db_path)
incidents = store.list()
c1, c2, c3, c4 = st.columns(4)
c1.metric("Investigated", len(incidents))
c2.metric("Awaiting review", sum(i.status == "review_required" for i in incidents))
c3.metric("Simulated containment", sum(i.status == "contained" for i in incidents))
c4.metric("Recorded AI calls", sum(i.usage.get("llm_calls", 0) for i in incidents))

with st.expander("New investigation", expanded=True):
    source = st.selectbox("Alert source", ["Phishing campaign demo", "Benign email demo", "Upload JSON", "Paste JSON"])
    raw = None
    if source.endswith("demo"):
        file = "phishing_incident.json" if source.startswith("Phishing") else "benign_incident.json"
        raw = (ROOT / "samples" / file).read_text()
        st.caption("Synthetic dataset: reserved domains, fictional users, and labeled demo intelligence.")
    elif source == "Upload JSON":
        uploaded = st.file_uploader("Security bundle", type=["json"])
        if uploaded:
            raw = uploaded.getvalue()
    else:
        raw = st.text_area("Security bundle JSON", height=200)
    if st.button("Investigate incident", type="primary"):
        try:
            if not raw:
                raise ValueError("Choose or enter an incident JSON first.")
            if len(raw.encode() if isinstance(raw, str) else raw) > 2_000_000:
                raise ValueError("Input exceeds 2 MB.")
            bundle = Bundle.model_validate_json(raw)
            if use_search and not settings.serper_key:
                st.warning("No Serper key configured; continuing with local evidence.")
            with st.spinner("Correlating evidence and preparing the response plan…"):
                incident = investigate_incident(bundle, store, settings, use_ai=use_ai, use_search=use_search)
            st.session_state["selected_incident"] = incident.id
            st.rerun()
        except ValidationError as error:
            st.error("Invalid security bundle. Use the schema in schemas/incident.schema.json.")
            st.json(
                [
                    {"field": ".".join(map(str, e["loc"])), "message": e["msg"]}
                    for e in error.errors(include_input=False)
                ]
            )
        except (ValueError, OSError) as error:
            st.error(str(error))

incidents = store.list()
if not incidents:
    st.caption("Start with the phishing demo to see the full approval workflow.")
    st.stop()

ids = [i.id for i in incidents]
selected = st.session_state.get("selected_incident", ids[0])
selected = st.selectbox(
    "Incident history",
    ids,
    index=ids.index(selected) if selected in ids else 0,
    format_func=lambda x: next(f"{i.title} · {i.status} · {i.id}" for i in incidents if i.id == x),
)
incident = store.get(selected)
st.subheader(incident.title)
s1, s2, s3, s4 = st.columns(4)
s1.metric("Severity", incident.severity.upper())
s2.metric("Heuristic risk", f"{incident.risk_score}/100")
s3.metric("Affected accounts", len(incident.affected_accounts))
s4.metric("Status", incident.status.replace("_", " "))
st.caption(f"{incident.id} · {incident.mode} · Score is a heuristic, not a probability or a live threat verdict.")
if incident.warning:
    st.warning(incident.warning)

evidence_tab, plan_tab, timeline_tab, export_tab = st.tabs(
    ["Investigation", "Response & approval", "Audit timeline", "Reports & metadata"]
)
with evidence_tab:
    st.write(incident.assessment.summary)
    for reason in incident.assessment.rationale:
        st.write("• " + reason)
    st.caption("Uncertainty: " + incident.assessment.uncertainty)
    st.write("Correlated accounts:", ", ".join(incident.affected_accounts))
    if incident.evidence:
        st.dataframe([e.model_dump() for e in incident.evidence], hide_index=True, use_container_width=True)
    else:
        st.caption("No indicator evidence was extracted from the supplied alert.")
    with st.expander("Threat enrichment and source references"):
        st.json(incident.enrichment)
with plan_tab:
    st.write(incident.guidance.explanation)
    for check in incident.guidance.analyst_checks:
        st.write("• " + check)
    if incident.actions:
        st.dataframe([a.model_dump() for a in incident.actions], hide_index=True, use_container_width=True)
    else:
        st.caption("No containment actions meet this playbook's policy.")
    if incident.status == "review_required":
        with st.form("analyst_decision_" + incident.id):
            analyst = st.text_input("Analyst name", max_chars=80)
            note = st.text_area("Decision note", max_chars=500)
            reviewed = st.checkbox("I reviewed all targets and approve the listed simulated actions.")
            approve = st.form_submit_button("Approve simulated containment", disabled=not bool(incident.actions))
            dismiss = st.form_submit_button("Dismiss after review")
        if approve or dismiss:
            try:
                if approve and not reviewed:
                    raise ValueError("Review the plan and check the approval box first.")
                store.decide(incident.id, "approve" if approve else "dismiss", analyst, note, plan_digest(incident))
                st.rerun()
            except ValueError as error:
                st.error(str(error))
    else:
        st.success("Decision recorded. Repeated execution is blocked.")
    effects = store.effects(incident.id)
    if effects:
        st.write("Recorded simulation effects")
        st.dataframe(effects, hide_index=True, use_container_width=True)
with timeline_tab:
    for entry in store.timeline(incident.id):
        st.write(f"**{entry['event']}** · {entry['timestamp']}")
        st.json(entry["details"])
with export_tab:
    st.download_button(
        "Download JSON report", report_json(incident, store), file_name=incident.id + ".json", mime="application/json"
    )
    st.download_button(
        "Download Markdown report",
        report_markdown(incident, store),
        file_name=incident.id + ".md",
        mime="text/markdown",
    )
    st.json({"metadata": incident.metadata, "usage": incident.usage, "input_sha256": incident.input_sha256})
