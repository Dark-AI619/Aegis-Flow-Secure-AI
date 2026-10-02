# Team ownership: 4–6 members

The supplied hackathon constraint is a team of 4–6 people. No additional judging or submission rules are available yet.

| Member | Ownership | Files / deliverable |
|---|---|---|
| Hannan — architecture and integration | Connect interfaces; bounded AI and CrewAI behavior | `crew.py`, `llm.py`, `service.py`, agent JSON |
| Security and evidence lead | Synthetic scenarios, indicator extraction, detection and source metadata | `samples/`, `tools/indicators.py`, `detection.py`, schemas |
| Backend and response lead | Policy, state, analyst decisions, audit and idempotent effects | `playbooks.py`, `storage.py`, playbook JSON |
| Dashboard and demo lead | User flow, evidence table, approval, exports and presentation | `app.py`, `reporting.py`, `docs/DEMO.md` |
| Optional fifth member | Search enrichment, uncertainty, threat-source evaluation | `tools/enrichment.py`, enrichment tests |
| Optional sixth member | Integration testing, rehearsal, documentation and submission | `tests/`, CI, README, final demo |

For four members, distribute enrichment to the evidence lead and testing/documentation across each owner. Every member should explain their module and its boundary during judging. The separate agents are software components, not a requirement to create one agent per teammate.

Agree on the JSON contracts first. Keep the fixed action plan outside model output. Use the phishing and benign samples as shared acceptance cases so each contribution fits the same end-to-end workflow.
