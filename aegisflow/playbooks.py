"""Action selection is deterministic. AI cannot add or change executable targets."""

import json

from aegisflow.models import Action
from aegisflow.settings import ROOT
from aegisflow.tools.indicators import event_hosts


def phishing_playbook() -> dict:
    return json.loads((ROOT / "config/playbooks.json").read_text())["phishing"]


def build_actions(findings: dict) -> list[Action]:
    book = phishing_playbook()
    if findings["score"] < book["minimum_score"]:
        return []
    bad = set(findings["malicious_domains"])
    actions = []
    for domain in sorted(bad):
        ids = [e.id for e in findings["evidence"] if e.kind == "domain_match" and e.indicator == domain]
        actions.append(
            Action(
                kind="block_domain",
                target=domain,
                evidence_ids=ids,
                description=f"Add {domain} to the simulated domain blocklist.",
            )
        )
    for event in findings["related"]:
        if not bad.intersection(event_hosts(event)):
            continue
        ids = [e.id for e in findings["evidence"] if e.event_id == event.id]
        if event.kind == "email":
            actions.append(
                Action(
                    kind="quarantine_email",
                    target=event.id,
                    evidence_ids=ids,
                    description=f"Quarantine simulated email {event.id} for {event.account}.",
                )
            )
        if event.kind == "signin" and event.success and event.suspicious and event.session_id:
            actions.append(
                Action(
                    kind="revoke_session",
                    target=event.session_id,
                    evidence_ids=ids,
                    description=f"Revoke simulated session {event.session_id} for {event.account}.",
                )
            )
    unique = {(action.kind, action.target): action for action in actions}
    return list(unique.values())
