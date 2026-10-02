"""Transparent heuristic detection and exact-host correlation."""

import hashlib
import json

from aegisflow.models import Bundle, Evidence
from aegisflow.tools.indicators import event_hosts


def canonical_hash(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def investigate(bundle: Bundle, enrichment: list[dict]) -> dict:
    alert = next(event for event in bundle.events if event.id == bundle.alert_event_id)
    seed_hosts = set(event_hosts(alert))
    related = [event for event in bundle.events if event.id == alert.id or seed_hosts.intersection(event_hosts(event))]
    malicious = {row["domain"] for row in enrichment if row.get("verdict") == "malicious"}
    evidence = []

    def add(event, indicator, kind, detail):
        evidence.append(
            Evidence(
                id=f"E{len(evidence) + 1:03}",
                event_id=event.id,
                indicator=indicator,
                kind=kind,
                detail=detail,
                source=event.source,
                observed_at=event.timestamp.isoformat(),
                event_sha256=canonical_hash(event.model_dump(mode="json")),
            )
        )

    for event in related:
        for domain in event_hosts(event):
            if domain in seed_hosts:
                detail = f"Exact host match in {event.kind}: {domain}."
                if domain in malicious:
                    detail += " Marked malicious by the SYNTHETIC demo feed."
                add(event, domain, "domain_match", detail)
        if event.kind == "email" and (event.spf == "fail" or event.dkim == "fail"):
            add(
                event,
                event.account,
                "authentication_failure",
                f"SPF={event.spf}, DKIM={event.dkim}; authentication failures alone do not prove phishing.",
            )
        if event.kind == "email" and any(
            term in (event.subject + " " + event.body).lower()
            for term in ("verify your", "password", "urgent", "account suspended")
        ):
            add(
                event,
                event.account,
                "credential_lure",
                "Message contains credential-request or urgency language; a heuristic signal.",
            )
        if event.kind == "signin" and event.suspicious and event.success:
            add(
                event,
                event.session_id,
                "suspicious_session",
                "Supplied log marks this successful session suspicious; correlated by exact host.",
            )
    accounts = sorted({event.account for event in related})
    kinds = {item.kind for item in evidence}
    reasons = []
    score = 0
    signals = [
        (bool(seed_hosts & malicious), 60, "Alert host appears in synthetic malicious feed"),
        ("authentication_failure" in kinds, 15, "Email authentication failure"),
        ("credential_lure" in kinds, 10, "Urgency or credential language"),
        (len(accounts) > 1 and bool(seed_hosts), 10, "Same host observed across multiple accounts"),
        ("suspicious_session" in kinds, 15, "Correlated suspicious successful session"),
    ]
    for active, weight, reason in signals:
        if active:
            score += weight
            reasons.append(f"+{weight}: {reason}")
    score = min(score, 100)
    return {
        "score": score,
        "severity": "high" if score >= 60 else "medium" if score >= 20 else "low",
        "evidence": evidence,
        "accounts": accounts,
        "related": related,
        "malicious_domains": sorted(seed_hosts & malicious),
        "reasons": reasons,
    }
