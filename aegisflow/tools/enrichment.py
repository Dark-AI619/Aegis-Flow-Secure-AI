"""Local fixture reputation plus optional Serper context (never a verdict)."""

import json
from datetime import datetime, timezone

import requests

from aegisflow.settings import ROOT
from aegisflow.tools.indicators import public_domain


def local_feed():
    return json.loads((ROOT / "samples/threat_intel.json").read_text())


def enrich(domains: list[str], key: str = "", use_search: bool = False) -> list[dict]:
    feed = local_feed()
    fixtures = {entry["domain"]: entry for entry in feed["indicators"]}
    collected = datetime.now(timezone.utc).isoformat()
    results = []
    searches = 0
    for domain in sorted(set(domains)):
        fixture = fixtures.get(domain)
        results.append(
            {
                "domain": domain,
                "source": feed["source"] if fixture else "local lookup",
                "verdict": fixture["verdict"] if fixture else "unknown",
                "detail": fixture["description"]
                if fixture
                else "No local reputation data. Unknown does not mean safe.",
                "collected_at": collected,
                "synthetic": bool(fixture),
            }
        )
        if not use_search or not key or not public_domain(domain) or searches >= 2:
            continue
        searches += 1
        try:
            response = requests.post(
                "https://google.serper.dev/search",
                headers={"X-API-KEY": key},
                json={"q": f'"{domain}" phishing security reputation', "num": 3},
                timeout=10,
            )
            response.raise_for_status()
            payload = response.json()
            snippets = [
                {
                    "title": str(row.get("title", ""))[:200],
                    "url": str(row.get("link", ""))[:500],
                    "snippet": str(row.get("snippet", ""))[:500],
                }
                for row in payload.get("organic", [])[:3]
            ]
            results.append(
                {
                    "domain": domain,
                    "source": "Serper public Google search",
                    "verdict": "unverified",
                    "collected_at": collected,
                    "results": snippets,
                    "detail": "Untrusted search context; not a malware/phishing verdict.",
                }
            )
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            results.append(
                {
                    "domain": domain,
                    "source": "Serper",
                    "verdict": "unavailable",
                    "collected_at": collected,
                    "detail": "Search unavailable; local evidence is still usable.",
                }
            )
    return results
