"""Offline-friendly CLI for rehearsals and automation."""

import argparse
from pathlib import Path

from aegisflow.models import Bundle
from aegisflow.reporting import report_json, report_markdown
from aegisflow.service import investigate_incident
from aegisflow.settings import Settings
from aegisflow.storage import Store, plan_digest


def main():
    parser = argparse.ArgumentParser(description="AegisFlow simulated incident investigation")
    parser.add_argument("input", type=Path, help="Security bundle JSON file")
    parser.add_argument("--ai", action="store_true", help="Use the two Groq-powered CrewAI agents")
    parser.add_argument("--search", action="store_true", help="Opt in to Serper public-domain search")
    parser.add_argument("--approve", action="store_true", help="Explicitly approve ALL proposed SIMULATED actions")
    parser.add_argument("--analyst", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--output", type=Path, default=Path("reports"))
    args = parser.parse_args()
    try:
        if args.input.stat().st_size > 2_000_000:
            raise ValueError("Input exceeds the 2 MB limit.")
        bundle = Bundle.model_validate_json(args.input.read_text())
        settings = Settings()
        store = Store(settings.db_path)
        incident = investigate_incident(bundle, store, settings, args.ai, args.search)
        if args.approve:
            incident = store.decide(incident.id, "approve", args.analyst, args.note, plan_digest(incident))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / f"{incident.id}.json").write_text(report_json(incident, store))
        (args.output / f"{incident.id}.md").write_text(report_markdown(incident, store))
        print(
            f"{incident.id}: {incident.severity}, {incident.status}, {incident.mode}, {len(incident.actions)} proposed actions."
        )
        print(f"Reports saved in {args.output.resolve()}")
        if incident.warning:
            print(incident.warning)
    except (ValueError, OSError) as error:
        parser.exit(2, f"Input/operation error: {error}\n")


if __name__ == "__main__":
    main()
