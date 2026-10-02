"""Run from the repository root: python -m scripts.generate_schemas"""

import json

from aegisflow.models import Bundle, Incident
from aegisflow.settings import ROOT

if __name__ == "__main__":
    folder = ROOT / "schemas"
    folder.mkdir(exist_ok=True)
    for filename, model in [("incident.schema.json", Bundle), ("report-record.schema.json", Incident)]:
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        (folder / filename).write_text(json.dumps(schema, indent=2) + "\n")
