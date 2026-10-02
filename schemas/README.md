# JSON schemas

- `incident.schema.json`: uploaded alert/log bundle.
- `report-record.schema.json`: persisted incident record inside the exported report envelope.

Both are generated from `aegisflow/models.py` by `python -m scripts.generate_schemas`. Semantic checks such as unique event IDs, existing alert references, timezone-aware timestamps, and successful-sign-in session requirements are also enforced by Python validators; JSON Schema alone does not express all of these relationships.
