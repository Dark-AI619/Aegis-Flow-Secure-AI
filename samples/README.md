# Synthetic inputs

`phishing_incident.json` has three phishing messages, one click, one suspicious successful session, and one unrelated email. Expected outcome: three affected accounts and five proposed simulation actions.

`benign_incident.json` has a normal authenticated meeting email. Expected outcome: low risk, no containment.

`threat_intel.json` is a **synthetic local fixture**, not a public intelligence source. Domains use reserved `.test` and `.example` names. The reserved-domain filter prevents sending them to Serper. Users, event timestamps, sessions, and verdicts are fictional.

The `source`, event ID, and timestamp fields feed the generated evidence metadata. Edit and upload your own authorized normalized JSON using `schemas/incident.schema.json`; API keys are not input fields.
