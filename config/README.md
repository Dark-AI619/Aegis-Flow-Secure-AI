# JSON configuration

`agents.json` supplies role, goal, and backstory for the two separately defined CrewAI agents.

`playbooks.json` supplies the phishing playbook ID, 60-point containment threshold, allowed action kinds, approval requirement, simulation marker, and static MITRE ATT&CK mapping.

This version deliberately implements one phishing playbook. Changing the descriptive `approval_required` or `execution_mode` fields does not turn off hard-coded approval or enable live actions. Changing allowed action names must remain compatible with the strict `Action` JSON contract. Keep policy/schema changes versioned and re-run the tests.
