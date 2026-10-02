# Two advisory agents

- `triage_agent.py`: explain the supplied evidence and uncertainty, with evidence references.
- `response_agent.py`: explain the already selected simulated action plan and analyst checks.

Agent roles, goals, and backstories are read from `config/agents.json`; tasks are defined in `aegisflow/crew.py`. Both agents share the same `GroqLLM` object and request budget. They have no tools or execution privileges. Neither can modify severity, the deterministic score, action targets, or analyst approval.

The live-provider path uses real CrewAI orchestration, not an imitation multi-agent loop. Offline mode uses explicitly labeled local explanations. See `tests/test_groq_crew.py` for the real framework/SDK integration test with a mocked provider endpoint.
