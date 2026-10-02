"""Agent 2: explain the preselected playbook, without execution privileges."""

from crewai import Agent


def create_response_agent(llm, config: dict) -> Agent:
    return Agent(
        **config,
        llm=llm,
        max_iter=1,
        max_retry_limit=0,
        allow_delegation=False,
        memory=False,
        verbose=False,
        allow_code_execution=False,
        respect_context_window=False,
        tools=[],
    )
