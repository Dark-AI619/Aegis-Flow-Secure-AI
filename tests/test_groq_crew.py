"""Real CrewAI + real Groq SDK, with only the HTTP endpoint mocked."""

import json
from dataclasses import replace

import httpx
import pytest
from groq import Groq

from aegisflow.llm import GroqLLM
from aegisflow.service import investigate_incident


def sdk_with_transport(responses, captured):
    def handle(request):
        payload = json.loads(request.content)
        captured.append(payload)
        index = len(captured) - 1
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-demo",
                "object": "chat.completion",
                "created": 1,
                "model": "llama-3.1-8b-instant",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(responses[min(index, len(responses) - 1)]),
                        },
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 80, "total_tokens": 180},
            },
        )

    return Groq(
        api_key="test-not-a-real-key", max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(handle))
    )


def valid_responses():
    return [
        {
            "summary": "Synthetic phishing campaign across three accounts.",
            "rationale": ["E001 matches a synthetic malicious domain."],
            "evidence_ids": ["E001"],
            "uncertainty": "These logs and reputation results are synthetic.",
        },
        {
            "explanation": "Review the fixed five simulated actions, then approve them as a human.",
            "analyst_checks": ["Confirm each target and its source evidence."],
        },
    ]


def test_actual_two_agent_crew_and_sdk_payload(phishing, store, settings):
    captured = []
    llm = GroqLLM("test", settings.model, client=sdk_with_transport(valid_responses(), captured))
    case = investigate_incident(phishing, store, settings, use_ai=True, llm=llm)
    assert case.mode == "groq", case.warning
    assert len(captured) == 2 == case.usage["llm_calls"]
    assert case.usage["prompt_tokens"] == 200
    assert len(case.actions) == 5 and not store.effects(case.id)
    for request in captured:
        assert request["max_tokens"] == 700
        assert request["response_format"] == {"type": "json_object"}
        assert all(set(msg) == {"role", "content"} for msg in request["messages"])
    # Cached results never reach Groq again.
    assert investigate_incident(phishing, store, settings, use_ai=True, llm=llm).id == case.id
    assert len(captured) == 2


def test_hard_budget_shared_by_both_agents(phishing, store, settings):
    captured = []
    limited = replace(settings, max_calls=1)
    llm = GroqLLM("test", settings.model, max_calls=1, client=sdk_with_transport(valid_responses(), captured))
    case = investigate_incident(phishing, store, limited, use_ai=True, llm=llm)
    assert case.mode == "offline-fallback"
    assert len(captured) == 1 == case.usage["llm_calls"]
    assert len(case.actions) == 5
    with pytest.raises(RuntimeError, match="budget"):
        llm.call("another request")


def test_unknown_ai_evidence_rejected(phishing, store, settings):
    captured = []
    bad = valid_responses()
    bad[0]["evidence_ids"] = ["E-DOES-NOT-EXIST"]
    llm = GroqLLM("test", settings.model, client=sdk_with_transport(bad, captured))
    case = investigate_incident(phishing, store, settings, use_ai=True, llm=llm)
    assert case.mode == "offline-fallback" and case.warning
    assert case.assessment.evidence_ids != ["E-DOES-NOT-EXIST"]


def test_unsupported_message_fields_are_stripped():
    captured = []
    llm = GroqLLM("test", "llama-3.1-8b-instant", client=sdk_with_transport(valid_responses(), captured))
    llm.call(
        [{"role": "user", "content": "Return JSON", "cache_breakpoint": True, "cache_control": {"type": "ephemeral"}}]
    )
    assert captured[0]["messages"][-1] == {"role": "user", "content": "Return JSON"}


def test_provider_failure_never_leaks_key(phishing, store, settings):
    class FailingClient:
        chat = None

    client = FailingClient()
    client.chat = client
    client.completions = client

    def fail(**kwargs):
        raise RuntimeError("sensitive-secret-do-not-export")

    client.create = fail
    llm = GroqLLM("test", settings.model, client=client)
    case = investigate_incident(phishing, store, settings, use_ai=True, llm=llm)
    assert case.mode == "offline-fallback" and case.usage["llm_calls"] == 1
    assert "sensitive-secret" not in case.model_dump_json()


def test_input_ceiling_blocks_request_before_spending():
    captured = []
    llm = GroqLLM("test", "llama-3.1-8b-instant", client=sdk_with_transport(valid_responses(), captured))
    with pytest.raises(ValueError, match="input size"):
        llm.call("x" * 24001)
    assert not captured and llm.calls == 0
