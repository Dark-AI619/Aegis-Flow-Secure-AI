"""Strict JSON input and output contracts for the entire application."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Text = Annotated[str, Field(max_length=500)]
Identifier = Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9_.@:+-]+$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Event(StrictModel):
    id: Identifier
    kind: Literal["email", "url_click", "signin"]
    timestamp: datetime
    source: Text = "uploaded-json"
    account: Identifier
    sender: Text = ""
    subject: Text = ""
    body: Annotated[str, Field(max_length=4000)] = ""
    url: Annotated[str, Field(max_length=2000)] = ""
    spf: Literal["pass", "fail", "unknown"] = "unknown"
    dkim: Literal["pass", "fail", "unknown"] = "unknown"
    session_id: Identifier | None = None
    suspicious: bool = False
    success: bool = False

    @model_validator(mode="after")
    def valid_event(self):
        if self.timestamp.tzinfo is None:
            raise ValueError("Event timestamps must include a timezone.")
        if self.kind == "signin" and self.success and not self.session_id:
            raise ValueError("Successful signin events require a session_id.")
        return self


class Bundle(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    title: Annotated[str, Field(min_length=1, max_length=120)]
    alert_event_id: Identifier
    events: list[Event] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def valid_events(self):
        ids = [event.id for event in self.events]
        if len(ids) != len(set(ids)):
            raise ValueError("Event IDs must be unique.")
        if self.alert_event_id not in ids:
            raise ValueError("alert_event_id must reference an included event.")
        return self


class Evidence(StrictModel):
    id: str
    event_id: str
    indicator: str
    kind: str
    detail: str
    source: str
    observed_at: str
    event_sha256: str


class Assessment(StrictModel):
    summary: Annotated[str, Field(min_length=1, max_length=1500)]
    rationale: list[Annotated[str, Field(max_length=500)]] = Field(max_length=8)
    evidence_ids: list[str] = Field(max_length=30)
    uncertainty: Annotated[str, Field(max_length=1000)]


class Guidance(StrictModel):
    explanation: Annotated[str, Field(min_length=1, max_length=1500)]
    analyst_checks: list[Annotated[str, Field(max_length=500)]] = Field(max_length=6)


class Action(StrictModel):
    kind: Literal["quarantine_email", "block_domain", "revoke_session"]
    target: str
    evidence_ids: list[str]
    description: str


class Incident(StrictModel):
    id: str
    title: str
    input_sha256: str
    created_at: str
    mode: Literal["offline", "groq", "offline-fallback"]
    status: Literal["review_required", "contained", "dismissed"] = "review_required"
    severity: Literal["low", "medium", "high"]
    risk_score: int = Field(ge=0, le=100)
    evidence: list[Evidence]
    affected_accounts: list[str]
    enrichment: list[dict]
    assessment: Assessment
    guidance: Guidance
    actions: list[Action]
    usage: dict
    warning: str = ""
    metadata: dict
