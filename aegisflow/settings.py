"""Environment configuration; keys never enter incident records."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
os.environ.setdefault("CREWAI_TELEMETRY_DISABLED", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")


@dataclass(frozen=True)
class Settings:
    groq_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", ""), repr=False)
    serper_key: str = field(default_factory=lambda: os.getenv("SERPER_API_KEY", ""), repr=False)
    model: str = field(default_factory=lambda: os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"))
    db_path: str = field(default_factory=lambda: os.getenv("AEGIS_DB_PATH", str(ROOT / "data/aegisflow.db")))
    max_calls: int = field(default_factory=lambda: int(os.getenv("AEGIS_MAX_LLM_CALLS", "2")))
    max_tokens: int = field(default_factory=lambda: int(os.getenv("AEGIS_MAX_OUTPUT_TOKENS", "700")))

    def __post_init__(self):
        if not 1 <= self.max_calls <= 4:
            raise ValueError("AEGIS_MAX_LLM_CALLS must be between 1 and 4.")
        if not 100 <= self.max_tokens <= 1500:
            raise ValueError("AEGIS_MAX_OUTPUT_TOKENS must be between 100 and 1500.")
