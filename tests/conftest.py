import pytest

from aegisflow.models import Bundle
from aegisflow.settings import ROOT, Settings
from aegisflow.storage import Store


@pytest.fixture
def phishing():
    return Bundle.model_validate_json((ROOT / "samples/phishing_incident.json").read_text())


@pytest.fixture
def benign():
    return Bundle.model_validate_json((ROOT / "samples/benign_incident.json").read_text())


@pytest.fixture
def settings(tmp_path):
    return Settings(db_path=str(tmp_path / "cases.db"), groq_key="", serper_key="")


@pytest.fixture
def store(settings):
    return Store(settings.db_path)
