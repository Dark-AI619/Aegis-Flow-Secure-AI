import requests

from aegisflow.tools.enrichment import enrich
from aegisflow.tools.indicators import host, public_domain


def test_url_normalization():
    assert host("https://SECURE-PAYROLL.test./login") == "secure-payroll.test"
    assert host("https://secure-payroll.test@innocent.example/login") == "innocent.example"
    assert host("https://[broken") == ""
    assert host("https://foo.invalid\\bad") == ""


def test_reserved_hosts_never_sent_to_serper(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Reserved hosts must never cause network requests")

    monkeypatch.setattr(requests, "post", fail)
    rows = enrich(["secure-payroll.test", "company.example", "localhost", "10.0.0.1", "example.com"], "test", True)
    assert all(not r["source"].startswith("Serper") for r in rows)
    assert not public_domain("127.0.0.1")


def test_serper_bounded_and_not_a_verdict(monkeypatch):
    calls = []

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "organic": [
                    {"title": "Context", "link": "https://reference.org/info", "snippet": "Unverified information"}
                ]
            }

    def post(url, **kwargs):
        calls.append(kwargs)
        return Response()

    monkeypatch.setattr(requests, "post", post)
    rows = enrich(["one.org", "two.org", "three.org"], "test", True)
    assert len(calls) == 2
    assert all("@" not in r["json"]["q"] for r in calls)
    assert all(r["verdict"] in {"unknown", "unverified"} for r in rows)


def test_search_failure_is_inconclusive(monkeypatch):
    def post(*args, **kwargs):
        raise requests.Timeout("never print this payload")

    monkeypatch.setattr(requests, "post", post)
    rows = enrich(["unknown.org"], "test", True)
    assert rows[0]["verdict"] == "unknown"
    assert rows[1]["verdict"] == "unavailable"
    assert "never print" not in str(rows)
