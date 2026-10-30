from unittest.mock import MagicMock

import pytest

from purplesync.config import Settings
from purplesync.tinyfish_references import (
    ReferenceLookupError,
    clear_references_cache,
    search_and_fetch_references,
)


@pytest.fixture(autouse=True)
def _reset_cache():
    clear_references_cache()
    yield
    clear_references_cache()


def _response(body):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = body
    return response


def test_search_fetch_uses_only_public_reference_hosts(monkeypatch):
    settings = Settings(demo_mode=False, tinyfish_api_key="tf_test_key")
    mitre_url = "https://attack.mitre.org/techniques/T1071/001/"
    sigma_url = "https://github.com/SigmaHQ/sigma/blob/master/rules/network/example.yml"
    responses = [
        _response({"results": [{"title": "ATT&CK", "url": mitre_url}]}),
        _response({"results": [{"title": "Sigma rule T1071.001", "url": sigma_url}]}),
        _response(
            {
                "results": [
                    {
                        "url": mitre_url,
                        "final_url": mitre_url,
                        "title": "Web Protocols",
                        "text": "Public technique reference.",
                    },
                    {
                        "url": sigma_url,
                        "final_url": sigma_url,
                        "title": "Example Sigma rule",
                        "text": "T1071.001 public rule reference.",
                    },
                ],
                "errors": [],
            }
        ),
    ]
    calls = []

    def fake_request(method, url, headers, timeout, **kwargs):
        calls.append((method, url, headers, kwargs))
        return responses.pop(0)

    monkeypatch.setattr("purplesync.tinyfish_references.requests.request", fake_request)
    references = search_and_fetch_references("T1071.001", settings)

    assert [reference.source for reference in references] == ["MITRE ATT&CK", "Sigma"]
    assert len(calls) == 3
    assert all(call[2]["X-API-Key"] == "tf_test_key" for call in calls)
    assert calls[0][3]["params"]["query"].startswith("T1071.001")
    assert calls[0][3]["params"]["include_domains"] == "attack.mitre.org"
    assert calls[2][3]["json"]["urls"] == [mitre_url, sigma_url]


def test_search_fetch_rejects_non_allowlisted_search_results(monkeypatch):
    settings = Settings(demo_mode=False, tinyfish_api_key="tf_test_key")
    response = _response(
        {
            "results": [
                {"title": "Unexpected", "url": "https://evil.example/techniques/"}
            ]
        }
    )
    monkeypatch.setattr(
        "purplesync.tinyfish_references.requests.request",
        lambda *args, **kwargs: response,
    )

    with pytest.raises(ReferenceLookupError, match="no results from the approved"):
        search_and_fetch_references("T1566", settings)


def test_fetch_rejects_redirect_outside_allowed_sources(monkeypatch):
    settings = Settings(demo_mode=False, tinyfish_api_key="tf_test_key")
    mitre_url = "https://attack.mitre.org/techniques/T1566/"
    responses = [
        _response({"results": [{"title": "ATT&CK", "url": mitre_url}]}),
        _response({"results": []}),
        _response(
            {
                "results": [
                    {
                        "url": mitre_url,
                        "final_url": "https://evil.example/redirected",
                        "title": "Unexpected",
                        "text": "Do not trust.",
                    }
                ]
            }
        ),
    ]
    monkeypatch.setattr(
        "purplesync.tinyfish_references.requests.request",
        lambda *args, **kwargs: responses.pop(0),
    )

    with pytest.raises(ReferenceLookupError, match="no content"):
        search_and_fetch_references("T1566", settings)


def test_search_fetch_requires_a_valid_technique_id():
    settings = Settings(demo_mode=False, tinyfish_api_key="tf_test_key")
    with pytest.raises(
        ReferenceLookupError, match="MITRE ATT&CK technique ID is invalid"
    ):
        search_and_fetch_references("https://evil.example", settings)


def test_unmapped_finding_uses_allowlisted_nist_guidance(monkeypatch):
    settings = Settings(demo_mode=False, tinyfish_api_key="tf_test_key")
    nist_url = "https://csrc.nist.gov/pubs/sp/800/61/r3/final"
    responses = [
        _response({"results": [{"title": "Incident Response", "url": nist_url}]}),
        _response(
            {
                "results": [
                    {
                        "url": nist_url,
                        "final_url": nist_url,
                        "title": "NIST SP 800-61 Rev. 3",
                        "text": "Public incident-response guidance.",
                    }
                ]
            }
        ),
    ]
    calls = []

    def fake_request(method, url, headers, timeout, **kwargs):
        calls.append((method, url, kwargs))
        return responses.pop(0)

    monkeypatch.setattr("purplesync.tinyfish_references.requests.request", fake_request)
    references = search_and_fetch_references(None, settings)

    assert references[0].source == "NIST"
    assert calls[0][2]["params"]["include_domains"] == "csrc.nist.gov"
    assert calls[0][2]["params"]["query"].startswith("incident response")
