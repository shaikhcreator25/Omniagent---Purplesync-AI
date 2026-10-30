"""Focused mocked tests for auth failures, upstream failures, budget, and partial success.

All tests are mocked — no live HTTP calls are made.
"""

from unittest.mock import MagicMock

import pytest

from purplesync.config import Settings
from purplesync.models import BlueTeamLog, RedTeamTest
from purplesync.pipeline import run_pipeline
from purplesync.tinyfish_agent import TinyFishError, check_alert
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


# ── Settings helpers ─────────────────────────────────────────────────────────


def _live_settings(**kwargs) -> Settings:
    return Settings(
        demo_mode=False,
        tinyfish_api_key="tf_test_key",
        siem_url="https://mock-siem.example.com/",
        allowed_siem_hosts=("mock-siem.example.com",),
        **kwargs,
    )


def _mock_resp(status: int, body: object = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body or {}
    return resp


# ── TinyFish Agent auth failure (401) ────────────────────────────────────────


def test_agent_401_raises_auth_failure(monkeypatch):
    """A 401 from Agent must raise TinyFishError with error_code='auth_failure'."""
    monkeypatch.setattr(
        "purplesync.tinyfish_agent.requests.post",
        lambda *a, **kw: _mock_resp(401),
    )
    settings = _live_settings()
    with pytest.raises(TinyFishError) as exc_info:
        check_alert("IDS rule Y", "before", settings)
    assert exc_info.value.error_code == "auth_failure"
    assert "401" in str(exc_info.value)
    assert "agent.tinyfish.ai/api-keys" in str(exc_info.value)


def test_agent_502_raises_upstream_unavailable(monkeypatch):
    """A 502 from Agent must raise TinyFishError with error_code='upstream_unavailable'."""
    monkeypatch.setattr(
        "purplesync.tinyfish_agent.requests.post",
        lambda *a, **kw: _mock_resp(502),
    )
    settings = _live_settings()
    with pytest.raises(TinyFishError) as exc_info:
        check_alert("IDS rule Y", "before", settings)
    assert exc_info.value.error_code == "upstream_unavailable"
    assert (
        "ngrok" in str(exc_info.value).lower()
        or "unreachable" in str(exc_info.value).lower()
    )


def test_agent_network_error_raises_network_code(monkeypatch):
    """A connection error must raise TinyFishError with error_code='network_error'."""
    import requests as req_lib

    monkeypatch.setattr(
        "purplesync.tinyfish_agent.requests.post",
        lambda *a, **kw: (_ for _ in ()).throw(req_lib.ConnectionError("refused")),
    )
    settings = _live_settings()
    with pytest.raises(TinyFishError) as exc_info:
        check_alert("IDS rule Y", "before", settings)
    assert exc_info.value.error_code == "network_error"


def test_agent_missing_key_raises_config_error():
    """Missing TINYFISH_API_KEY must raise TinyFishError with error_code='config_error'."""
    settings = Settings(
        demo_mode=False,
        tinyfish_api_key="",
        siem_url="https://mock-siem.example.com/",
        allowed_siem_hosts=("mock-siem.example.com",),
    )
    with pytest.raises(TinyFishError) as exc_info:
        check_alert("IDS rule Y", "before", settings)
    assert exc_info.value.error_code == "config_error"


# ── TinyFish Search/Fetch auth failure (401) ─────────────────────────────────


def test_search_401_raises_auth_failure(monkeypatch):
    """A 401 from Search must raise ReferenceLookupError with error_code='auth_failure'."""
    resp = _mock_resp(
        401, {"error": {"code": "INVALID_API_KEY", "message": "Invalid key"}}
    )
    monkeypatch.setattr(
        "purplesync.tinyfish_references.requests.request",
        lambda *a, **kw: resp,
    )
    settings = _live_settings()
    with pytest.raises(ReferenceLookupError) as exc_info:
        search_and_fetch_references("T1071.001", settings)
    assert exc_info.value.error_code == "auth_failure"
    assert "401" in str(exc_info.value)
    assert (
        "single key" in str(exc_info.value).lower()
        or "unified" in str(exc_info.value).lower()
    )


def test_fetch_502_raises_upstream_unavailable(monkeypatch):
    """A 502 from Search must raise ReferenceLookupError with error_code='upstream_unavailable'."""
    monkeypatch.setattr(
        "purplesync.tinyfish_references.requests.request",
        lambda *a, **kw: _mock_resp(502),
    )
    settings = _live_settings()
    with pytest.raises(ReferenceLookupError) as exc_info:
        search_and_fetch_references("T1566", settings)
    assert exc_info.value.error_code == "upstream_unavailable"


# ── Pipeline partial success ──────────────────────────────────────────────────


def _sample_tests() -> list[RedTeamTest]:
    return [
        RedTeamTest(
            test_id="RT-001",
            name="Malicious HTTP",
            technique_id="T1071.001",
            expected_detection="IDS rule Y",
            keywords=["http", "beacon"],
        )
    ]


def _sample_logs() -> list[BlueTeamLog]:
    return []


def test_pipeline_partial_success_agent_fails_references_fail(monkeypatch):
    """When Agent AND Search/Fetch both fail, correlation result is still returned.

    stage_correlation must be 'ok'; stage_agent must be 'failed'; stage_references 'failed'.
    The failure must not be silently replaced with a success-shaped default.
    """
    # Agent returns 401
    monkeypatch.setattr(
        "purplesync.tinyfish_agent.requests.post",
        lambda *a, **kw: _mock_resp(401),
    )
    # Search returns 401 too
    monkeypatch.setattr(
        "purplesync.tinyfish_references.requests.request",
        lambda *a, **kw: _mock_resp(401, {"error": {"message": "bad key"}}),
    )
    settings = _live_settings()
    results = run_pipeline(_sample_tests(), _sample_logs(), settings=settings)

    assert len(results) == 1
    r = results[0]
    assert r.stage_correlation == "ok", "Correlation must succeed independently"
    assert r.stage_agent == "failed", "Agent stage must be failed on 401"
    assert r.stage_references == "failed", "References stage must be failed on 401"
    # siem_error must contain 401 or auth info
    assert r.siem_error is not None
    assert "401" in r.siem_error or "auth" in r.siem_error.lower()
    # references_error must exist
    assert r.references_error is not None
    assert "401" in r.references_error


def test_pipeline_partial_success_agent_ok_references_fail(monkeypatch):
    """Agent succeeds but Search/Fetch fails. Correlation and Agent stages must be 'ok'."""
    good_agent_resp = _mock_resp(200)
    good_agent_resp.json.return_value = {
        "status": "COMPLETED",
        "result": {"alert_found": False, "evidence": "no alert"},
    }
    monkeypatch.setattr(
        "purplesync.tinyfish_agent.requests.post",
        lambda *a, **kw: good_agent_resp,
    )
    monkeypatch.setattr(
        "purplesync.tinyfish_references.requests.request",
        lambda *a, **kw: _mock_resp(401, {"error": {"message": "bad key"}}),
    )
    settings = _live_settings()
    results = run_pipeline(_sample_tests(), _sample_logs(), settings=settings)

    assert len(results) == 1
    r = results[0]
    assert r.stage_correlation == "ok"
    assert r.stage_agent == "ok"
    assert r.stage_references == "failed"
    assert r.siem_before is not None
    assert r.references_error is not None


# ── Budget semantics ──────────────────────────────────────────────────────────


def test_pipeline_budget_limits_agent_checks(monkeypatch):
    """With MAX_TINYFISH_QUERIES=1 and 3 findings, only 1 gets Agent check."""
    good_resp = _mock_resp(200)
    good_resp.json.return_value = {
        "status": "COMPLETED",
        "result": {"alert_found": False, "evidence": "none"},
    }
    call_count = {"n": 0}

    def counting_post(*a, **kw):
        call_count["n"] += 1
        return good_resp

    monkeypatch.setattr("purplesync.tinyfish_agent.requests.post", counting_post)
    monkeypatch.setattr(
        "purplesync.tinyfish_references.requests.request",
        lambda *a, **kw: _mock_resp(401),
    )

    tests = [
        RedTeamTest(
            test_id=f"RT-{i:03d}",
            name=f"Test {i}",
            technique_id="T1071.001",
            expected_detection="alert",
        )
        for i in range(3)
    ]
    settings = _live_settings(max_tinyfish_queries=1)
    results = run_pipeline(tests, [], settings=settings)

    assert call_count["n"] == 1, "Only 1 Agent call should be made with budget=1"
    agent_checked = [r for r in results if r.stage_agent == "ok"]
    agent_skipped = [r for r in results if r.stage_agent == "skipped"]
    assert len(agent_checked) == 1
    assert len(agent_skipped) == 2


# ── Config loading ────────────────────────────────────────────────────────────


def test_config_live_mode_no_key_raises():
    """Pipeline must raise if live mode is selected but no key is configured."""
    settings = Settings(demo_mode=False, tinyfish_api_key="")
    with pytest.raises(TinyFishError):
        run_pipeline([], [], settings=settings)


def test_config_demo_mode_no_key_works():
    """Demo mode must work without a key — no live HTTP calls."""
    settings = Settings(demo_mode=True, tinyfish_api_key="")
    results = run_pipeline(_sample_tests(), _sample_logs(), settings=settings)
    assert len(results) == 1
    assert results[0].stage_correlation == "ok"


# ── Preflight module ──────────────────────────────────────────────────────────


def test_preflight_agent_401(monkeypatch):
    """Preflight Agent check must return ok=False and error_code='auth_failure' on 401."""
    from purplesync.preflight import check_agent

    monkeypatch.setattr(
        "purplesync.preflight.requests.post",
        lambda *a, **kw: _mock_resp(401),
    )
    result = check_agent(_live_settings())
    assert result["ok"] is False
    assert result["error_code"] == "auth_failure"


def test_preflight_siem_502(monkeypatch):
    """Preflight SIEM check must return ok=False and error_code='upstream_unavailable' on 502."""
    from purplesync.preflight import check_siem

    monkeypatch.setattr(
        "purplesync.preflight.requests.head",
        lambda *a, **kw: _mock_resp(502),
    )
    result = check_siem(_live_settings())
    assert result["ok"] is False
    assert result["error_code"] == "upstream_unavailable"


def test_preflight_siem_200(monkeypatch):
    """Preflight SIEM check must return ok=True on 200."""
    from purplesync.preflight import check_siem

    monkeypatch.setattr(
        "purplesync.preflight.requests.head",
        lambda *a, **kw: _mock_resp(200),
    )
    result = check_siem(_live_settings())
    assert result["ok"] is True


def test_preflight_no_key_returns_config_error():
    """Preflight must return config_error when no key is set, without making HTTP calls."""
    from purplesync.preflight import check_agent, check_fetch, check_search

    settings = Settings(demo_mode=False, tinyfish_api_key="")
    for fn in (check_agent, check_search, check_fetch):
        result = fn(settings)
        assert result["ok"] is False
        assert result["error_code"] == "config_error"


def test_preflight_search_200(monkeypatch):
    """Preflight Search check returns ok=True on 200."""
    from purplesync.preflight import check_search

    monkeypatch.setattr(
        "purplesync.preflight.requests.get",
        lambda *a, **kw: _mock_resp(200, {"results": []}),
    )
    result = check_search(_live_settings())
    assert result["ok"] is True
