from unittest.mock import MagicMock

import pytest

from purplesync.config import Settings
from purplesync.tinyfish_agent import TinyFishError, check_alert, validate_siem_url


def test_default_siem_url_matches_allowlist():
    settings = Settings()
    assert settings.siem_url == "https://release-enviable-supply.ngrok-free.dev/"
    assert settings.siem_host_allowed(settings.siem_url)


def test_demo_search_before_missing():
    settings = Settings(demo_mode=True, tinyfish_api_key="")
    result = check_alert("IDS rule Y", "before", settings)
    assert result["alert_found"] is False
    assert result["mode"] == "demo"


def test_demo_search_after_found():
    settings = Settings(demo_mode=True, tinyfish_api_key="")
    result = check_alert("IDS rule Y", "after", settings)
    assert result["alert_found"] is True


def test_allowlist_rejects_uncontrolled_host():
    settings = Settings(allowed_siem_hosts=("mock-siem.example.com",))
    with pytest.raises(TinyFishError):
        validate_siem_url("https://evil.example", settings)


def test_rejects_insecure_or_credential_bearing_siem_urls():
    settings = Settings(allowed_siem_hosts=("mock-siem.example.com",))
    with pytest.raises(TinyFishError):
        validate_siem_url("http://mock-siem.example.com/app", settings)
    with pytest.raises(TinyFishError):
        validate_siem_url("https://user:pass@mock-siem.example.com/app", settings)
    with pytest.raises(TinyFishError):
        validate_siem_url("https://mock-siem.example.com/app?token=secret", settings)
    with pytest.raises(TinyFishError):
        validate_siem_url("https://mock-siem.example.com:8443/app", settings)


def test_allowlist_accepts_mock_host():
    settings = Settings(
        siem_url="https://mock-siem.example.com/app",
        allowed_siem_hosts=("mock-siem.example.com",),
    )
    assert validate_siem_url(settings.siem_url, settings).startswith("https://")


def test_allowlist_rejects_private_and_local_hosts():
    settings = Settings(
        allowed_siem_hosts=("127.0.0.1", "localhost", "mock-siem.local")
    )
    assert not settings.siem_host_allowed("https://127.0.0.1/app")
    assert not settings.siem_host_allowed("https://localhost/app")
    assert not settings.siem_host_allowed("https://mock-siem.local/app")


def test_live_call_mocked(monkeypatch):
    settings = Settings(
        demo_mode=False,
        tinyfish_api_key="tf_test_key",
        siem_url="https://mock-siem.example.com/app",
        allowed_siem_hosts=("mock-siem.example.com",),
    )
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "status": "COMPLETED",
        "result": {
            "alert_found": True,
            "alert_name": "IDS alert for alice@example.org",
            "evidence": "visible in grid",
        },
    }

    def fake_post(url, headers, json, timeout):
        assert url.startswith("https://agent.tinyfish.ai")
        assert headers["X-API-Key"] == "tf_test_key"
        assert json["url"] == "https://mock-siem.example.com/app"
        assert '"mock-siem.example.com"' in json["goal"]
        return response

    monkeypatch.setattr("purplesync.tinyfish_agent.requests.post", fake_post)
    result = check_alert("IDS rule Y", "before", settings)
    assert result["alert_found"] is True
    assert "alice@example.org" not in result["alert_name"]
    assert result["mode"] == "live"


def test_live_call_rejects_failed_run(monkeypatch):
    settings = Settings(
        demo_mode=False,
        tinyfish_api_key="tf_test_key",
        siem_url="https://mock-siem.example.com/app",
        allowed_siem_hosts=("mock-siem.example.com",),
    )
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "status": "FAILED",
        "error": {"message": "agent error"},
    }
    monkeypatch.setattr(
        "purplesync.tinyfish_agent.requests.post", lambda *args, **kwargs: response
    )
    with pytest.raises(TinyFishError, match="did not complete"):
        check_alert("IDS rule Y", settings=settings)
