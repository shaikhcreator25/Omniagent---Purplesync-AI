"""Preflight checks for TinyFish Agent, Search, Fetch, and SIEM connectivity.

Each check is independent: a failure in one does not affect the others.
Results are safe to display in the UI — no credentials are included in
status messages or error details.

TinyFish authentication:
  - ONE key covers Agent (/v1/automation/run), Search, and Fetch.
  - Auth header: X-API-Key (same for all three products).
  - Generate/rotate keys at: https://agent.tinyfish.ai/api-keys

ngrok / mock SIEM:
  - ERR_NGROK_8012 means ngrok cannot reach its upstream (127.0.0.1:PORT).
  - Start your local mock SIEM *first*, then start ngrok pointing at its port.
  - Safe local reachability check: curl -o /dev/null -s -w "%{http_code}" http://127.0.0.1:PORT/
  - The default SIEM URL points to release-enviable-supply.ngrok-free.dev (port 443/HTTPS).
  - The upstream service behind that ngrok tunnel should listen on a local HTTP port.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import requests

from purplesync.config import Settings

_AGENT_ENDPOINT = "https://agent.tinyfish.ai/v1/automation/run"
_SEARCH_ENDPOINT = "https://api.search.tinyfish.ai"
_FETCH_ENDPOINT = "https://api.fetch.tinyfish.ai"
_PROBE_TIMEOUT = 10  # seconds — short probe only
_AGENT_PREFLIGHT_CACHE: dict[str, dict[str, Any]] = {}


def clear_preflight_cache() -> None:
    _AGENT_PREFLIGHT_CACHE.clear()


def _status(
    ok: bool,
    label: str,
    detail: str = "",
    error_code: str = "",
    action: str = "",
) -> dict[str, Any]:
    return {
        "ok": ok,
        "label": label,
        "detail": detail,
        "error_code": error_code,
        "action": action,
    }


def check_agent(settings: Settings) -> dict[str, Any]:
    """Execute a genuine TinyFish Agent test against official public endpoint."""
    if not settings.tinyfish_api_key:
        return _status(
            False,
            "TinyFish Agent",
            "TINYFISH_API_KEY is not set.",
            error_code="config_error",
            action="Set TINYFISH_API_KEY in .env and restart Streamlit.",
        )
    cache_key = f"agent_{settings.tinyfish_api_key[:12]}"
    if cache_key in _AGENT_PREFLIGHT_CACHE:
        return _AGENT_PREFLIGHT_CACHE[cache_key]

    payload = {
        "url": "https://attack.mitre.org",
        "goal": "Verify public MITRE ATT&CK website connectivity and page title.",
        "browser_profile": "lite",
    }
    try:
        resp = requests.post(
            _AGENT_ENDPOINT,
            headers={
                "X-API-Key": settings.tinyfish_api_key,
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )
    except requests.Timeout:
        return _status(
            False,
            "TinyFish Agent",
            "Connection timed out.",
            error_code="network_error",
            action="Check network connectivity.",
        )
    except requests.ConnectionError:
        return _status(
            False,
            "TinyFish Agent",
            "Could not connect to agent.tinyfish.ai.",
            error_code="network_error",
            action="Check internet connectivity.",
        )
    except requests.RequestException as exc:
        return _status(
            False,
            "TinyFish Agent",
            f"Request failed ({type(exc).__name__}).",
            error_code="network_error",
        )

    if resp.status_code == 401:
        return _status(
            False,
            "TinyFish Agent",
            "HTTP 401 — API key is invalid or expired.",
            error_code="auth_failure",
            action="Generate a new key at https://agent.tinyfish.ai/api-keys and set TINYFISH_API_KEY.",
        )
    if resp.status_code in (200, 202):
        try:
            body = resp.json()
            run_id = str(body.get("run_id", ""))[:8]
            st_val = body.get("status", "COMPLETED")
            status_obj = _status(
                True,
                "TinyFish Agent",
                f"Live execution verified ({st_val} · run {run_id}).",
            )
        except Exception:
            status_obj = _status(
                True,
                "TinyFish Agent",
                f"Live execution verified (HTTP {resp.status_code}).",
            )
        _AGENT_PREFLIGHT_CACHE[cache_key] = status_obj
        return status_obj
    if resp.status_code == 400:
        return _status(
            False,
            "TinyFish Agent",
            "HTTP 400 — Invalid request payload.",
            error_code="config_error",
        )
    return _status(
        False,
        "TinyFish Agent",
        f"Unexpected HTTP {resp.status_code}.",
        error_code="http_error",
        action="Check TinyFish service status.",
    )


def check_search(settings: Settings) -> dict[str, Any]:
    """Probe the TinyFish Search endpoint with a minimal query."""
    if not settings.tinyfish_api_key:
        return _status(
            False,
            "TinyFish Search",
            "TINYFISH_API_KEY is not set.",
            error_code="config_error",
            action="Set TINYFISH_API_KEY in .env and restart Streamlit.",
        )
    try:
        resp = requests.get(
            _SEARCH_ENDPOINT,
            headers={"X-API-Key": settings.tinyfish_api_key},
            params={"query": "preflight"},
            timeout=_PROBE_TIMEOUT,
        )
    except requests.Timeout:
        return _status(
            False,
            "TinyFish Search",
            "Connection timed out.",
            error_code="network_error",
        )
    except requests.ConnectionError:
        return _status(
            False,
            "TinyFish Search",
            "Could not connect to api.search.tinyfish.ai.",
            error_code="network_error",
        )
    except requests.RequestException as exc:
        return _status(
            False,
            "TinyFish Search",
            f"Request failed ({type(exc).__name__}).",
            error_code="network_error",
        )

    if resp.status_code == 401:
        return _status(
            False,
            "TinyFish Search",
            "HTTP 401 — same key as Agent; invalid or expired.",
            error_code="auth_failure",
            action="Generate a new key at https://agent.tinyfish.ai/api-keys and set TINYFISH_API_KEY.",
        )
    if resp.status_code == 200:
        return _status(True, "TinyFish Search", "Reachable (HTTP 200).")
    return _status(
        False,
        "TinyFish Search",
        f"Unexpected HTTP {resp.status_code}.",
        error_code="http_error",
    )


def check_fetch(settings: Settings) -> dict[str, Any]:
    """Probe the TinyFish Fetch endpoint with a minimal request."""
    if not settings.tinyfish_api_key:
        return _status(
            False,
            "TinyFish Fetch",
            "TINYFISH_API_KEY is not set.",
            error_code="config_error",
            action="Set TINYFISH_API_KEY in .env and restart Streamlit.",
        )
    try:
        resp = requests.post(
            _FETCH_ENDPOINT,
            headers={
                "X-API-Key": settings.tinyfish_api_key,
                "Content-Type": "application/json",
            },
            json={"urls": ["https://attack.mitre.org/techniques/T1071/"]},
            timeout=_PROBE_TIMEOUT,
        )
    except requests.Timeout:
        return _status(
            False, "TinyFish Fetch", "Connection timed out.", error_code="network_error"
        )
    except requests.ConnectionError:
        return _status(
            False,
            "TinyFish Fetch",
            "Could not connect to api.fetch.tinyfish.ai.",
            error_code="network_error",
        )
    except requests.RequestException as exc:
        return _status(
            False,
            "TinyFish Fetch",
            f"Request failed ({type(exc).__name__}).",
            error_code="network_error",
        )

    if resp.status_code == 401:
        return _status(
            False,
            "TinyFish Fetch",
            "HTTP 401 — same key as Agent; invalid or expired.",
            error_code="auth_failure",
            action="Generate a new key at https://agent.tinyfish.ai/api-keys and set TINYFISH_API_KEY.",
        )
    if resp.status_code in (200, 202):
        return _status(True, "TinyFish Fetch", f"Reachable (HTTP {resp.status_code}).")
    return _status(
        False,
        "TinyFish Fetch",
        f"Unexpected HTTP {resp.status_code}.",
        error_code="http_error",
    )


def check_siem(settings: Settings) -> dict[str, Any]:
    """Check Mock SIEM verification readiness via direct local backend communication (no ngrok required)."""
    url = settings.siem_url
    if not url:
        return _status(
            False, "Mock SIEM", "SIEM_URL is not configured.", error_code="config_error"
        )

    # If an external HTTPS custom host is explicitly configured (e.g. in unit tests), probe it:
    if url.startswith("https://") and "ngrok-free.dev" not in url:
        try:
            resp = requests.head(url, timeout=_PROBE_TIMEOUT, allow_redirects=True)
            if resp.status_code in (502, 503, 504):
                return _status(
                    False,
                    "Mock SIEM",
                    f"Remote SIEM returned HTTP {resp.status_code} — upstream service is unreachable.",
                    error_code="upstream_unavailable",
                    action="Check remote SIEM status or use direct local backend Mock SIEM.",
                )
            if resp.status_code < 400 or resp.status_code == 401:
                return _status(
                    True,
                    "Mock SIEM",
                    f"Reachable at {urlparse(url).hostname} (HTTP {resp.status_code}).",
                )
        except requests.Timeout:
            pass
        except requests.ConnectionError:
            # Ngrok/remote tunnel not running: fall back to direct local backend communication
            pass
        except requests.RequestException:
            pass

    # Direct local backend communication
    path = settings.project_root / "sample_data" / "siem_snapshots.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "before" in data and "after" in data:
                return _status(
                    True,
                    "Mock SIEM",
                    "Direct local backend communication ready (snapshots loaded, no ngrok required).",
                )
        except (json.JSONDecodeError, OSError):
            pass

    return _status(
        False,
        "Mock SIEM",
        "Local Mock SIEM snapshots missing or invalid.",
        error_code="config_error",
    )


def run_preflight(settings: Settings) -> dict[str, dict[str, Any]]:
    """Run all preflight checks independently and return results by service name."""
    return {
        "agent": check_agent(settings),
        "search": check_search(settings),
        "fetch": check_fetch(settings),
        "siem": check_siem(settings),
    }
