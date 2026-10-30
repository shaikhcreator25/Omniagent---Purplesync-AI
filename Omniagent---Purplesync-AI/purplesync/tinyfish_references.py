"""Use TinyFish Search and Fetch to ground per-finding public security guidance."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import requests

from purplesync.config import Settings
from purplesync.models import ReferenceEvidence
from purplesync.privacy import redact_sensitive_text

import time

_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_SEARCH_URL = "https://api.search.tinyfish.ai"
_FETCH_URL = "https://api.fetch.tinyfish.ai"
_TIMEOUT_SECONDS = 30
_MAX_RETRIES = 2

_REFERENCES_CACHE: dict[str, list[ReferenceEvidence]] = {}
_SEARCH_CACHE: dict[tuple[str, str], list[dict[str, Any]]] = {}


def clear_references_cache() -> None:
    """Clear memory caches (useful for testing or cache refresh)."""
    _REFERENCES_CACHE.clear()
    _SEARCH_CACHE.clear()


class ReferenceLookupError(RuntimeError):
    """Raised when TinyFish Search or Fetch fails.

    error_code values:
      'auth_failure'         – HTTP 401; same key, same header as Agent (X-API-Key)
      'rate_limited'         – HTTP 429; rate limit exceeded
      'upstream_unavailable' – HTTP 502/503/504; TinyFish infra issue
      'http_error'           – other 4xx/5xx
      'network_error'        – connection/timeout
      'no_results'           – search returned no approved-source results
      'no_content'           – fetch returned no usable content
    """

    def __init__(self, message: str, error_code: str = "unknown") -> None:
        super().__init__(message)
        self.error_code = error_code


def _request_json(
    method: str, url: str, settings: Settings, **kwargs: Any
) -> dict[str, Any]:
    headers = {
        "X-API-Key": settings.tinyfish_api_key,
        "Accept": "application/json",
    }
    retries = 0
    backoff = 1.5

    while True:
        try:
            response = requests.request(
                method, url, headers=headers, timeout=_TIMEOUT_SECONDS, **kwargs
            )
        except requests.Timeout as exc:
            if retries < _MAX_RETRIES:
                retries += 1
                time.sleep(backoff)
                backoff *= 2
                continue
            raise ReferenceLookupError(
                "TinyFish Search/Fetch request timed out.",
                error_code="network_error",
            ) from exc
        except requests.ConnectionError as exc:
            if retries < _MAX_RETRIES:
                retries += 1
                time.sleep(backoff)
                backoff *= 2
                continue
            raise ReferenceLookupError(
                "TinyFish Search/Fetch could not connect (network error).",
                error_code="network_error",
            ) from exc
        except requests.RequestException as exc:
            raise ReferenceLookupError(
                f"TinyFish Search/Fetch request failed ({type(exc).__name__}).",
                error_code="network_error",
            ) from exc

        if response.status_code == 429:
            if retries < _MAX_RETRIES:
                retries += 1
                retry_after = response.headers.get("Retry-After")
                wait_time = (
                    float(retry_after)
                    if retry_after and retry_after.isdigit()
                    else backoff
                )
                time.sleep(wait_time)
                backoff *= 2
                continue
            raise ReferenceLookupError(
                "TinyFish Search/Fetch rate limit reached (HTTP 429).",
                error_code="rate_limited",
            )

        if response.status_code in (502, 503, 504):
            if retries < _MAX_RETRIES:
                retries += 1
                time.sleep(backoff)
                backoff *= 2
                continue
            raise ReferenceLookupError(
                f"TinyFish Search/Fetch returned HTTP {response.status_code}. "
                "TinyFish infrastructure may be temporarily unavailable.",
                error_code="upstream_unavailable",
            )

        break

    if response.status_code == 401:
        _error_detail = ""
        try:
            _body = response.json()
            _err = _body.get("error", {})
            if isinstance(_err, dict):
                _error_detail = _err.get("message", "")
        except ValueError:
            _error_detail = ""
        raise ReferenceLookupError(
            "TinyFish Search/Fetch returned HTTP 401 Unauthorized. "
            "The API key is missing, invalid, or expired. "
            "TinyFish uses a single key for all products (Agent, Search, Fetch). "
            "Generate a fresh key at https://agent.tinyfish.ai/api-keys and set "
            f"TINYFISH_API_KEY in .env.{' Detail: ' + _error_detail if _error_detail else ''}",
            error_code="auth_failure",
        )
    if response.status_code >= 400:
        raise ReferenceLookupError(
            f"TinyFish Search/Fetch returned HTTP {response.status_code}.",
            error_code="http_error",
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise ReferenceLookupError(
            "TinyFish Search/Fetch returned invalid JSON"
        ) from exc
    if not isinstance(body, dict):
        raise ReferenceLookupError(
            "TinyFish Search/Fetch returned an unexpected response"
        )
    return body


def _safe_reference_url(source: str, value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
    ):
        return None
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if source == "MITRE ATT&CK":
        return (
            value
            if host == "attack.mitre.org" and path.startswith("/techniques/")
            else None
        )
    if source == "Sigma":
        return (
            value
            if host == "github.com" and path.startswith("/sigmahq/sigma/")
            else None
        )
    if source == "NIST":
        return (
            value
            if host == "csrc.nist.gov"
            and (path.startswith("/pubs/") or path.startswith("/projects/"))
            else None
        )
    return None


def _matches_technique(
    source: str, url: str, search_result: dict[str, Any], technique_id: str | None
) -> bool:
    if not technique_id:
        return source == "NIST"
    if source == "MITRE ATT&CK":
        match = re.search(r"/techniques/(T\d{4})(?:/(\d{3}))?/?$", url, re.I)
        if not match:
            return False
        url_id = match.group(1).upper()
        if match.group(2):
            url_id += f".{match.group(2)}"
        return url_id == technique_id or technique_id.startswith(url_id + ".")
    searchable = " ".join(
        str(search_result.get(field, "")) for field in ("title", "snippet", "url")
    )
    return technique_id in searchable.upper()


def _search(query: str, domain: str, settings: Settings) -> list[dict[str, Any]]:
    cache_key = (query.strip().lower(), domain.strip().lower())
    if cache_key in _SEARCH_CACHE:
        return _SEARCH_CACHE[cache_key]
    body = _request_json(
        "GET",
        _SEARCH_URL,
        settings,
        params={"query": query, "include_domains": domain},
    )
    results = body.get("results")
    if not isinstance(results, list):
        raise ReferenceLookupError(
            "TinyFish Search response is missing results field.",
            error_code="response_error",
        )
    parsed = [result for result in results if isinstance(result, dict)]
    _SEARCH_CACHE[cache_key] = parsed
    return parsed


def search_and_fetch_references(
    technique_id: str | None, settings: Settings
) -> list[ReferenceEvidence]:
    """Fetch public ATT&CK/Sigma pages, or general NIST guidance if unmapped."""
    if not settings.has_tinyfish:
        raise ReferenceLookupError(
            "Public reference lookup requires demo mode off and a TinyFish API key."
        )
    tid = (technique_id or "").strip().upper()
    if tid and not _TECHNIQUE_ID.fullmatch(tid):
        raise ReferenceLookupError("MITRE ATT&CK technique ID is invalid.")

    cache_key = tid if tid else "NIST_GENERAL"
    if cache_key in _REFERENCES_CACHE:
        return _REFERENCES_CACHE[cache_key]

    queries = (
        [
            (
                "MITRE ATT&CK",
                f"{tid} detection strategy data sources",
                "attack.mitre.org",
            ),
            ("Sigma", f"{tid} detection rule", "github.com"),
        ]
        if tid
        else [
            (
                "NIST",
                "incident response event analysis detection evidence collection",
                "csrc.nist.gov",
            )
        ]
    )
    candidates: list[tuple[str, dict[str, Any], str]] = []
    for source, query, domain in queries:
        results = _search(query, domain, settings)
        for result in results:
            safe_url = _safe_reference_url(source, result.get("url"))
            if safe_url and _matches_technique(source, safe_url, result, tid or None):
                candidates.append((source, result, safe_url))
                break

    if not candidates:
        raise ReferenceLookupError(
            "TinyFish Search found no results from the approved public sources "
            "(attack.mitre.org, github.com/SigmaHQ, csrc.nist.gov).",
            error_code="no_results",
        )

    body = _request_json(
        "POST",
        _FETCH_URL,
        settings,
        json={
            "urls": [url for _, _, url in candidates],
            "purpose": "Fetch public defensive ATT&CK, Sigma, or NIST guidance.",
            "format": "markdown",
            "per_url_timeout_ms": 20000,
        },
    )
    fetched = body.get("results")
    if not isinstance(fetched, list):
        raise ReferenceLookupError(
            "TinyFish Fetch response is missing results field.",
            error_code="response_error",
        )

    by_url: dict[str, tuple[dict[str, Any], str]] = {}
    for item in fetched:
        if not isinstance(item, dict):
            continue
        requested_url = item.get("url")
        final_url = item.get("final_url") or item.get("url")
        for source, _, candidate_url in candidates:
            safe_final_url = _safe_reference_url(source, final_url)
            if requested_url == candidate_url and safe_final_url:
                by_url[candidate_url] = (item, safe_final_url)
                break

    references = []
    for source, search_result, requested_url in candidates:
        fetched_content = by_url.get(requested_url)
        if fetched_content is None:
            continue
        content, url = fetched_content
        title = content.get("title") or search_result.get("title") or source
        text = content.get("text") or search_result.get("snippet") or ""
        if not isinstance(title, str) or not isinstance(text, str):
            continue
        if source == "Sigma" and tid not in text.upper():
            continue
        references.append(
            ReferenceEvidence(
                source=source,
                title=redact_sensitive_text(title[:200]),
                url=url,
                snippet=redact_sensitive_text(text[:1200]),
            )
        )

    if not references:
        errors = body.get("errors")
        suffix = " Fetch returned errors." if errors else ""
        raise ReferenceLookupError(
            f"TinyFish Fetch returned no content for the selected public sources.{suffix}",
            error_code="no_content",
        )
    _REFERENCES_CACHE[cache_key] = references
    return references
