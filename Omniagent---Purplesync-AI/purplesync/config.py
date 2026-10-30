"""Load configuration from environment variables and Streamlit secrets."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def _get_secret(name: str, default: str = "") -> str:
    value = os.getenv(name, "").strip()
    if value:
        return value
    try:
        import streamlit as st

        # Check session state override if set via UI
        if hasattr(st, "session_state") and name in st.session_state:
            val = str(st.session_state[name] or "").strip()
            if val:
                return val

        secrets = getattr(st, "secrets", {})
        if name in secrets and str(secrets[name]).strip():
            return str(secrets[name]).strip()
        if name.lower() in secrets and str(secrets[name.lower()]).strip():
            return str(secrets[name.lower()]).strip()
    except Exception:
        return default
    return default


def _bool_env(name: str, default: bool = False) -> bool:
    raw = _get_secret(name, str(default)).lower()
    return raw in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = _get_secret(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    tinyfish_api_key: str = ""
    tinyfish_endpoint: str = "https://agent.tinyfish.ai/v1/automation/run"
    siem_url: str = "https://release-enviable-supply.ngrok-free.dev/"
    allowed_siem_hosts: tuple[str, ...] = ("release-enviable-supply.ngrok-free.dev",)
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    demo_mode: bool = False
    # MAX_TINYFISH_QUERIES: bounds the number of *findings* that receive live
    # TinyFish calls. Each checked finding can produce up to:
    #   1 HTTP call  – TinyFish Agent (SIEM check)
    #   3 HTTP calls – TinyFish Search (ATT&CK query + Sigma query + optional NIST)
    #   1 HTTP call  – TinyFish Fetch (content retrieval)
    # So 10 findings ≈ up to 50 HTTP calls, not 10.
    # Reduce this value if you hit rate limits.
    max_tinyfish_queries: int = 10
    request_timeout_seconds: int = 90
    project_root: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[1]
    )

    @property
    def has_tinyfish(self) -> bool:
        return bool(self.tinyfish_api_key) and not self.demo_mode

    @property
    def has_llm(self) -> bool:
        return bool(self.openai_api_key)

    def siem_host_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        try:
            port = parsed.port
        except ValueError:
            return False
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or port not in (None, 443)
        ):
            return False
        host = (parsed.hostname or "").lower()
        if host == "localhost" or host.endswith((".localhost", ".local")):
            return False
        try:
            if not ipaddress.ip_address(host).is_global:
                return False
        except ValueError:
            pass
        return host in {h.lower() for h in self.allowed_siem_hosts}


def load_settings() -> Settings:
    env_file = Path(__file__).resolve().parents[1] / ".env"
    if env_file.exists():
        load_dotenv(env_file, override=False)
    default_host = "release-enviable-supply.ngrok-free.dev"
    default_url = f"https://{default_host}/"
    hosts_raw = _get_secret("ALLOWED_SIEM_HOSTS", default_host)
    hosts = tuple(h.strip() for h in hosts_raw.split(",") if h.strip())
    return Settings(
        tinyfish_api_key=_get_secret("TINYFISH_API_KEY"),
        siem_url=_get_secret("SIEM_URL", default_url),
        allowed_siem_hosts=hosts or (default_host,),
        openai_api_key=_get_secret("OPENAI_API_KEY"),
        openai_model=_get_secret("OPENAI_MODEL", "gpt-4o-mini"),
        demo_mode=_bool_env("PURPLESYNC_DEMO_MODE", False),
        max_tinyfish_queries=_int_env("MAX_TINYFISH_QUERIES", 10, 1, 100),
    )
