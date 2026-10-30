from pathlib import Path

import pytest

from purplesync.config import Settings
from purplesync.correlator import correlate
from purplesync.models import CorrelationResult
from purplesync.parsers import parse_blue_team, parse_red_team
from purplesync.privacy import redact_sensitive_text
from purplesync.workflow import ReviewError, approve_finding, retest_finding

ROOT = Path(__file__).resolve().parents[1]


def _rt001_result() -> CorrelationResult:
    tests = parse_red_team((ROOT / "sample_data" / "red_team_tests.json").read_bytes())
    logs = parse_blue_team((ROOT / "sample_data" / "blue_team_logs.json").read_bytes())
    return correlate([tests[0]], logs)[0]


def test_demo_retest_and_human_approval():
    result = _rt001_result()
    result.siem_before = {
        "alert_found": False,
        "evidence": "No alert in the before snapshot.",
    }

    retest_finding(result, Settings(demo_mode=True), "simulated", actor="analyst")

    assert result.verification_status == "verified"
    assert result.siem_after["alert_found"] is True
    assert result.audit_events[-1].action == "retest_completed"

    approve_finding(result, "Reviewer One", "Evidence reviewed.")
    assert result.approved_at
    assert result.audit_events[-1].action == "approved"


def test_cannot_approve_unverified_gap_or_repeat_approval():
    result = _rt001_result()
    with pytest.raises(ReviewError, match="only after"):
        approve_finding(result, "Reviewer One")

    result.verification_status = "verified"
    approve_finding(result, "Reviewer One")
    with pytest.raises(ReviewError, match="already been approved"):
        approve_finding(result, "Reviewer Two")


def test_live_retest_requires_live_agent():
    result = _rt001_result()
    with pytest.raises(ReviewError, match="Live retesting requires"):
        retest_finding(
            result, Settings(demo_mode=False), "operator_reported", actor="analyst"
        )


def test_sensitive_values_are_redacted_before_external_use():
    text = (
        "Contact alice@example.org from 10.1.2.3 or 2001:db8::1; "
        "api_key=abc123; Authorization: Bearer abc.xyz"
    )
    redacted = redact_sensitive_text(text)
    assert "alice@example.org" not in redacted
    assert "10.1.2.3" not in redacted
    assert "2001:db8::1" not in redacted
    assert "abc123" not in redacted
    assert "abc.xyz" not in redacted
