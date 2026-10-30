"""Human-gated retest and approval operations for correlation findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from purplesync.config import Settings
from purplesync.models import AuditEvent, CorrelationResult
from purplesync.tinyfish_agent import check_alert

RemediationMode = Literal["simulated", "operator_reported"]


class ReviewError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _record(
    result: CorrelationResult, action: str, actor: str = "system", details: str = ""
) -> None:
    result.audit_events.append(
        AuditEvent(timestamp=_utc_now(), action=action, actor=actor, details=details)
    )


def retest_finding(
    result: CorrelationResult,
    settings: Settings,
    mode: RemediationMode,
    *,
    actor: str,
) -> CorrelationResult:
    if mode == "simulated" and not settings.demo_mode:
        raise ReviewError("Simulated remediation is only available in demo mode.")
    if mode == "operator_reported" and not settings.has_tinyfish:
        raise ReviewError(
            "Live retesting requires demo mode off and a configured TinyFish API key."
        )

    after = check_alert(result.expected_detection, "after", settings)
    result.siem_after = after
    result.remediation_mode = mode
    before_found = bool((result.siem_before or {}).get("alert_found"))
    after_found = bool(after.get("alert_found"))
    if after_found and not before_found:
        result.verification_status = "verified"
        details = "Expected alert absent before and present after retest."
    elif after_found:
        result.verification_status = "already_detected"
        details = "Expected alert was already present before retest."
    else:
        result.verification_status = "not_verified"
        details = "Expected alert was not found during the after retest."
    _record(result, "retest_completed", actor, details)
    return result


def approve_finding(
    result: CorrelationResult, reviewer: str, note: str = ""
) -> CorrelationResult:
    name = reviewer.strip()
    if not name:
        raise ReviewError("Enter a reviewer name before approving.")
    eligible = (
        result.verification_status == "verified"
        or result.status == "Detected"
        or bool((result.siem_before or {}).get("alert_found"))
    )
    if not eligible:
        raise ReviewError(
            "Approve only after the finding is detected or its remediation is verified."
        )
    if result.approved_at:
        raise ReviewError("This finding has already been approved.")

    result.reviewer = name[:120]
    result.approval_note = note.strip()[:500]
    result.approved_at = _utc_now()
    _record(result, "approved", name, result.approval_note)
    return result
