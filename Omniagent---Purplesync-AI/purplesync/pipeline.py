"""Orchestrates parse → correlate → TinyFish (bounded) → optional LLM."""

from __future__ import annotations

from datetime import datetime, timezone

from purplesync.assessment import build_assessment
from purplesync.config import Settings, load_settings
from purplesync.correlator import correlate
from purplesync.llm_helper import attach_summaries
from purplesync.logging_setup import configure_logging
from purplesync.models import AuditEvent, BlueTeamLog, CorrelationResult, RedTeamTest
from purplesync.tinyfish_agent import TinyFishError, check_alert
from purplesync.tinyfish_references import (
    ReferenceLookupError,
    search_and_fetch_references,
)

logger = configure_logging()


def run_pipeline(
    tests: list[RedTeamTest],
    logs: list[BlueTeamLog],
    *,
    run_tinyfish: bool = True,
    run_llm: bool = True,
    allow_external_llm: bool = False,
    run_references: bool = True,
    settings: Settings | None = None,
) -> list[CorrelationResult]:
    settings = settings or load_settings()
    if not settings.demo_mode and not settings.has_tinyfish:
        raise TinyFishError(
            "Live mode requires TINYFISH_API_KEY. Configure the key or explicitly "
            "enable offline demo mode."
        )
    if not settings.demo_mode and not run_tinyfish:
        raise TinyFishError("Live analysis requires TinyFish Agent SIEM verification.")
    if not settings.demo_mode and not run_references:
        raise TinyFishError("Live analysis requires TinyFish Search/Fetch grounding.")

    results = correlate(tests, logs)
    for result in results:
        result.stage_correlation = "ok"  # correlation always succeeds if we reach here
        result.audit_events.append(
            AuditEvent(
                timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                action="correlation_completed",
                details=f"status={result.status}; confidence={result.confidence}",
            )
        )

    if run_tinyfish:
        # budget = number of *findings* to check (not total HTTP calls).
        # Each finding uses up to 1 Agent call + 3 Search/Fetch calls.
        budget = len(results) if settings.demo_mode else settings.max_tinyfish_queries
        for result in results[:budget]:
            try:
                logger.info(
                    "Checking SIEM before remediation for test %s", result.test_id
                )
                result.siem_before = check_alert(
                    result.expected_detection, "before", settings
                )
                result.stage_agent = "ok"
                if result.siem_before.get("alert_found"):
                    result.comments += " TinyFish saw the alert in the SIEM UI."
                else:
                    result.comments += (
                        " TinyFish before-remediation search did not find the alert."
                    )
            except TinyFishError as exc:
                logger.warning(
                    "TinyFish check failed for test %s: %s (code=%s)",
                    result.test_id,
                    exc,
                    getattr(exc, "error_code", "unknown"),
                )
                result.siem_error = str(exc)
                result.stage_agent = "failed"
                result.comments += (
                    " TinyFish check unavailable; see the SIEM check status."
                )
        for result in results[budget:]:
            result.siem_error = (
                "TinyFish per-run query budget reached; this finding was not checked."
            )
            result.stage_agent = "skipped"

    if run_references and not settings.demo_mode:
        # Same finding budget as Agent. Each finding uses up to 3 HTTP Search/Fetch calls.
        reference_budget = settings.max_tinyfish_queries
        eligible = results
        for result in eligible[:reference_budget]:
            result.reference_lookup_attempted = True
            try:
                result.references = search_and_fetch_references(
                    result.technique_id, settings
                )
                result.stage_references = "ok"
                result.audit_events.append(
                    AuditEvent(
                        timestamp=datetime.now(timezone.utc).isoformat(
                            timespec="seconds"
                        ),
                        action="public_references_fetched",
                        details=f"ATT&CK/Sigma references for {result.technique_id}",
                    )
                )
            except ReferenceLookupError as exc:
                result.references_error = str(exc)
                result.stage_references = "failed"
                result.audit_events.append(
                    AuditEvent(
                        timestamp=datetime.now(timezone.utc).isoformat(
                            timespec="seconds"
                        ),
                        action="public_reference_lookup_failed",
                        details=str(exc),
                    )
                )
            result.assessment = build_assessment(
                result, result.references, research_error=result.references_error
            )
        for result in eligible[reference_budget:]:
            result.references_error = (
                "TinyFish public reference lookup budget reached; not searched."
            )
            result.reference_lookup_attempted = True
            result.stage_references = "skipped"
            result.assessment_error = result.references_error
            result.assessment = build_assessment(
                result, [], research_error=result.references_error
            )
    elif settings.demo_mode:
        for result in results:
            result.stage_references = "skipped"
            result.assessment = build_assessment(
                result,
                [],
                research_error="Offline synthetic demo does not contact TinyFish Search/Fetch.",
            )

    if run_llm:
        attach_summaries(results, settings, allow_external=allow_external_llm)
    return results
