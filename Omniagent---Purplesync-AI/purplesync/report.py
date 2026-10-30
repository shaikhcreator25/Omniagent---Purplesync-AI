"""CSV export helpers for correlation results."""

from __future__ import annotations

import csv
import io
import json

from purplesync.models import CorrelationResult


def _csv_safe(value: object) -> object:
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def results_to_csv(results: list[CorrelationResult]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        _csv_safe(value)
        for value in [
            "test_id",
            "test_name",
            "asset_id",
            "executed_at",
            "time_window_minutes",
            "technique_id",
            "technique_name",
            "tactic",
            "status",
            "match_confidence_heuristic",
            "excluded_context_logs",
            "expected_detection",
            "comments",
            "siem_before_found",
            "siem_after_found",
            "remediation_mode",
            "verification_status",
            "reviewer",
            "approval_note",
            "approved_at",
            "public_references",
            "references_error",
            "review_priority_score",
            "review_priority_band",
            "priority_basis",
            "flaws_and_unknowns",
            "red_team_actions",
            "blue_team_actions",
            "web_research_summary",
            "audit_events",
            "llm_summary",
            "llm_error",
        ]
    )
    for item in results:
        writer.writerow(
            _csv_safe(value)
            for value in [
                item.test_id,
                item.test_name,
                item.asset_id or "",
                item.executed_at or "",
                (
                    item.time_window_minutes
                    if item.time_window_minutes is not None
                    else ""
                ),
                item.technique_id or "",
                item.technique_name or "",
                item.tactic or "",
                item.status,
                item.confidence,
                item.excluded_context_logs,
                item.expected_detection,
                item.comments,
                (item.siem_before or {}).get("alert_found", ""),
                (item.siem_after or {}).get("alert_found", ""),
                item.remediation_mode,
                item.verification_status,
                item.reviewer or "",
                item.approval_note or "",
                item.approved_at or "",
                json.dumps(
                    [reference.model_dump() for reference in item.references],
                    ensure_ascii=True,
                ),
                item.references_error or "",
                item.assessment.priority_score if item.assessment else "",
                item.assessment.priority_band if item.assessment else "",
                item.assessment.priority_basis if item.assessment else "",
                json.dumps(
                    item.assessment.flaws_and_unknowns if item.assessment else [],
                    ensure_ascii=True,
                ),
                json.dumps(
                    item.assessment.red_team_actions if item.assessment else [],
                    ensure_ascii=True,
                ),
                json.dumps(
                    item.assessment.blue_team_actions if item.assessment else [],
                    ensure_ascii=True,
                ),
                item.assessment.web_research_summary if item.assessment else "",
                json.dumps(
                    [event.model_dump() for event in item.audit_events],
                    ensure_ascii=True,
                ),
                item.llm_summary or "",
                item.llm_error or "",
            ]
        )
    return buffer.getvalue()
