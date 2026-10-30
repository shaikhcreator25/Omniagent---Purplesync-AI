"""Shared data models for Red/Blue inputs and correlation results."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Status = Literal[
    "Detected",
    "Gap – missing evidence",
    "Requiring investigation",
    "Insufficient Data",
]


def _sanitize_text(value: str, max_len: int = 2000) -> str:
    text = value.replace("\x00", "").strip()
    if text[:1] in {"=", "+", "-", "@"}:
        text = "'" + text
    return text[:max_len]


class RedTeamTest(BaseModel):
    test_id: str
    name: str
    description: str = ""
    technique_id: str | None = None
    expected_detection: str
    keywords: list[str] = Field(default_factory=list)
    asset_id: str | None = None
    executed_at: str | None = None
    time_window_minutes: int = Field(default=30, ge=0, le=1440)

    @field_validator(
        "test_id", "name", "description", "expected_detection", mode="before"
    )
    @classmethod
    def _clean_str(cls, value: Any) -> str:
        return _sanitize_text(str(value or ""))

    @field_validator("technique_id", mode="before")
    @classmethod
    def _clean_tid(cls, value: Any) -> str | None:
        if value is None or str(value).strip() == "":
            return None
        return _sanitize_text(str(value), 32)

    @field_validator("asset_id", mode="before")
    @classmethod
    def _clean_asset(cls, value: Any) -> str | None:
        if value is None or str(value).strip() == "":
            return None
        return _sanitize_text(str(value), 128)

    @field_validator("executed_at", mode="before")
    @classmethod
    def _clean_executed_at(cls, value: Any) -> str | None:
        if value is None or str(value).strip() == "":
            return None
        cleaned = _sanitize_text(str(value), 64)
        try:
            datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("executed_at must be an ISO 8601 timestamp") from exc
        return cleaned

    @field_validator("keywords", mode="before")
    @classmethod
    def _clean_keywords(cls, value: Any) -> list[str]:
        if value is None or value == "":
            return []
        if isinstance(value, str):
            parts = [p.strip() for p in value.replace(";", ",").split(",")]
            return [_sanitize_text(p, 80) for p in parts if p.strip()]
        return [_sanitize_text(str(p), 80) for p in value if str(p).strip()]


class BlueTeamLog(BaseModel):
    timestamp: str = ""
    source: str = ""
    alert_name: str = ""
    technique_id: str | None = None
    message: str = ""
    severity: str = ""
    rule_id: str = ""
    asset_id: str | None = None

    @field_validator(
        "timestamp",
        "source",
        "alert_name",
        "message",
        "severity",
        "rule_id",
        mode="before",
    )
    @classmethod
    def _clean_str(cls, value: Any) -> str:
        return _sanitize_text(str(value or ""), 4000)

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, value: str) -> str:
        if not value:
            return value
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO 8601 timestamp") from exc
        return value

    @field_validator("technique_id", mode="before")
    @classmethod
    def _clean_tid(cls, value: Any) -> str | None:
        if value is None or str(value).strip() == "":
            return None
        return _sanitize_text(str(value), 32)

    @field_validator("asset_id", mode="before")
    @classmethod
    def _clean_asset(cls, value: Any) -> str | None:
        if value is None or str(value).strip() == "":
            return None
        return _sanitize_text(str(value), 128)


class AuditEvent(BaseModel):
    timestamp: str
    action: str
    actor: str = "system"
    details: str = ""


class MatchEvidence(BaseModel):
    log_index: int
    alert_name: str
    source: str
    snippet: str
    score: float
    asset_id: str | None = None
    timestamp: str | None = None
    severity: str | None = None


class ReferenceEvidence(BaseModel):
    source: str
    title: str
    url: str
    snippet: str


class FindingAssessment(BaseModel):
    priority_score: int = Field(ge=0, le=100)
    priority_band: Literal["Low", "Moderate", "High", "Urgent"]
    priority_basis: str
    flaws_and_unknowns: list[str] = Field(default_factory=list)
    red_team_actions: list[str] = Field(default_factory=list)
    blue_team_actions: list[str] = Field(default_factory=list)
    web_research_summary: str
    sources: list[ReferenceEvidence] = Field(default_factory=list)


StageStatus = Literal["ok", "failed", "skipped", "pending"]


class CorrelationResult(BaseModel):
    test_id: str
    test_name: str
    asset_id: str | None = None
    executed_at: str | None = None
    time_window_minutes: int | None = None
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None
    status: Status
    comments: str
    confidence: float = 0.0
    expected_detection: str = ""
    evidence: list[MatchEvidence] = Field(default_factory=list)
    excluded_context_logs: int = 0
    siem_before: dict[str, Any] | None = None
    siem_after: dict[str, Any] | None = None
    siem_error: str | None = None
    # Per-stage pipeline status: "ok" | "failed" | "skipped" | "pending"
    stage_correlation: StageStatus = "pending"
    stage_agent: StageStatus = "pending"
    stage_references: StageStatus = "pending"
    llm_summary: str | None = None
    llm_error: str | None = None
    references: list[ReferenceEvidence] = Field(default_factory=list)
    references_error: str | None = None
    reference_lookup_attempted: bool = False
    assessment: FindingAssessment | None = None
    assessment_error: str | None = None
    remediation_mode: Literal["not_started", "simulated", "operator_reported"] = (
        "not_started"
    )
    verification_status: Literal[
        "not_retested", "verified", "not_verified", "already_detected"
    ] = "not_retested"
    reviewer: str | None = None
    approval_note: str | None = None
    approved_at: str | None = None
    audit_events: list[AuditEvent] = Field(default_factory=list)
