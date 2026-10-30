"""Rule-based Red Team / Blue Team correlator with MITRE context."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable

from purplesync.logging_setup import configure_logging
from purplesync.mitre import lookup_technique
from purplesync.models import BlueTeamLog, CorrelationResult, MatchEvidence, RedTeamTest

logger = configure_logging()

_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{2,}", re.I)
_STOPWORDS = {
    "the",
    "and",
    "for",
    "from",
    "with",
    "this",
    "that",
    "rule",
    "alert",
    "detected",
    "detection",
    "event",
    "log",
    "logs",
    "test",
    "http",
    "https",
}


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _tokens(*parts: str) -> set[str]:
    found: set[str] = set()
    for part in parts:
        found.update(m.group(0).lower() for m in _TOKEN.finditer(part or ""))
    return {token for token in found if token not in _STOPWORDS}


def _same_technique(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    a, b = left.upper(), right.upper()
    return a == b or a.startswith(b + ".") or b.startswith(a + ".")


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _context_matches(test: RedTeamTest, log: BlueTeamLog) -> bool:
    if test.asset_id and (
        not log.asset_id or test.asset_id.casefold() != log.asset_id.casefold()
    ):
        return False
    if test.executed_at:
        test_time = _parse_timestamp(test.executed_at)
        log_time = _parse_timestamp(log.timestamp)
        if test_time is None or log_time is None:
            return False
        allowed_seconds = test.time_window_minutes * 60
        if abs((log_time - test_time).total_seconds()) > allowed_seconds:
            return False
    return True


def _score_log(test: RedTeamTest, log: BlueTeamLog) -> float:
    score = 0.0
    expected = _normalize(test.expected_detection)
    alert = _normalize(f"{log.alert_name} {log.rule_id}")
    message = _normalize(log.message)
    blob = f"{alert} {message}"
    expected_in_blob = bool(expected) and expected in blob

    if expected_in_blob:
        score += 0.55
    expected_tokens = _tokens(test.expected_detection)
    blob_tokens = _tokens(log.alert_name, log.rule_id, log.message, log.source)
    if expected_tokens:
        overlap = len(expected_tokens & blob_tokens) / len(expected_tokens)
        score += 0.25 * overlap

    extra = {_normalize(k) for k in test.keywords if k}
    if extra:
        hits = sum(1 for k in extra if k in blob)
        score += 0.15 * (hits / len(extra))

    if _same_technique(test.technique_id, log.technique_id):
        score += 0.2

    # Do not promote a finding to "Detected" unless the expected alert text is present.
    if not expected_in_blob:
        score = min(score, 0.27)
    return min(score, 1.0)


def _classify(best: float, related: bool) -> tuple[str, str, float]:
    if best >= 0.55:
        return (
            "Detected",
            "Expected detection matched Blue Team evidence (alert name, rule, or technique).",
            min(0.95, 0.6 + best / 2),
        )
    if best >= 0.28:
        return (
            "Requiring investigation",
            "Partial overlap between the test and logs. Analyst review recommended.",
            0.45 + best / 4,
        )
    if related:
        return (
            "Gap – missing evidence",
            "Related telemetry exists, but the expected detection/alert was not found.",
            0.4,
        )
    return (
        "Insufficient Data",
        "No relevant Blue Team logs were found for this test.",
        0.2,
    )


def _is_related(test: RedTeamTest, log: BlueTeamLog) -> bool:
    if not _context_matches(test, log):
        return False
    tech = lookup_technique(test.name, test.technique_id)
    if tech and _same_technique(tech.technique_id, log.technique_id):
        return True
    name_tokens = _tokens(test.name, test.expected_detection, *test.keywords)
    log_tokens = _tokens(log.alert_name, log.message, log.source, log.rule_id)
    return len(name_tokens & log_tokens) >= 2


def correlate(
    tests: Iterable[RedTeamTest],
    logs: Iterable[BlueTeamLog],
) -> list[CorrelationResult]:
    tests = list(tests)
    logs = list(logs)
    logger.info(
        "Correlating %s Red Team tests against %s Blue Team logs", len(tests), len(logs)
    )
    results: list[CorrelationResult] = []

    for test in tests:
        technique = lookup_technique(test.name, test.technique_id)
        scored: list[MatchEvidence] = []
        related = False
        excluded_context_logs = 0
        for idx, log in enumerate(logs):
            if not _context_matches(test, log):
                excluded_context_logs += 1
                continue
            related = related or _is_related(test, log)
            value = _score_log(test, log)
            if value >= 0.2:
                snippet = (log.message or log.alert_name)[:240]
                scored.append(
                    MatchEvidence(
                        log_index=idx,
                        alert_name=log.alert_name or log.rule_id,
                        source=log.source,
                        snippet=snippet,
                        score=round(value, 3),
                        asset_id=log.asset_id,
                        timestamp=log.timestamp or None,
                        severity=log.severity or None,
                    )
                )
        scored.sort(key=lambda item: item.score, reverse=True)
        best = scored[0].score if scored else 0.0
        status, comments, confidence = _classify(best, related)
        results.append(
            CorrelationResult(
                test_id=test.test_id,
                test_name=test.name,
                asset_id=test.asset_id,
                executed_at=test.executed_at,
                time_window_minutes=test.time_window_minutes,
                technique_id=technique.technique_id if technique else test.technique_id,
                technique_name=technique.name if technique else None,
                tactic=technique.tactic if technique else None,
                status=status,  # type: ignore[arg-type]
                comments=comments,
                confidence=round(confidence, 2),
                expected_detection=test.expected_detection,
                evidence=scored[:5],
                excluded_context_logs=excluded_context_logs,
            )
        )
        logger.info(
            "Correlated test %s -> status=%s confidence=%s",
            test.test_id,
            status,
            round(confidence, 2),
        )
    return results
