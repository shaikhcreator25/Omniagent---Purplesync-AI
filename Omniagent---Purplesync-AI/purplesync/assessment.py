"""Build transparent team actions and review priority from local findings."""

from __future__ import annotations

from purplesync.models import CorrelationResult, FindingAssessment, ReferenceEvidence


_STATUS_PRIORITY = {
    "Gap – missing evidence": 70,
    "Requiring investigation": 60,
    "Insufficient Data": 55,
    "Detected": 25,
}
_SEVERITY_BONUS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}


def build_assessment(
    result: CorrelationResult,
    references: list[ReferenceEvidence],
    *,
    research_error: str | None = None,
) -> FindingAssessment:
    """Create review actions from correlation facts and TinyFish public sources."""
    base_score = _STATUS_PRIORITY[result.status]
    evidence_severities = [
        evidence.severity.lower() for evidence in result.evidence if evidence.severity
    ]
    severity = max(
        evidence_severities, key=lambda value: _SEVERITY_BONUS.get(value, 0), default=""
    )
    score = min(100, base_score + _SEVERITY_BONUS.get(severity, 0))
    band = (
        "Urgent"
        if score >= 85
        else "High" if score >= 65 else "Moderate" if score >= 40 else "Low"
    )
    basis = f"Heuristic review-priority score: status base {base_score}/100" + (
        f" plus {severity} evidence adjustment " f"{_SEVERITY_BONUS[severity]}."
        if severity in _SEVERITY_BONUS
        else "; no severity adjustment."
    )

    flaws: list[str] = []
    if not result.asset_id:
        flaws.append(
            "Red Team input has no asset ID, so asset-level matching is limited."
        )
    if not result.executed_at:
        flaws.append(
            "Red Team input has no execution time, so time-window correlation cannot be enforced."
        )
    if result.excluded_context_logs:
        flaws.append(
            f"{result.excluded_context_logs} log(s) were excluded for asset/time mismatch."
        )
    if result.status == "Gap – missing evidence":
        flaws.append(
            "Related telemetry exists in scope, but the expected detection was not matched."
        )
    elif result.status == "Requiring investigation":
        flaws.append(
            "Only partial evidence matched; a human must decide whether it represents the test."
        )
    elif result.status == "Insufficient Data":
        flaws.append(
            "No relevant in-scope telemetry was matched; absence of evidence is not proof of no detection."
        )
    elif result.status == "Detected":
        flaws.append(
            "A text/technique match is not a full control-quality or false-positive assessment."
        )

    if result.status == "Gap – missing evidence":
        red_actions = [
            (
                "Confirm this was an authorized simulation and preserve its run ID, "
                "asset, UTC time, and expected alert."
            ),
            (
                "After the Blue Team tunes coverage, repeat the same safe, approved "
                "test and compare the new evidence."
            ),
        ]
        blue_actions = [
            (
                "Review in-scope telemetry and ingestion for the test window; identify "
                "whether the miss is collection, parsing, correlation, or rule coverage."
            ),
            (
                "Compare the candidate detection logic with the cited ATT&CK/Sigma "
                "guidance, then validate changes in a lab before deployment."
            ),
            (
                "Retest with the Red Team and record alert evidence, triage routing, "
                "and any remaining blind spots."
            ),
        ]
    elif result.status == "Requiring investigation":
        red_actions = [
            (
                "Provide the authorized run ID, exact UTC execution time, target asset, "
                "and expected observable to disambiguate the partial match."
            ),
            (
                "Repeat only if the exercise owner confirms scope and the current "
                "evidence is insufficient."
            ),
        ]
        blue_actions = [
            (
                "Have an analyst inspect the partial match in its asset/time context "
                "before classifying it as detected."
            ),
            (
                "Check alert fidelity, event fields, and triage routing; document why "
                "the evidence does or does not satisfy the expected control."
            ),
        ]
    elif result.status == "Insufficient Data":
        red_actions = [
            (
                "Complete the test record with authorized scope, asset ID, execution "
                "time, technique, and expected observable."
            ),
            (
                "Coordinate a safe rerun only after the Blue Team confirms telemetry "
                "collection is ready."
            ),
        ]
        blue_actions = [
            (
                "Check that the relevant log source is connected, parsing events, and "
                "retaining data for the test window."
            ),
            (
                "Do not interpret missing telemetry as a confirmed detection failure "
                "until collection and search coverage are checked."
            ),
        ]
    else:
        red_actions = [
            "Preserve the exact test conditions and repeat within the approved scope to check reproducibility.",
            "Record any test variations separately so a successful match is not generalized beyond the evidence.",
        ]
        blue_actions = [
            (
                "Verify alert fidelity, false-positive rate, routing, and analyst "
                "response rather than relying on a text match alone."
            ),
            "Record the evidence and keep monitoring for coverage gaps across related telemetry.",
        ]

    if references:
        sources_text = "; ".join(
            f"{source.source}: {source.title}" for source in references[:4]
        )
        research_summary = (
            f"TinyFish Search/Fetch returned {len(references)} public source(s): "
            f"{sources_text}. These inform review questions; they do not prove local "
            "telemetry or detection performance."
        )
    elif research_error:
        research_summary = (
            "TinyFish public-source research did not complete successfully. "
            "The local heuristic assessment is available, but recommendations are "
            f"not externally grounded ({research_error})."
        )
    else:
        research_summary = (
            "TinyFish Search/Fetch returned no eligible public pages. The local "
            "heuristic assessment is not externally grounded."
        )

    return FindingAssessment(
        priority_score=score,
        priority_band=band,
        priority_basis=basis,
        flaws_and_unknowns=flaws,
        red_team_actions=red_actions,
        blue_team_actions=blue_actions,
        web_research_summary=research_summary,
        sources=references,
    )
