from pathlib import Path

from purplesync.assessment import build_assessment
from purplesync.correlator import correlate
from purplesync.models import ReferenceEvidence
from purplesync.parsers import parse_blue_team, parse_red_team

ROOT = Path(__file__).resolve().parents[1]


def _sample_result(test_id: str):
    tests = parse_red_team((ROOT / "sample_data" / "red_team_tests.json").read_bytes())
    logs = parse_blue_team((ROOT / "sample_data" / "blue_team_logs.json").read_bytes())
    test = next(test for test in tests if test.test_id == test_id)
    return correlate([test], logs)[0]


def test_gap_assessment_gives_both_teams_specific_next_steps():
    result = _sample_result("RT-001")
    reference = ReferenceEvidence(
        source="MITRE ATT&CK",
        title="Web Protocols",
        url="https://attack.mitre.org/techniques/T1071/001/",
        snippet="Public detection guidance.",
    )

    assessment = build_assessment(result, [reference])

    assert assessment.priority_band == "High"
    assert assessment.priority_score == 78
    assert assessment.red_team_actions
    assert assessment.blue_team_actions
    assert "ingestion" in " ".join(assessment.blue_team_actions).lower()
    assert assessment.sources == [reference]
    assert "do not prove local telemetry" in assessment.web_research_summary


def test_insufficient_data_is_not_claimed_as_a_detection_failure():
    assessment = build_assessment(_sample_result("RT-005"), [])

    assert any("not proof" in flaw for flaw in assessment.flaws_and_unknowns)
    assert any(
        "collection" in action.lower() for action in assessment.blue_team_actions
    )
    assert "not externally grounded" in assessment.web_research_summary
